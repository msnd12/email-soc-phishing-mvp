import { Inject, Injectable, NotFoundException, ServiceUnavailableException } from "@nestjs/common";
import { google, gmail_v1 } from "googleapis";
import jwt from "jsonwebtoken";
import sanitizeHtml from "sanitize-html";
import { AppConfig, CONFIG } from "../config";
import { CryptoService } from "../common/crypto.service";
import { AuthResults, NormalizedEmail } from "../common/types";
import { DbService } from "../db/db.service";

const GMAIL_SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/userinfo.email"
];

@Injectable()
export class GmailConnectorService {
  constructor(
    private readonly db: DbService,
    private readonly crypto: CryptoService,
    @Inject(CONFIG) private readonly config: AppConfig
  ) {}

  getAuthUrl(userId: string): string {
    const oauth = this.oauthClient();
    const state = jwt.sign({ sub: userId, provider: "gmail" }, this.config.jwtSecret, { expiresIn: "10m" });
    return oauth.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: GMAIL_SCOPES,
      state
    });
  }

  async handleCallback(code: string, state: string): Promise<{ mailbox: string; watchStarted: boolean }> {
    const payload = jwt.verify(state, this.config.jwtSecret) as { sub: string; provider: string };
    if (payload.provider !== "gmail") {
      throw new ServiceUnavailableException("Invalid OAuth provider state");
    }

    const oauth = this.oauthClient();
    const tokenResponse = await oauth.getToken(code);
    oauth.setCredentials(tokenResponse.tokens);
    const gmail = google.gmail({ version: "v1", auth: oauth });
    const profile = await gmail.users.getProfile({ userId: "me" });
    const mailbox = profile.data.emailAddress;
    if (!mailbox) {
      throw new ServiceUnavailableException("Gmail profile did not return an email address");
    }

    const accessToken = this.crypto.encrypt(tokenResponse.tokens.access_token ?? "");
    const refreshToken = this.crypto.encrypt(tokenResponse.tokens.refresh_token ?? undefined);
    const expiry = tokenResponse.tokens.expiry_date ? new Date(tokenResponse.tokens.expiry_date).toISOString() : null;
    await this.db.query(
      `INSERT INTO provider_tokens
        (provider, mailbox, user_id, access_token_encrypted, refresh_token_encrypted, scope, expiry_date, last_history_id)
       VALUES ('gmail', $1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (provider, mailbox)
       DO UPDATE SET
        user_id = EXCLUDED.user_id,
        access_token_encrypted = EXCLUDED.access_token_encrypted,
        refresh_token_encrypted = COALESCE(EXCLUDED.refresh_token_encrypted, provider_tokens.refresh_token_encrypted),
        scope = EXCLUDED.scope,
        expiry_date = EXCLUDED.expiry_date,
        last_history_id = EXCLUDED.last_history_id,
        updated_at = NOW()`,
      [
        mailbox,
        payload.sub,
        accessToken,
        refreshToken,
        tokenResponse.tokens.scope ?? GMAIL_SCOPES.join(" "),
        expiry,
        profile.data.historyId ?? null
      ]
    );

    const watchStarted = await this.startWatch(mailbox).catch(() => false);
    return { mailbox, watchStarted };
  }

  async status() {
    const result = await this.db.query(
      `SELECT provider, mailbox, last_history_id, watch_expires_at, updated_at
       FROM provider_tokens
       WHERE provider = 'gmail'
       ORDER BY updated_at DESC`
    );
    return result.rows;
  }

  async startWatch(mailbox: string): Promise<boolean> {
    if (!this.config.google.projectId || !this.config.google.pubsubTopic) {
      return false;
    }
    const gmail = await this.clientForMailbox(mailbox);
    const topicName = `projects/${this.config.google.projectId}/topics/${this.config.google.pubsubTopic}`;
    const response = await gmail.users.watch({
      userId: "me",
      requestBody: {
        topicName,
        labelIds: ["INBOX"]
      }
    });
    await this.db.query(
      `UPDATE provider_tokens
       SET last_history_id = COALESCE($2, last_history_id), watch_expires_at = $3, updated_at = NOW()
       WHERE provider = 'gmail' AND mailbox = $1`,
      [
        mailbox,
        response.data.historyId ?? null,
        response.data.expiration ? new Date(Number(response.data.expiration)).toISOString() : null
      ]
    );
    return true;
  }

  async pollLatest(mailbox?: string, maxResults = 10): Promise<NormalizedEmail[]> {
    const token = await this.resolveToken(mailbox);
    const gmail = await this.clientForMailbox(token.mailbox);
    const messages = await gmail.users.messages.list({
      userId: "me",
      labelIds: ["INBOX"],
      q: "newer_than:1d",
      maxResults
    });
    const ids = messages.data.messages?.map((message) => message.id).filter(Boolean) as string[] | undefined;
    if (!ids?.length) return [];
    const normalized: NormalizedEmail[] = [];
    for (const id of ids) {
      normalized.push(await this.fetchMessage(token.mailbox, id));
    }
    return normalized;
  }

  async fromPubSub(body: any): Promise<NormalizedEmail[]> {
    const data = body?.message?.data;
    if (!data) {
      throw new ServiceUnavailableException("Missing Pub/Sub message data");
    }
    const payload = JSON.parse(Buffer.from(data, "base64").toString("utf8")) as { emailAddress: string; historyId: string };
    const token = await this.resolveToken(payload.emailAddress);
    const gmail = await this.clientForMailbox(token.mailbox);
    const since = token.last_history_id ?? payload.historyId;
    const history = await gmail.users.history.list({
      userId: "me",
      startHistoryId: since,
      historyTypes: ["messageAdded"]
    });
    const ids = new Set<string>();
    for (const item of history.data.history ?? []) {
      for (const added of item.messagesAdded ?? []) {
        if (added.message?.id) ids.add(added.message.id);
      }
    }
    await this.db.query(
      "UPDATE provider_tokens SET last_history_id = $2, updated_at = NOW() WHERE provider = 'gmail' AND mailbox = $1",
      [token.mailbox, history.data.historyId ?? payload.historyId]
    );
    const normalized: NormalizedEmail[] = [];
    for (const id of ids) {
      normalized.push(await this.fetchMessage(token.mailbox, id));
    }
    return normalized;
  }

  async fetchMessage(mailbox: string, messageId: string): Promise<NormalizedEmail> {
    const gmail = await this.clientForMailbox(mailbox);
    const response = await gmail.users.messages.get({ userId: "me", id: messageId, format: "full" });
    return this.normalizeMessage(mailbox, response.data);
  }

  private normalizeMessage(mailbox: string, message: gmail_v1.Schema$Message): NormalizedEmail {
    const headers = (message.payload?.headers ?? []).map((header) => ({
      name: header.name ?? "",
      value: header.value ?? ""
    }));
    const getHeader = (name: string) => headers.find((header) => header.name.toLowerCase() === name.toLowerCase())?.value;
    const from = getHeader("From") ?? "unknown";
    const to = getHeader("To") ?? mailbox;
    const subject = getHeader("Subject") ?? "";
    const receivedAt = getHeader("Date") ? new Date(getHeader("Date") as string).toISOString() : undefined;
    const bodyParts = this.extractBodies(message.payload);
    const auth = this.parseAuthResults(headers.filter((header) => header.name.toLowerCase() === "authentication-results").map((header) => header.value));
    const attachments = this.extractAttachments(message.payload);

    return {
      provider: "gmail",
      providerMessageId: message.id ?? "",
      mailbox,
      sender: this.extractEmail(from) ?? from,
      senderDomain: this.extractDomain(from),
      recipient: this.extractEmail(to) ?? to,
      replyTo: this.extractEmail(getHeader("Reply-To") ?? ""),
      returnPath: this.extractEmail(getHeader("Return-Path") ?? ""),
      subject,
      receivedAt,
      bodyPreview: message.snippet ?? bodyParts.text.slice(0, 500),
      bodyText: bodyParts.text,
      htmlBody: bodyParts.html,
      sanitizedHtml: sanitizeHtml(bodyParts.html, {
        allowedTags: sanitizeHtml.defaults.allowedTags.concat(["img"]),
        allowedAttributes: {
          a: ["href", "name", "target"],
          img: ["src", "alt"]
        },
        allowedSchemes: ["http", "https", "mailto"]
      }),
      authenticationResults: auth,
      sourceIps: this.extractSourceIps(headers),
      headers,
      attachments
    };
  }

  private async clientForMailbox(mailbox: string) {
    const token = await this.resolveToken(mailbox);
    const oauth = this.oauthClient();
    oauth.setCredentials({
      access_token: this.crypto.decrypt(token.access_token_encrypted) ?? undefined,
      refresh_token: this.crypto.decrypt(token.refresh_token_encrypted) ?? undefined,
      expiry_date: token.expiry_date ? new Date(token.expiry_date).getTime() : undefined
    });
    oauth.on("tokens", async (tokens) => {
      await this.db.query(
        `UPDATE provider_tokens
         SET access_token_encrypted = COALESCE($2, access_token_encrypted),
             refresh_token_encrypted = COALESCE($3, refresh_token_encrypted),
             expiry_date = COALESCE($4, expiry_date),
             updated_at = NOW()
         WHERE provider = 'gmail' AND mailbox = $1`,
        [
          token.mailbox,
          this.crypto.encrypt(tokens.access_token ?? undefined),
          this.crypto.encrypt(tokens.refresh_token ?? undefined),
          tokens.expiry_date ? new Date(tokens.expiry_date).toISOString() : null
        ]
      );
    });
    return google.gmail({ version: "v1", auth: oauth });
  }

  private async resolveToken(mailbox?: string): Promise<any> {
    const result = await this.db.query(
      `SELECT * FROM provider_tokens
       WHERE provider = 'gmail' AND ($1::text IS NULL OR mailbox = $1)
       ORDER BY updated_at DESC
       LIMIT 1`,
      [mailbox ?? null]
    );
    const row = result.rows[0];
    if (!row) {
      throw new NotFoundException("No Gmail mailbox is connected");
    }
    return row;
  }

  private oauthClient() {
    if (!this.config.google.clientId || !this.config.google.clientSecret || !this.config.google.redirectUri) {
      throw new ServiceUnavailableException("Gmail OAuth is not configured");
    }
    return new google.auth.OAuth2(this.config.google.clientId, this.config.google.clientSecret, this.config.google.redirectUri);
  }

  private extractBodies(part?: gmail_v1.Schema$MessagePart): { text: string; html: string } {
    if (!part) return { text: "", html: "" };
    const current = this.decodeBody(part.body?.data);
    let text = part.mimeType === "text/plain" ? current : "";
    let html = part.mimeType === "text/html" ? current : "";
    for (const child of part.parts ?? []) {
      const childBodies = this.extractBodies(child);
      text += childBodies.text ? `\n${childBodies.text}` : "";
      html += childBodies.html ? `\n${childBodies.html}` : "";
    }
    return { text: text.trim(), html: html.trim() };
  }

  private extractAttachments(part?: gmail_v1.Schema$MessagePart): NormalizedEmail["attachments"] {
    if (!part) return [];
    const attachments: NormalizedEmail["attachments"] = [];
    if (part.filename && part.body?.attachmentId) {
      attachments.push({
        filename: part.filename,
        contentType: part.mimeType ?? undefined,
        sizeBytes: part.body.size ?? undefined
      });
    }
    for (const child of part.parts ?? []) {
      attachments.push(...this.extractAttachments(child));
    }
    return attachments;
  }

  private decodeBody(data?: string | null): string {
    if (!data) return "";
    return Buffer.from(data.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  }

  private parseAuthResults(values: string[]): AuthResults {
    const joined = values.join("\n").toLowerCase();
    const pick = (name: string) => joined.match(new RegExp(`${name}=([a-zA-Z0-9_-]+)`))?.[1];
    return {
      spf: pick("spf"),
      dkim: pick("dkim"),
      dmarc: pick("dmarc"),
      raw: values
    };
  }

  private extractSourceIps(headers: Array<{ name: string; value: string }>): string[] {
    const ips = new Set<string>();
    for (const header of headers.filter((item) => item.name.toLowerCase() === "received")) {
      for (const match of header.value.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
        ips.add(match[0]);
      }
    }
    return [...ips];
  }

  private extractEmail(value: string): string | undefined {
    return value.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0]?.toLowerCase();
  }

  private extractDomain(value: string): string | undefined {
    return this.extractEmail(value)?.split("@").pop();
  }
}
