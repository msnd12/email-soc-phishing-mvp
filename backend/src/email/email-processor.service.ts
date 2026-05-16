import { Injectable } from "@nestjs/common";
import { NormalizedEmail, Verdict } from "../common/types";
import { DbService } from "../db/db.service";
import { AlertsService } from "../alerts/alerts.service";
import { RiskScoringService } from "../threat/risk-scoring.service";
import { ThreatIntelService } from "../threat/threat-intel.service";
import { UrlExtractorService } from "../threat/url-extractor.service";

@Injectable()
export class EmailProcessorService {
  constructor(
    private readonly db: DbService,
    private readonly urls: UrlExtractorService,
    private readonly threatIntel: ThreatIntelService,
    private readonly scoring: RiskScoringService,
    private readonly alerts: AlertsService
  ) {}

  async ingest(email: NormalizedEmail): Promise<{ emailMessageId: string; alertId?: string; riskScore: number; verdict: string }> {
    const extractedUrls = this.urls.extract(email.bodyText, email.htmlBody);
    const bodyText = process.env.FULL_MESSAGE_STORAGE_ENABLED === "true" ? email.bodyText : null;
    const sanitizedHtml = process.env.FULL_MESSAGE_STORAGE_ENABLED === "true" ? email.sanitizedHtml : null;

    const emailMessageId = await this.db.tx(async (query) => {
      const messageResult = await query<{ id: string }>(
        `INSERT INTO email_messages
          (provider, provider_message_id, mailbox, sender, sender_domain, recipient, reply_to, return_path, subject,
           received_at, body_preview, body_text, sanitized_html, authentication_results, source_ips)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15)
         ON CONFLICT (provider, provider_message_id, mailbox)
         DO UPDATE SET
          sender = EXCLUDED.sender,
          sender_domain = EXCLUDED.sender_domain,
          recipient = EXCLUDED.recipient,
          reply_to = EXCLUDED.reply_to,
          return_path = EXCLUDED.return_path,
          subject = EXCLUDED.subject,
          received_at = EXCLUDED.received_at,
          body_preview = EXCLUDED.body_preview,
          body_text = EXCLUDED.body_text,
          sanitized_html = EXCLUDED.sanitized_html,
          authentication_results = EXCLUDED.authentication_results,
          source_ips = EXCLUDED.source_ips,
          updated_at = NOW()
         RETURNING id`,
        [
          email.provider,
          email.providerMessageId,
          email.mailbox,
          email.sender,
          email.senderDomain ?? null,
          email.recipient,
          email.replyTo ?? null,
          email.returnPath ?? null,
          email.subject ?? null,
          email.receivedAt ?? null,
          email.bodyPreview ?? null,
          bodyText,
          sanitizedHtml,
          JSON.stringify(email.authenticationResults),
          email.sourceIps
        ]
      );
      const id = messageResult.rows[0].id;
      await query("DELETE FROM email_headers WHERE email_message_id = $1", [id]);
      await query("DELETE FROM email_attachments WHERE email_message_id = $1", [id]);
      await query("DELETE FROM email_urls WHERE email_message_id = $1", [id]);

      for (const header of email.headers) {
        await query("INSERT INTO email_headers (email_message_id, name, value) VALUES ($1, $2, $3)", [
          id,
          header.name,
          header.value
        ]);
      }
      for (const attachment of email.attachments) {
        await query(
          `INSERT INTO email_attachments (email_message_id, filename, content_type, size_bytes, sha256)
           VALUES ($1, $2, $3, $4, $5)`,
          [id, attachment.filename, attachment.contentType ?? null, attachment.sizeBytes ?? null, attachment.sha256 ?? null]
        );
      }
      for (const url of extractedUrls) {
        await query(
          `INSERT INTO email_urls
            (email_message_id, original_url, normalized_url, display_text, domain, is_shortened, is_punycode,
             is_ip_url, is_suspicious_tld, is_lookalike, has_mismatched_anchor, redirect_chain)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb)`,
          [
            id,
            url.originalUrl,
            url.normalizedUrl,
            url.displayText ?? null,
            url.domain ?? null,
            url.isShortened,
            url.isPunycode,
            url.isIpUrl,
            url.isSuspiciousTld,
            url.isLookalike,
            url.hasMismatchedAnchor,
            JSON.stringify(url.redirectChain)
          ]
        );
      }
      return id;
    });

    const urlRows = await this.db.query<any>("SELECT * FROM email_urls WHERE email_message_id = $1", [emailMessageId]);
    const scannedUrls = [];
    for (const url of urlRows.rows) {
      const scans = await this.threatIntel.scanEmailUrl(url.id, url.normalized_url);
      const urlScore = this.scoreUrl(url, scans);
      const hasMaliciousScan = scans.some((scan) => scan.maliciousCount > 0 || scan.verdict === "malicious");
      const hasSuspiciousScan = scans.some((scan) => scan.suspiciousCount > 0 || scan.verdict === "suspicious");
      const urlVerdict: Verdict = hasMaliciousScan ? "malicious" : hasSuspiciousScan || urlScore >= 50 ? "suspicious" : "safe";
      await this.db.query("UPDATE email_urls SET risk_score = $2, verdict = $3 WHERE id = $1", [url.id, urlScore, urlVerdict]);
      scannedUrls.push({
        id: url.id,
        normalizedUrl: url.normalized_url,
        domain: url.domain,
        isShortened: url.is_shortened,
        isPunycode: url.is_punycode,
        isIpUrl: url.is_ip_url,
        isSuspiciousTld: url.is_suspicious_tld,
        isLookalike: url.is_lookalike,
        hasMismatchedAnchor: url.has_mismatched_anchor,
        verdict: urlVerdict,
        maliciousCount: scans.reduce((sum, scan) => sum + scan.maliciousCount, 0),
        suspiciousCount: scans.reduce((sum, scan) => sum + scan.suspiciousCount, 0)
      });
    }

    const score = this.scoring.score({
      sender: email.sender,
      senderDomain: email.senderDomain,
      replyTo: email.replyTo,
      returnPath: email.returnPath,
      subject: email.subject,
      bodyPreview: email.bodyPreview,
      authenticationResults: email.authenticationResults,
      urls: scannedUrls,
      attachments: email.attachments
    });

    await this.db.query("UPDATE email_messages SET risk_score = $2, verdict = $3, updated_at = NOW() WHERE id = $1", [
      emailMessageId,
      score.riskScore,
      score.verdict
    ]);

    let alertId: string | undefined;
    if (score.riskScore >= 30) {
      alertId = await this.alerts.upsertForEmail(emailMessageId, score);
    } else {
      await this.alerts.deleteForEmail(emailMessageId);
    }

    return { emailMessageId, alertId, riskScore: score.riskScore, verdict: score.verdict };
  }

  async rescan(emailMessageId: string): Promise<{ emailMessageId: string; alertId?: string; riskScore: number; verdict: string }> {
    const message = await this.db.query<any>("SELECT * FROM email_messages WHERE id = $1", [emailMessageId]);
    if (!message.rows[0]) {
      throw new Error("Email message not found");
    }
    const headers = await this.db.query<any>("SELECT name, value FROM email_headers WHERE email_message_id = $1", [emailMessageId]);
    const attachments = await this.db.query<any>("SELECT filename, content_type, size_bytes, sha256 FROM email_attachments WHERE email_message_id = $1", [
      emailMessageId
    ]);
    const row = message.rows[0];
    return this.ingest({
      provider: row.provider,
      providerMessageId: row.provider_message_id,
      mailbox: row.mailbox,
      sender: row.sender,
      senderDomain: row.sender_domain,
      recipient: row.recipient,
      replyTo: row.reply_to,
      returnPath: row.return_path,
      subject: row.subject,
      receivedAt: row.received_at,
      bodyPreview: row.body_preview,
      bodyText: row.body_text ?? row.body_preview ?? "",
      htmlBody: row.sanitized_html ?? "",
      sanitizedHtml: row.sanitized_html ?? "",
      authenticationResults: row.authentication_results,
      sourceIps: row.source_ips ?? [],
      headers: headers.rows,
      attachments: attachments.rows.map((attachment) => ({
        filename: attachment.filename,
        contentType: attachment.content_type,
        sizeBytes: attachment.size_bytes,
        sha256: attachment.sha256
      }))
    });
  }

  private scoreUrl(url: any, scans: Array<{ maliciousCount: number; suspiciousCount: number; verdict: string }>): number {
    let score = 0;
    if (url.is_shortened) score += 8;
    if (url.is_punycode) score += 14;
    if (url.is_ip_url) score += 14;
    if (url.is_suspicious_tld) score += 8;
    if (url.is_lookalike) score += 12;
    if (url.has_mismatched_anchor) score += 15;
    if (scans.some((scan) => scan.maliciousCount > 0 || scan.verdict === "malicious")) score += 70;
    if (scans.some((scan) => scan.suspiciousCount > 0 || scan.verdict === "suspicious")) score += 35;
    return Math.min(100, score);
  }
}
