import { Body, Controller, Get, Inject, Param, Post, Query, Redirect, Req, UseGuards } from "@nestjs/common";
import { IsInt, IsOptional, IsString, Max, Min } from "class-validator";
import { AuthGuard } from "../auth/auth.guard";
import { AuditService } from "../audit/audit.service";
import { DbService } from "../db/db.service";
import { AlertsService } from "../alerts/alerts.service";
import { AppConfig, CONFIG } from "../config";
import { EmailProcessorService } from "./email-processor.service";
import { GmailConnectorService } from "./gmail-connector.service";

class PollDto {
  @IsOptional()
  @IsString()
  mailbox?: string;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(25)
  maxResults?: number;
}

@Controller("/api/email")
export class EmailController {
  constructor(
    private readonly gmail: GmailConnectorService,
    private readonly processor: EmailProcessorService,
    private readonly db: DbService,
    private readonly alerts: AlertsService,
    private readonly audit: AuditService,
    @Inject(CONFIG) private readonly config: AppConfig
  ) {}

  @Get("/oauth/gmail/start")
  @UseGuards(AuthGuard)
  gmailStart(@Req() req: any) {
    return { url: this.gmail.getAuthUrl(req.user.id) };
  }

  @Get("/oauth/gmail/callback")
  @Redirect()
  async gmailCallback(@Query("code") code: string, @Query("state") state: string) {
    const result = await this.gmail.handleCallback(code, state);
    return { url: `${this.config.appUrl}/gmail-connected.html?mailbox=${encodeURIComponent(result.mailbox)}&watch=${String(result.watchStarted)}` };
  }

  @Get("/connections")
  @UseGuards(AuthGuard)
  connections() {
    return this.gmail.status();
  }

  @Post("/poll/gmail")
  @UseGuards(AuthGuard)
  async pollGmail(@Body() body: PollDto, @Req() req: any) {
    const emails = await this.gmail.pollLatest(body.mailbox, body.maxResults ?? 10);
    const results = [];
    for (const email of emails) {
      results.push(await this.processor.ingest(email));
    }
    await this.audit.log({
      actorUserId: req.user.id,
      action: "email.gmail_polled",
      targetType: "provider",
      targetId: body.mailbox ?? "latest",
      details: { count: results.length },
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"]
    });
    return { ingested: results.length, results };
  }

  @Post("/webhook/gmail")
  async gmailWebhook(@Body() body: any) {
    const emails = await this.gmail.fromPubSub(body);
    const results = [];
    for (const email of emails) {
      results.push(await this.processor.ingest(email));
    }
    return { ok: true, ingested: results.length, results };
  }

  @Post("/webhook/microsoft")
  microsoftWebhook(@Body() body: any, @Req() req: any) {
    const expected = process.env.MICROSOFT_WEBHOOK_SECRET;
    const received = req.headers["x-ms-client-state"] ?? body?.value?.[0]?.clientState;
    if (expected && received !== expected) {
      return { ok: false, status: "invalid_client_state" };
    }
    return {
      ok: false,
      status: "integration_not_configured",
      message: "Microsoft 365 Graph change notification support is reserved for the next connector. This MVP is wired to Gmail first."
    };
  }

  @Get("/messages")
  @UseGuards(AuthGuard)
  async messages() {
    const result = await this.db.query(
      `SELECT m.*,
        COALESCE(urls.url_count, 0)::int AS url_count,
        alerts.id AS alert_id,
        alerts.severity AS alert_severity,
        alerts.status AS alert_status
       FROM email_messages m
       LEFT JOIN (
        SELECT email_message_id, COUNT(*) AS url_count FROM email_urls GROUP BY email_message_id
       ) urls ON urls.email_message_id = m.id
       LEFT JOIN email_alerts alerts ON alerts.email_message_id = m.id
       ORDER BY m.received_at DESC NULLS LAST, m.created_at DESC
       LIMIT 200`
    );
    return result.rows;
  }

  @Get("/messages/:id")
  @UseGuards(AuthGuard)
  async message(@Param("id") id: string) {
    const message = await this.db.query("SELECT * FROM email_messages WHERE id = $1", [id]);
    const urls = await this.db.query(
      `SELECT u.*,
        COALESCE(json_agg(s.* ORDER BY s.scanned_at DESC) FILTER (WHERE s.id IS NOT NULL), '[]') AS scan_results
       FROM email_urls u
       LEFT JOIN url_scan_results s ON s.email_url_id = u.id
       WHERE u.email_message_id = $1
       GROUP BY u.id
       ORDER BY u.risk_score DESC`,
      [id]
    );
    const headers = await this.db.query("SELECT name, value FROM email_headers WHERE email_message_id = $1", [id]);
    const attachments = await this.db.query("SELECT * FROM email_attachments WHERE email_message_id = $1", [id]);
    return { message: message.rows[0], urls: urls.rows, headers: headers.rows, attachments: attachments.rows };
  }

  @Post("/rescan/:id")
  @UseGuards(AuthGuard)
  async rescan(@Param("id") id: string, @Req() req: any) {
    const message = await this.db.query<any>("SELECT provider, provider_message_id, mailbox FROM email_messages WHERE id = $1", [id]);
    const row = message.rows[0];
    const result =
      row?.provider === "gmail"
        ? await this.processor.ingest(await this.gmail.fetchMessage(row.mailbox, row.provider_message_id))
        : await this.processor.rescan(id);
    await this.audit.log({
      actorUserId: req.user.id,
      action: "email.rescanned",
      targetType: "email_message",
      targetId: id,
      details: result,
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"]
    });
    return result;
  }

  @Get("/overview")
  @UseGuards(AuthGuard)
  overview() {
    return this.alerts.overview();
  }
}
