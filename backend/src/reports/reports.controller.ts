import { Controller, Get, Param, Post, Req, UseGuards } from "@nestjs/common";
import { AuthGuard } from "../auth/auth.guard";
import { AuditService } from "../audit/audit.service";
import { DbService } from "../db/db.service";

@Controller("/api/reports")
@UseGuards(AuthGuard)
export class ReportsController {
  constructor(
    private readonly db: DbService,
    private readonly audit: AuditService
  ) {}

  @Post("/email-alert/:id")
  async create(@Param("id") id: string, @Req() req: any) {
    const detail = await this.db.query(
      `SELECT a.*, m.authentication_results, m.body_preview
       FROM email_alerts a
       JOIN email_messages m ON m.id = a.email_message_id
       WHERE a.id = $1`,
      [id]
    );
    const urls = await this.db.query("SELECT * FROM email_urls WHERE email_message_id = $1", [detail.rows[0]?.email_message_id]);
    const report = { alert: detail.rows[0], urls: urls.rows, generatedAt: new Date().toISOString() };
    const saved = await this.db.query<{ id: string }>(
      "INSERT INTO reports (alert_id, report_json, created_by) VALUES ($1, $2::jsonb, $3) RETURNING id",
      [id, JSON.stringify(report), req.user.id]
    );
    await this.audit.log({
      actorUserId: req.user.id,
      action: "report.created",
      targetType: "email_alert",
      targetId: id,
      details: { reportId: saved.rows[0].id },
      ipAddress: req.ip,
      userAgent: req.headers["user-agent"]
    });
    return { reportId: saved.rows[0].id };
  }

  @Get("/:id/download")
  async download(@Param("id") id: string) {
    const result = await this.db.query("SELECT report_json FROM reports WHERE id = $1", [id]);
    return result.rows[0]?.report_json ?? { error: "Report not found" };
  }
}
