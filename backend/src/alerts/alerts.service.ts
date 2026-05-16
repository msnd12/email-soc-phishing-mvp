import { Injectable, NotFoundException } from "@nestjs/common";
import { DbService } from "../db/db.service";
import { AuditService } from "../audit/audit.service";
import { ScoreOutput } from "../threat/risk-scoring.service";

@Injectable()
export class AlertsService {
  constructor(
    private readonly db: DbService,
    private readonly audit: AuditService
  ) {}

  async upsertForEmail(emailMessageId: string, score: ScoreOutput): Promise<string> {
    const message = await this.db.query<any>("SELECT * FROM email_messages WHERE id = $1", [emailMessageId]);
    const row = message.rows[0];
    if (!row) throw new NotFoundException("Email message not found");

    const result = await this.db.query<{ id: string }>(
      `INSERT INTO email_alerts
        (email_message_id, subject, sender, recipient, severity, risk_score, verdict, detection_reason, reasons, recommended_action)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
       ON CONFLICT (email_message_id)
       DO UPDATE SET
        subject = EXCLUDED.subject,
        sender = EXCLUDED.sender,
        recipient = EXCLUDED.recipient,
        severity = EXCLUDED.severity,
        risk_score = EXCLUDED.risk_score,
        verdict = EXCLUDED.verdict,
        detection_reason = EXCLUDED.detection_reason,
        reasons = EXCLUDED.reasons,
        recommended_action = EXCLUDED.recommended_action,
        updated_at = NOW()
       RETURNING id`,
      [
        emailMessageId,
        row.subject,
        row.sender,
        row.recipient,
        score.severity,
        score.riskScore,
        score.verdict,
        score.reasons[0],
        JSON.stringify(score.reasons),
        score.recommendedAction
      ]
    );
    return result.rows[0].id;
  }

  async deleteForEmail(emailMessageId: string): Promise<void> {
    await this.db.query("DELETE FROM email_alerts WHERE email_message_id = $1", [emailMessageId]);
  }

  async list() {
    const result = await this.db.query(
      `SELECT a.*, m.received_at,
        COALESCE(urls.url_count, 0)::int AS url_count,
        analyst.email AS assigned_analyst_email
       FROM email_alerts a
       JOIN email_messages m ON m.id = a.email_message_id
       LEFT JOIN users analyst ON analyst.id = a.assigned_analyst
       LEFT JOIN (
         SELECT email_message_id, COUNT(*) AS url_count
         FROM email_urls
         GROUP BY email_message_id
       ) urls ON urls.email_message_id = m.id
       WHERE a.status NOT IN ('false_positive', 'closed')
       ORDER BY a.created_at DESC
       LIMIT 200`
    );
    return result.rows;
  }

  async detail(id: string) {
    const alertResult = await this.db.query<any>(
      `SELECT a.*, m.provider, m.provider_message_id, m.mailbox, m.sender_domain, m.reply_to, m.return_path,
        m.body_preview, m.authentication_results, m.source_ips, m.received_at, m.created_at AS email_created_at,
        analyst.email AS assigned_analyst_email
       FROM email_alerts a
       JOIN email_messages m ON m.id = a.email_message_id
       LEFT JOIN users analyst ON analyst.id = a.assigned_analyst
       WHERE a.id = $1`,
      [id]
    );
    const alert = alertResult.rows[0];
    if (!alert) throw new NotFoundException("Alert not found");
    const urls = await this.db.query<any>(
      `SELECT u.*,
        COALESCE(json_agg(s.* ORDER BY s.scanned_at DESC) FILTER (WHERE s.id IS NOT NULL), '[]') AS scan_results
       FROM email_urls u
       LEFT JOIN url_scan_results s ON s.email_url_id = u.id
       WHERE u.email_message_id = $1
       GROUP BY u.id
       ORDER BY u.risk_score DESC`,
      [alert.email_message_id]
    );
    const attachments = await this.db.query("SELECT * FROM email_attachments WHERE email_message_id = $1", [alert.email_message_id]);
    const headers = await this.db.query("SELECT name, value FROM email_headers WHERE email_message_id = $1 ORDER BY name", [alert.email_message_id]);
    const audit = await this.audit.listForTarget("email_alert", id);
    return {
      alert,
      urls: urls.rows,
      attachments: attachments.rows,
      headers: headers.rows,
      timeline: audit
    };
  }

  async updateStatus(id: string, input: { status?: string; verdict?: string }, actor: any, requestMeta?: { ip?: string; userAgent?: string }) {
    const allowedStatus = new Set(["open", "triaged", "false_positive", "closed", "incident_created"]);
    const allowedVerdict = new Set(["safe", "suspicious", "phishing", "malicious"]);
    const current = await this.db.query<any>("SELECT * FROM email_alerts WHERE id = $1", [id]);
    const alert = current.rows[0];
    if (!alert) throw new NotFoundException("Alert not found");

    const nextStatus = input.status && allowedStatus.has(input.status) ? input.status : alert.status;
    const nextVerdict = input.verdict && allowedVerdict.has(input.verdict) ? input.verdict : alert.verdict;
    const result = await this.db.query(
      `UPDATE email_alerts
       SET status = $2, verdict = $3, updated_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id, nextStatus, nextVerdict]
    );
    await this.db.query("UPDATE email_messages SET verdict = $2, updated_at = NOW() WHERE id = $1", [alert.email_message_id, nextVerdict]);
    await this.audit.log({
      actorUserId: actor?.id,
      action: "email_alert.status_updated",
      targetType: "email_alert",
      targetId: id,
      details: { fromStatus: alert.status, toStatus: nextStatus, fromVerdict: alert.verdict, toVerdict: nextVerdict },
      ipAddress: requestMeta?.ip,
      userAgent: requestMeta?.userAgent
    });
    return result.rows[0];
  }

  async assign(id: string, analystId: string, actor: any, requestMeta?: { ip?: string; userAgent?: string }) {
    const result = await this.db.query(
      `UPDATE email_alerts SET assigned_analyst = $2, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [id, analystId]
    );
    if (!result.rows[0]) throw new NotFoundException("Alert not found");
    await this.audit.log({
      actorUserId: actor?.id,
      action: "email_alert.assigned",
      targetType: "email_alert",
      targetId: id,
      details: { analystId },
      ipAddress: requestMeta?.ip,
      userAgent: requestMeta?.userAgent
    });
    return result.rows[0];
  }

  async createIncident(id: string, actor: any, requestMeta?: { ip?: string; userAgent?: string }) {
    const detail = await this.detail(id);
    const alert = detail.alert;
    const domain = alert.sender_domain ?? "unknown-domain";
    const topUrl = detail.urls[0]?.domain ?? "no-url";
    const campaignKey = `${domain}|${topUrl}`.toLowerCase();
    const result = await this.db.query<{ id: string }>(
      `INSERT INTO email_incidents (title, severity, campaign_key, summary, alert_ids)
       VALUES ($1, $2, $3, $4, ARRAY[$5]::uuid[])
       ON CONFLICT DO NOTHING
       RETURNING id`,
      [
        `Potential phishing campaign from ${domain}`,
        alert.severity,
        campaignKey,
        `Grouped from alert ${id}. Shared sender domain: ${domain}. Top URL domain: ${topUrl}.`,
        id
      ]
    );
    let incidentId = result.rows[0]?.id;
    if (!incidentId) {
      const existing = await this.db.query<{ id: string; alert_ids: string[] }>(
        "SELECT id, alert_ids FROM email_incidents WHERE campaign_key = $1 ORDER BY created_at DESC LIMIT 1",
        [campaignKey]
      );
      incidentId = existing.rows[0]?.id;
      if (incidentId) {
        await this.db.query(
          `UPDATE email_incidents
           SET alert_ids = CASE WHEN $2 = ANY(alert_ids) THEN alert_ids ELSE array_append(alert_ids, $2) END,
               updated_at = NOW()
           WHERE id = $1`,
          [incidentId, id]
        );
      }
    }
    await this.updateStatus(id, { status: "incident_created" }, actor, requestMeta);
    await this.audit.log({
      actorUserId: actor?.id,
      action: "email_alert.incident_created",
      targetType: "email_alert",
      targetId: id,
      details: { incidentId },
      ipAddress: requestMeta?.ip,
      userAgent: requestMeta?.userAgent
    });
    return { incidentId };
  }

  async overview() {
    const result = await this.db.query(
      `SELECT
        COUNT(DISTINCT m.id) FILTER (WHERE m.created_at::date = CURRENT_DATE)::int AS emails_scanned_today,
        COUNT(DISTINCT m.id) FILTER (WHERE m.verdict = 'suspicious')::int AS suspicious_emails,
        COUNT(DISTINCT m.id) FILTER (WHERE m.verdict = 'phishing')::int AS phishing_emails,
        COUNT(DISTINCT u.id) FILTER (
          WHERE u.verdict = 'malicious' OR s.verdict = 'malicious' OR s.malicious_count > 0
        )::int AS malicious_urls_detected
       FROM email_messages m
       LEFT JOIN email_urls u ON u.email_message_id = m.id
       LEFT JOIN url_scan_results s ON s.email_url_id = u.id`
    );
    const senderDomains = await this.db.query(
      `SELECT sender_domain, COUNT(*)::int AS count
       FROM email_messages
       WHERE sender_domain IS NOT NULL
       GROUP BY sender_domain
       ORDER BY count DESC
       LIMIT 8`
    );
    const targetedUsers = await this.db.query(
      `SELECT recipient, COUNT(*)::int AS count
       FROM email_messages
       GROUP BY recipient
       ORDER BY count DESC
       LIMIT 8`
    );
    const verdicts = await this.db.query(
      `SELECT verdict, COUNT(*)::int AS count FROM email_messages GROUP BY verdict ORDER BY count DESC`
    );
    return { ...result.rows[0], top_sender_domains: senderDomains.rows, top_targeted_users: targetedUsers.rows, verdict_breakdown: verdicts.rows };
  }
}
