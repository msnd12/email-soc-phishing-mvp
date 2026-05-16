import { Injectable } from "@nestjs/common";
import { AuditService } from "../audit/audit.service";
import { DbService } from "../db/db.service";

@Injectable()
export class PlaybooksService {
  constructor(
    private readonly db: DbService,
    private readonly audit: AuditService
  ) {}

  async run(action: string, input: Record<string, unknown>, actor: any, requestMeta?: { ip?: string; userAgent?: string }) {
    const integrationConfigured = false;
    const status = integrationConfigured ? "completed" : "integration_not_configured";
    const result = {
      message: integrationConfigured
        ? "Playbook completed"
        : "The response integration is not configured yet. No mailbox, gateway, or blocklist change was made.",
      input
    };
    const saved = await this.db.query<{ id: string }>(
      `INSERT INTO playbook_runs (alert_id, action, status, result, requested_by)
       VALUES ($1, $2, $3, $4::jsonb, $5)
       RETURNING id`,
      [(input.alertId as string | undefined) ?? null, action, status, JSON.stringify(result), actor?.id ?? null]
    );
    await this.audit.log({
      actorUserId: actor?.id,
      action: `playbook.${action}`,
      targetType: "playbook_run",
      targetId: saved.rows[0].id,
      details: { status, ...input },
      ipAddress: requestMeta?.ip,
      userAgent: requestMeta?.userAgent
    });
    return { runId: saved.rows[0].id, action, status, result };
  }
}
