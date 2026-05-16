import { Injectable } from "@nestjs/common";
import { DbService } from "../db/db.service";

@Injectable()
export class AuditService {
  constructor(private readonly db: DbService) {}

  async log(input: {
    actorUserId?: string;
    action: string;
    targetType: string;
    targetId: string;
    details?: Record<string, unknown>;
    ipAddress?: string;
    userAgent?: string;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, details, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7)`,
      [
        input.actorUserId ?? null,
        input.action,
        input.targetType,
        input.targetId,
        JSON.stringify(input.details ?? {}),
        input.ipAddress ?? null,
        input.userAgent ?? null
      ]
    );
  }

  async listForTarget(targetType: string, targetId: string) {
    const result = await this.db.query(
      `SELECT id, action, target_type, target_id, details, ip_address, user_agent, created_at
       FROM audit_logs
       WHERE target_type = $1 AND target_id = $2
       ORDER BY created_at DESC`,
      [targetType, targetId]
    );
    return result.rows;
  }
}
