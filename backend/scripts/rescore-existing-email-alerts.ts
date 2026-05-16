import { Pool } from "pg";
import { loadEnvFile } from "../src/load-env";
import { RiskScoringService } from "../src/threat/risk-scoring.service";

async function main() {
  loadEnvFile();
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is required");
  }

  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const scoring = new RiskScoringService();
  let rescored = 0;
  let upsertedAlerts = 0;
  let deletedAlerts = 0;

  try {
    const messages = await pool.query<any>("SELECT * FROM email_messages ORDER BY created_at DESC");
    for (const message of messages.rows) {
      const urls = await pool.query<any>(
        `SELECT u.*,
          COALESCE(SUM(s.malicious_count), 0)::int AS malicious_count,
          COALESCE(SUM(s.suspicious_count), 0)::int AS suspicious_count,
          CASE
            WHEN BOOL_OR(s.verdict = 'malicious') THEN 'malicious'
            WHEN BOOL_OR(s.verdict = 'suspicious') THEN 'suspicious'
            ELSE u.verdict
          END AS combined_verdict
         FROM email_urls u
         LEFT JOIN url_scan_results s ON s.email_url_id = u.id
         WHERE u.email_message_id = $1
         GROUP BY u.id`,
        [message.id]
      );
      const attachments = await pool.query<any>("SELECT filename FROM email_attachments WHERE email_message_id = $1", [message.id]);
      const score = scoring.score({
        sender: message.sender,
        senderDomain: message.sender_domain,
        replyTo: message.reply_to,
        returnPath: message.return_path,
        subject: message.subject,
        bodyPreview: message.body_preview,
        authenticationResults: message.authentication_results,
        urls: urls.rows.map((url) => ({
          id: url.id,
          normalizedUrl: url.normalized_url,
          domain: url.domain,
          isShortened: url.is_shortened,
          isPunycode: url.is_punycode,
          isIpUrl: url.is_ip_url,
          isSuspiciousTld: url.is_suspicious_tld,
          isLookalike: url.is_lookalike,
          hasMismatchedAnchor: url.has_mismatched_anchor,
          verdict: url.combined_verdict,
          maliciousCount: url.malicious_count,
          suspiciousCount: url.suspicious_count
        })),
        attachments: attachments.rows
      });

      await pool.query("UPDATE email_messages SET risk_score = $2, verdict = $3, updated_at = NOW() WHERE id = $1", [
        message.id,
        score.riskScore,
        score.verdict
      ]);

      if (score.riskScore >= 30) {
        await pool.query(
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
            updated_at = NOW()`,
          [
            message.id,
            message.subject,
            message.sender,
            message.recipient,
            score.severity,
            score.riskScore,
            score.verdict,
            score.reasons[0],
            JSON.stringify(score.reasons),
            score.recommendedAction
          ]
        );
        upsertedAlerts += 1;
      } else {
        const deleted = await pool.query("DELETE FROM email_alerts WHERE email_message_id = $1", [message.id]);
        deletedAlerts += deleted.rowCount ?? 0;
      }
      rescored += 1;
    }
  } finally {
    await pool.end();
  }

  console.log(`Rescored ${rescored} emails. Alerts created/updated: ${upsertedAlerts}. Alerts removed: ${deletedAlerts}.`);
}

void main().catch((error) => {
  console.error(error);
  process.exit(1);
});
