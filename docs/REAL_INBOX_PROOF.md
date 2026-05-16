# Real Gmail Proof Checklist

Use this sheet during acceptance testing. Do not mark the MVP complete until each item has real evidence.

## Required Inputs

- Gmail test mailbox connected through OAuth
- Sender mailbox you control
- `VIRUSTOTAL_API_KEY`
- `URLSCAN_API_KEY`
- `GOOGLE_SAFE_BROWSING_API_KEY`
- PostgreSQL running
- Redis running

## Evidence to Capture

1. Screenshot of connected Gmail mailbox in the dashboard.
2. Test email in Gmail inbox.
3. Backend response from `POST /api/email/poll/gmail` or Pub/Sub webhook delivery log.
4. Database row count for:

   ```sql
   SELECT COUNT(*) FROM email_messages;
   SELECT COUNT(*) FROM email_urls;
   SELECT provider, verdict, COUNT(*) FROM url_scan_results GROUP BY provider, verdict;
   SELECT COUNT(*) FROM email_alerts;
   SELECT COUNT(*) FROM audit_logs;
   ```

5. Dashboard screenshot showing the alert list.
6. Alert detail screenshot showing:

   - sender
   - subject
   - extracted URL
   - VirusTotal result
   - urlscan.io result
   - Safe Browsing result
   - risk score and reasons
   - recommended action

7. Screenshot after marking the alert `phishing`.
8. Database evidence that the audit log was written:

   ```sql
   SELECT action, target_type, target_id, details, created_at
   FROM audit_logs
   ORDER BY created_at DESC
   LIMIT 5;
   ```
