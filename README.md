# Email SOC Phishing Detection MVP

This is a real email phishing detection MVP for a SOC/SIEM dashboard. It is intentionally scoped to the end-to-end email flow first:

1. Analyst login
2. Gmail OAuth connection
3. Gmail push webhook plus documented polling fallback
4. Real email ingestion
5. URL extraction and URL feature detection
6. VirusTotal, urlscan.io, and Google Safe Browsing scanning
7. Explainable phishing risk scoring
8. Alert creation and alert detail evidence
9. Analyst verdict/status updates
10. Audit logs for analyst actions

It does not claim the broader dashboard is complete. Microsoft 365 and enforcement playbooks are represented by real endpoints, but the MVP returns `integration_not_configured` until those connectors are configured.

## Stack

- Backend: NestJS, PostgreSQL, Redis-ready configuration
- Frontend: dependency-free static analyst UI
- Database schema: SQL migrations in `backend/db/schema.sql`
- Threat intel: VirusTotal URL API, urlscan.io API, Google Safe Browsing API
- Email provider: Gmail API OAuth 2.0, Gmail watch/Pub/Sub, and polling fallback

## Local Setup

1. Install dependencies:

   ```powershell
   npm.cmd install --cache .\.npm-cache
   ```

2. Copy the environment file:

   ```powershell
   Copy-Item .env.example .env
   ```

3. Generate secrets and put them in `.env`:

   ```powershell
   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
   ```

   Use one generated value for `ENCRYPTION_KEY`. Use another long random value for `JWT_SECRET`.

4. Start PostgreSQL and Redis.

   Docker Compose is included:

   ```powershell
   docker compose up -d postgres redis
   ```

   Keep `POSTGRES_PASSWORD` in `.env` only. Do not commit real database passwords or API keys.

5. Apply schema and seed the first analyst:

   ```powershell
   npm.cmd run db:migrate
   npm.cmd run seed:admin
   ```

6. Run the API and UI:

   ```powershell
   npm.cmd run backend:dev
   npm.cmd run frontend:dev
   ```

   Backend: `http://localhost:4000`  
   Frontend: `http://localhost:5173`

## Gmail Setup

1. In Google Cloud, enable Gmail API.
2. Create an OAuth 2.0 Web Client.
3. Add redirect URI:

   ```text
   http://localhost:4000/api/email/oauth/gmail/callback
   ```

4. Put these values in `.env`:

   ```text
   GOOGLE_CLIENT_ID=
   GOOGLE_CLIENT_SECRET=
   GOOGLE_REDIRECT_URI=http://localhost:4000/api/email/oauth/gmail/callback
   ```

5. Optional near-real-time Gmail watch:

   - Create a Pub/Sub topic.
   - Grant `gmail-api-push@system.gserviceaccount.com` publish permission on that topic.
   - Expose the backend webhook over HTTPS, for example with a trusted tunnel.
   - Configure Pub/Sub push delivery to:

     ```text
     https://your-public-url/api/email/webhook/gmail
     ```

   - Set:

     ```text
     GOOGLE_PROJECT_ID=
     GOOGLE_PUBSUB_TOPIC=
     GOOGLE_PUBSUB_SUBSCRIPTION=
     WEBHOOK_BASE_URL=https://your-public-url
     ```

6. If Pub/Sub is not ready, use the dashboard `Fetch latest` button. That uses the Gmail API against the real connected mailbox and ingests recent inbox messages.

## Threat Intel Setup

Add at least VirusTotal and urlscan.io keys for the acceptance proof:

```text
VIRUSTOTAL_API_KEY=
URLSCAN_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
```

If a key is missing, the backend stores `integration_not_configured` for that provider. It does not fake clean or malicious results.

## Train the URL AI Classifier

The backend now includes an offline URL phishing classifier trainer using PhishTank positives and Tranco benign domains.

For the requested 300k + 300k training run:

```powershell
$env:PHISHTANK_APP_KEY="your-phishtank-app-key"
$env:PHISHTANK_USER_AGENT="email-soc-phishing-mvp/0.1 your-email@example.com"
$env:AI_TRAINING_SAMPLE_SIZE="300000"
$env:URL_AI_MODEL_PATH="models/url-phishing-model.json"
npm.cmd run ai:train
```

See `docs/AI_TRAINING.md` before running it. PhishTank's public online-valid feed may contain fewer than 300,000 active URLs on a given day; the trainer fails honestly instead of duplicating rows.

## Real Inbox Proof

The MVP is not accepted until these pass against a real mailbox and real API keys:

1. Login as the seeded analyst.
2. Connect a Gmail mailbox from the dashboard.
3. Send one test message from another account using an example from `examples/phishing-email-samples.md`.
4. Either wait for Gmail Pub/Sub push or click `Fetch latest`.
5. Confirm the backend creates an `email_messages` row.
6. Confirm one or more `email_urls` rows are created.
7. Confirm `url_scan_results` contains VirusTotal and urlscan.io rows.
8. Confirm the alert appears in the dashboard.
9. Open the alert detail and verify sender, subject, URL evidence, scan results, reasons, and recommended action.
10. Mark the alert safe, suspicious, phishing, or malicious.
11. Confirm `audit_logs` contains the analyst action.

## Useful Commands

```powershell
npm.cmd run build
npm.cmd run test --workspace backend
npm.cmd run lint --workspace frontend
npm.cmd run ai:train
```

## GitHub Upload Safety

Before pushing to GitHub:

```powershell
npm.cmd audit --omit=dev
npm.cmd run lint
npm.cmd run test
npm.cmd run build
git status --ignored --short
```

Only `.env.example` should be committed. Real `.env` files, trained model JSON files, datasets, logs, and `node_modules` must remain ignored.

## Production Safety Notes

- Keep the GitHub repository private unless the project is intentionally open sourced.
- Enable GitHub secret scanning, Dependabot alerts, and branch protection.
- OAuth tokens are encrypted with AES-256-GCM using `ENCRYPTION_KEY`.
- API keys are only loaded from environment variables.
- Database and Redis ports are bound to `127.0.0.1` by default in Docker Compose.
- Full email body storage is off by default. Set `FULL_MESSAGE_STORAGE_ENABLED=true` only after an admin decision.
- HTML email content is sanitized before storage when full body storage is enabled.
- The app never opens suspicious links in a browser for redirect following.
- Threat scanning uses external TI APIs instead of local link clicking.
- Playbook buttons record an audit/playbook run and clearly return `integration_not_configured` until enforcement integrations exist.
