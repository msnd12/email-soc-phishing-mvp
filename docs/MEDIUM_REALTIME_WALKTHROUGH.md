# How I Built a Real Email SOC Phishing Detection Dashboard: A Step-by-Step Walkthrough

This article is written as a build-along guide. The goal is not to show a fake cybersecurity dashboard. The goal is to connect a real Gmail inbox, ingest real emails, extract real links, scan them with real threat-intelligence APIs, score the phishing risk, and create alerts for an analyst.

Source code:

```text
https://github.com/msnd12/email-soc-phishing-mvp
```

Important screenshot rule before publishing: never show your real `.env`, API keys, Google client secret, Gmail address, OAuth tokens, database password, real email subjects, or real victim/sender addresses. Blur or crop those parts.

## Screenshot Checklist for Medium

Use these exact screenshots while following the guide:

```text
01-github-repo.png                    GitHub repository page
02-clone-repo-terminal.png            PowerShell after git clone
03-npm-install.png                    npm install completed
04-env-example.png                    .env.example or redacted .env
05-docker-compose-up.png              Docker containers running
06-db-migrate.png                     Database migration completed
07-seed-admin.png                     Admin user seeded
08-google-enable-gmail-api.png        Gmail API enabled in Google Cloud
09-google-oauth-client.png            OAuth client redirect URI, secret hidden
10-threat-intel-keys-redacted.png     API key provider pages, keys hidden
11-backend-running.png                NestJS backend running
12-frontend-running.png               Frontend server running
13-login-page.png                     Dashboard login page
14-connect-gmail.png                  Dashboard Connect Gmail button
15-google-consent-redacted.png        Google OAuth consent, email hidden
16-gmail-connected.png                Gmail connected page, mailbox hidden
17-test-email.png                     Test phishing email before sending
18-fetch-latest.png                   Dashboard after clicking Fetch latest
19-alert-created.png                  Suspicious email alert visible
20-alert-detail.png                   Alert evidence page
21-postgres-email-rows.png            PostgreSQL email_messages query
22-postgres-url-scans.png             PostgreSQL url_scan_results query
23-audit-log.png                      PostgreSQL audit_logs query
```

In the article below, every `Screenshot to insert:` line tells you exactly what image to place there.

## What We Are Building

The MVP flow is:

```text
Real Gmail inbox
  -> Gmail API OAuth connection
  -> Email ingestion
  -> URL extraction
  -> VirusTotal / urlscan.io / Safe Browsing scans
  -> Explainable risk score
  -> SOC alert
  -> Analyst action
  -> Audit log
```

The finished dashboard looks like this with sanitized example data:

![Email Security Overview](https://raw.githubusercontent.com/msnd12/email-soc-phishing-mvp/main/docs/screenshots/email-soc-overview.png)

And the alert detail page shows the evidence:

![Email Alert Evidence Detail](https://raw.githubusercontent.com/msnd12/email-soc-phishing-mvp/main/docs/screenshots/email-alert-detail.png)

Screenshot to insert: `01-github-repo.png`

Show the GitHub repository page. This helps readers know what they are cloning.

## Prerequisites

Install these first:

- Git
- Node.js 20 or newer
- Docker Desktop
- Google Cloud account
- Gmail account you control
- VirusTotal API key
- urlscan.io API key
- Google Safe Browsing API key

This guide uses Windows PowerShell. If you use Linux or macOS, replace `npm.cmd` with `npm`.

## Step 1: Clone the Project

Open PowerShell:

```powershell
cd $HOME\Documents
git clone https://github.com/msnd12/email-soc-phishing-mvp.git
cd email-soc-phishing-mvp
```

Screenshot to insert: `02-clone-repo-terminal.png`

Show the terminal after cloning and entering the project folder.

## Step 2: Install Dependencies

Run:

```powershell
npm.cmd install --cache .\.npm-cache
```

Screenshot to insert: `03-npm-install.png`

Show `npm install` completed successfully. Do not include personal folder paths if you do not want them public.

## Step 3: Create Your `.env` File

Copy the example environment file:

```powershell
Copy-Item .env.example .env
```

Generate two secrets:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Put one generated value in `JWT_SECRET` and the other in `ENCRYPTION_KEY`.

Example `.env` structure:

```text
POSTGRES_USER=soc
POSTGRES_PASSWORD=replace-with-a-long-random-local-db-password
POSTGRES_DB=email_soc
POSTGRES_BIND_ADDR=127.0.0.1
REDIS_BIND_ADDR=127.0.0.1

DATABASE_URL=postgresql://soc:replace-with-a-long-random-local-db-password@localhost:5432/email_soc
REDIS_URL=redis://localhost:6379

JWT_SECRET=replace-with-a-long-random-secret
ENCRYPTION_KEY=replace-with-32-byte-base64-key

GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_PROJECT_ID=
GOOGLE_PUBSUB_TOPIC=
GOOGLE_PUBSUB_SUBSCRIPTION=
GOOGLE_REDIRECT_URI=http://localhost:4000/api/email/oauth/gmail/callback

VIRUSTOTAL_API_KEY=
URLSCAN_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=

APP_URL=http://localhost:5173
WEBHOOK_BASE_URL=
NODE_ENV=development
PORT=4000
FULL_MESSAGE_STORAGE_ENABLED=false

URL_AI_MODEL_PATH=models/url-phishing-model.json

ADMIN_EMAIL=analyst@example.com
ADMIN_PASSWORD=change-this-admin-password
```

Screenshot to insert: `04-env-example.png`

Show `.env.example`, or show `.env` only after blurring all real values. Never publish real secrets.

## Step 4: Start PostgreSQL and Redis

Docker Compose is included:

```powershell
docker compose up -d postgres redis
```

Check the containers:

```powershell
docker compose ps
```

Screenshot to insert: `05-docker-compose-up.png`

Show `postgres` and `redis` running or healthy.

The Compose file keeps local services bound to localhost:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    ports:
      - "${POSTGRES_BIND_ADDR:-127.0.0.1}:5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "${REDIS_BIND_ADDR:-127.0.0.1}:6379:6379"
```

## Step 5: Create the Database Tables

Run:

```powershell
npm.cmd run db:migrate
```

Screenshot to insert: `06-db-migrate.png`

Show the migration command completed without errors.

Important tables include:

```sql
CREATE TABLE IF NOT EXISTS email_messages (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  provider TEXT NOT NULL,
  provider_message_id TEXT NOT NULL,
  mailbox TEXT NOT NULL,
  sender TEXT NOT NULL,
  sender_domain TEXT,
  recipient TEXT NOT NULL,
  reply_to TEXT,
  return_path TEXT,
  subject TEXT,
  received_at TIMESTAMPTZ,
  body_preview TEXT,
  authentication_results JSONB NOT NULL DEFAULT '{}'::JSONB,
  source_ips TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  risk_score INTEGER NOT NULL DEFAULT 0,
  verdict TEXT NOT NULL DEFAULT 'safe',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(provider, provider_message_id, mailbox)
);
```

```sql
CREATE TABLE IF NOT EXISTS email_urls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_message_id UUID NOT NULL REFERENCES email_messages(id) ON DELETE CASCADE,
  original_url TEXT NOT NULL,
  normalized_url TEXT NOT NULL,
  display_text TEXT,
  domain TEXT,
  is_shortened BOOLEAN NOT NULL DEFAULT FALSE,
  is_punycode BOOLEAN NOT NULL DEFAULT FALSE,
  is_ip_url BOOLEAN NOT NULL DEFAULT FALSE,
  is_suspicious_tld BOOLEAN NOT NULL DEFAULT FALSE,
  is_lookalike BOOLEAN NOT NULL DEFAULT FALSE,
  has_mismatched_anchor BOOLEAN NOT NULL DEFAULT FALSE,
  risk_score INTEGER NOT NULL DEFAULT 0,
  verdict TEXT NOT NULL DEFAULT 'safe',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

```sql
CREATE TABLE IF NOT EXISTS url_scan_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_url_id UUID NOT NULL REFERENCES email_urls(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  scan_id TEXT,
  malicious_count INTEGER NOT NULL DEFAULT 0,
  suspicious_count INTEGER NOT NULL DEFAULT 0,
  harmless_count INTEGER NOT NULL DEFAULT 0,
  verdict TEXT NOT NULL DEFAULT 'unknown',
  raw_response JSONB NOT NULL DEFAULT '{}'::JSONB,
  scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## Step 6: Create the Admin Analyst User

Make sure these are set in `.env`:

```text
ADMIN_EMAIL=analyst@example.com
ADMIN_PASSWORD=change-this-admin-password
```

Then run:

```powershell
npm.cmd run seed:admin
```

Screenshot to insert: `07-seed-admin.png`

Show the seed command completed. Hide the password if it appears anywhere.

## Step 7: Configure Gmail API

In Google Cloud:

1. Create or select a project.
2. Go to APIs and Services.
3. Enable the Gmail API.

Screenshot to insert: `08-google-enable-gmail-api.png`

Show the Gmail API enabled screen. Hide project IDs if you do not want them public.

Now create an OAuth 2.0 Web Client.

Add this redirect URI:

```text
http://localhost:4000/api/email/oauth/gmail/callback
```

Screenshot to insert: `09-google-oauth-client.png`

Show the OAuth client screen with the redirect URI visible, but hide the client secret.

Put the values in `.env`:

```text
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:4000/api/email/oauth/gmail/callback
```

## Step 8: Add Threat-Intelligence API Keys

Create keys for:

- VirusTotal
- urlscan.io
- Google Safe Browsing

Then update `.env`:

```text
VIRUSTOTAL_API_KEY=your-virustotal-api-key
URLSCAN_API_KEY=your-urlscan-api-key
GOOGLE_SAFE_BROWSING_API_KEY=your-safe-browsing-api-key
```

Screenshot to insert: `10-threat-intel-keys-redacted.png`

Show the provider dashboards or `.env`, but blur the actual keys.

If a key is missing, the backend stores this honestly:

```text
integration_not_configured
```

It does not pretend the scan happened.

## Step 9: Run the Backend

Open a new PowerShell terminal:

```powershell
cd $HOME\Documents\email-soc-phishing-mvp
npm.cmd run backend:dev
```

You should see the API running on:

```text
http://localhost:4000
```

Screenshot to insert: `11-backend-running.png`

Show the backend terminal after NestJS starts.

## Step 10: Run the Frontend

Open another PowerShell terminal:

```powershell
cd $HOME\Documents\email-soc-phishing-mvp
npm.cmd run frontend:dev
```

Open:

```text
http://localhost:5173
```

Screenshot to insert: `12-frontend-running.png`

Show the frontend terminal and local URL.

## Step 11: Login

Open:

```text
http://localhost:5173
```

Login using:

```text
ADMIN_EMAIL
ADMIN_PASSWORD
```

from `.env`.

Screenshot to insert: `13-login-page.png`

Show the login page. Do not show your password.

## Step 12: Connect Gmail

After login, click:

```text
Connect Gmail
```

Screenshot to insert: `14-connect-gmail.png`

Show the dashboard with the Connect Gmail button.

Google will show the OAuth consent flow.

Screenshot to insert: `15-google-consent-redacted.png`

Show the consent screen, but hide your Gmail address.

After consent, the app redirects back to the frontend.

Screenshot to insert: `16-gmail-connected.png`

Show the connected screen, but hide your real mailbox address.

The Gmail OAuth code uses a signed state value and encrypted token storage:

```ts
getAuthUrl(userId: string): string {
  const oauth = this.oauthClient();
  const state = jwt.sign(
    { sub: userId, provider: "gmail" },
    this.config.jwtSecret,
    { expiresIn: "10m" }
  );

  return oauth.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/gmail.readonly",
      "https://www.googleapis.com/auth/gmail.modify",
      "https://www.googleapis.com/auth/userinfo.email"
    ],
    state
  });
}
```

## Step 13: Send a Test Phishing Email

Use another email account and send a test message to your connected Gmail inbox.

Subject:

```text
Urgent password verification required
```

Body:

```text
Your mailbox access will be suspended today. Verify your password immediately:
https://bit.ly/security-reset-test
```

HTML test:

```html
<p>Your Microsoft 365 session expired. Sign in again:</p>
<p><a href="https://login-microsoft-support.click/verify">https://microsoft.com</a></p>
```

Screenshot to insert: `17-test-email.png`

Show the test email before sending. Use only your own test inbox.

## Step 14: Fetch Latest Emails

Back in the dashboard, click:

```text
Fetch latest
```

Screenshot to insert: `18-fetch-latest.png`

Show the dashboard after clicking Fetch latest.

The backend endpoint calls Gmail, ingests the messages, and audits the polling action:

```ts
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
```

## Step 15: Watch the Alert Appear

If the message crosses the alert threshold, it appears in the suspicious email table.

Screenshot to insert: `19-alert-created.png`

Show the suspicious email row. Blur real sender, recipient, and subject if needed.

Open the alert.

Screenshot to insert: `20-alert-detail.png`

Show the evidence page: authentication results, URLs, scan results, AI/rules explanation, recommendation, analyst buttons, and timeline.

## Step 16: How URL Extraction Works

The extractor pulls URLs from plain text and HTML anchors:

```ts
const URL_REGEX = /\bhttps?:\/\/[^\s<>"')\]]+/gi;
const ANCHOR_REGEX = /<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;

extract(text?: string, html?: string): ExtractedUrl[] {
  const candidates: Array<{ url: string; displayText?: string }> = [];

  const pushTextUrls = (value?: string) => {
    if (!value) return;
    for (const match of value.matchAll(URL_REGEX)) {
      candidates.push({ url: match[0] });
    }
  };

  pushTextUrls(text);
  pushTextUrls(html);

  if (html) {
    for (const match of html.matchAll(ANCHOR_REGEX)) {
      candidates.push({
        url: match[1],
        displayText: this.plainText(match[2])
      });
    }
  }

  return candidates
    .map((candidate) => this.analyze(candidate.url, candidate.displayText))
    .filter(Boolean);
}
```

Each URL is analyzed for suspicious features:

```ts
const isIpUrl = this.isIp(domain);
const isPunycode = asciiDomain.startsWith("xn--") || asciiDomain.includes(".xn--");
const isShortened = SHORTENER_DOMAINS.has(domain);
const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld);
const isLookalike = this.looksLikeBrand(domain);
const hasMismatchedAnchor = this.hasMismatchedAnchor(displayText, domain);
```

## Step 17: How Threat-Intel Scanning Works

The backend calls all configured providers:

```ts
async scanUrl(url: string): Promise<ScanVerdict[]> {
  const providers = await Promise.allSettled([
    this.scanVirusTotal(url),
    this.scanUrlscan(url),
    this.scanSafeBrowsing(url)
  ]);

  return providers.map((provider) => {
    if (provider.status === "fulfilled") return provider.value;

    return {
      provider: "web_risk",
      maliciousCount: 0,
      suspiciousCount: 0,
      harmlessCount: 0,
      verdict: "unknown",
      rawResponse: { error: String(provider.reason) }
    };
  });
}
```

VirusTotal example:

```ts
private async scanVirusTotal(url: string): Promise<ScanVerdict> {
  const apiKey = this.config.threatIntel.virusTotalApiKey;
  if (!apiKey) return this.notConfigured("virustotal");

  const id = Buffer.from(url).toString("base64url");
  const details = await fetchJson<any>(
    `https://www.virustotal.com/api/v3/urls/${id}`,
    { headers: { "x-apikey": apiKey } }
  );

  const stats = details?.data?.attributes?.last_analysis_stats ?? {};
  const malicious = Number(stats.malicious ?? 0);
  const suspicious = Number(stats.suspicious ?? 0);

  return {
    provider: "virustotal",
    scanId: details?.data?.id,
    maliciousCount: malicious,
    suspiciousCount: suspicious,
    harmlessCount: Number(stats.harmless ?? 0),
    verdict: malicious > 0 ? "malicious" : suspicious > 0 ? "suspicious" : "safe",
    rawResponse: details
  };
}
```

## Step 18: How Risk Scoring Works

The scoring service adds points for real evidence:

```ts
if (auth.dmarc && auth.dmarc !== "pass") {
  score += 20;
  reasons.push(`DMARC ${auth.dmarc}`);
}

if (input.replyTo && input.sender && !this.sameOrganizationDomain(input.replyTo, input.sender)) {
  score += 12;
  reasons.push("Reply-To domain differs from sender domain");
}

if (url.hasMismatchedAnchor) {
  score += 15;
  reasons.push("Link text does not match the real destination");
}

if ((url.maliciousCount ?? 0) > 0 || url.verdict === "malicious") {
  score += 45;
  reasons.push("Threat intelligence marked a URL malicious");
}
```

Severity mapping:

```text
0-29   Informational
30-49  Low
50-69  Medium
70-89  High
90-100 Critical
```

The output includes:

```text
risk_score
verdict
confidence
severity
reasons
recommended_action
```

## Step 19: Prove It in PostgreSQL

Check email rows:

```powershell
docker compose exec postgres psql -U soc -d email_soc -c "SELECT subject, sender, risk_score, verdict FROM email_messages ORDER BY created_at DESC LIMIT 5;"
```

Screenshot to insert: `21-postgres-email-rows.png`

Blur real subjects, senders, and recipients.

Check URL scan results:

```powershell
docker compose exec postgres psql -U soc -d email_soc -c "SELECT provider, verdict, malicious_count, suspicious_count, scanned_at FROM url_scan_results ORDER BY scanned_at DESC LIMIT 10;"
```

Screenshot to insert: `22-postgres-url-scans.png`

Show provider verdicts and counts.

Check audit logs:

```powershell
docker compose exec postgres psql -U soc -d email_soc -c "SELECT action, target_type, target_id, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 10;"
```

Screenshot to insert: `23-audit-log.png`

Show that analyst actions were logged. Blur IDs if you want.

## Step 20: Useful API Testing Commands

Login:

```powershell
$login = Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:4000/api/auth/login" `
  -ContentType "application/json" `
  -Body '{"email":"analyst@example.com","password":"YOUR_ADMIN_PASSWORD"}'

$headers = @{ Authorization = "Bearer $($login.token)" }
```

Poll Gmail:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:4000/api/email/poll/gmail" `
  -Headers $headers `
  -ContentType "application/json" `
  -Body '{"maxResults":10}'
```

List alerts:

```powershell
Invoke-RestMethod `
  -Method Get `
  -Uri "http://localhost:4000/api/email-alerts" `
  -Headers $headers
```

Mark an alert as phishing:

```powershell
Invoke-RestMethod `
  -Method Patch `
  -Uri "http://localhost:4000/api/email-alerts/ALERT_ID/status" `
  -Headers $headers `
  -ContentType "application/json" `
  -Body '{"status":"triaged","verdict":"phishing"}'
```

Create an incident:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:4000/api/email-alerts/ALERT_ID/create-incident" `
  -Headers $headers
```

Export evidence:

```powershell
Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:4000/api/reports/email-alert/ALERT_ID" `
  -Headers $headers
```

## Optional: Train the URL AI Classifier

The app can train a URL classifier using PhishTank phishing URLs and Tranco benign domains:

```powershell
$env:PHISHTANK_APP_KEY="your-phishtank-app-key"
$env:PHISHTANK_USER_AGENT="email-soc-phishing-mvp/0.1 your-email@example.com"
$env:AI_TRAINING_SAMPLE_SIZE="300000"
$env:URL_AI_MODEL_PATH="models/url-phishing-model.json"
npm.cmd run ai:train
```

If you have the VON URL dataset:

```powershell
$env:VON_DATASET_PATH="C:\path\to\vonDataset20180426.dill"
$env:URL_AI_MODEL_PATH="models/url-phishing-model.json"
$env:VON_AI_TARGET_MAX_FPR="0.02"
npm.cmd run ai:train:von-ngram
```

Do not commit local datasets or trained models unless you intentionally want to publish them.

## Security Checklist Before Publishing the Project

Run:

```powershell
git log --all -- .env
git log --all -- "*token*"
git log --all -- "*secret*"
git log --all -- "*key*"
git status --ignored
```

Your `.gitignore` should include:

```text
.env
node_modules/
logs/
*.log
*.sqlite
*.db
coverage/
dist/
build/
.DS_Store
backend/datasets/
backend/models/
```

On GitHub, enable:

```text
Settings -> Code security and analysis -> Secret scanning
Settings -> Code security and analysis -> Push protection
Settings -> Dependabot alerts
```

## Troubleshooting

If Docker is not recognized:

```powershell
docker --version
```

If it fails, restart PowerShell after installing Docker Desktop.

If migration says `DATABASE_URL is required`, your `.env` is missing or the command is running from the wrong folder.

If Gmail connect ends with `not found`, check:

```text
GOOGLE_REDIRECT_URI=http://localhost:4000/api/email/oauth/gmail/callback
APP_URL=http://localhost:5173
PORT=4000
```

Also make sure the same redirect URI is added in Google Cloud.

If alerts are too noisy, train the model with a lower false-positive target:

```powershell
$env:VON_AI_TARGET_MAX_FPR="0.01"
npm.cmd run ai:train:von-ngram
```

If threat scans show `integration_not_configured`, add the missing API key and restart the backend.

## Final Acceptance Test

The project is functional only when this passes:

```text
1. Real Gmail connected
2. Test email sent to that inbox
3. Email ingested through Gmail API
4. URL extracted
5. VirusTotal/urlscan/Safe Browsing called
6. Results saved in PostgreSQL
7. Risk score and explanation generated
8. Alert visible in dashboard
9. Analyst updates verdict
10. Audit log written
```

That is the difference between a dashboard that looks like a SOC tool and a dashboard that actually does SOC work.

