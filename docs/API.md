# API Reference

Base URL: `http://localhost:4000`

All analyst endpoints require:

```text
Authorization: Bearer <jwt>
```

## Auth

`POST /api/auth/login`

```json
{ "email": "analyst@example.com", "password": "your-password" }
```

`GET /api/auth/me`

## Gmail Connection and Ingestion

`GET /api/email/oauth/gmail/start`

Returns the Google OAuth consent URL.

`GET /api/email/oauth/gmail/callback`

OAuth callback used by Google.

`GET /api/email/connections`

Lists connected Gmail mailboxes.

`POST /api/email/webhook/gmail`

Receives Google Pub/Sub push notifications, fetches the Gmail history delta, normalizes messages, scans URLs, scores risk, and creates alerts.

`POST /api/email/webhook/microsoft`

Returns `integration_not_configured` in this MVP unless Microsoft Graph support is added.

`POST /api/email/poll/gmail`

Polling fallback for local proof with a real Gmail inbox.

```json
{ "mailbox": "user@example.com", "maxResults": 10 }
```

`GET /api/email/messages`

Lists ingested messages.

`GET /api/email/messages/:id`

Returns message metadata, headers, attachments, URLs, and scan results.

`POST /api/email/rescan/:id`

Rescans stored metadata and URLs.

## Threat Scanning

`POST /api/threat/scan-url`

```json
{ "url": "https://example.com/login" }
```

`GET /api/threat/url/:id`

Returns one extracted URL and its scan history.

`POST /api/threat/lookup`

```json
{ "indicatorType": "url", "indicatorValue": "https://example.com/login" }
```

Allowed indicator types: `url`, `domain`, `ip`, `file_hash`, `sender_email`.

## Alerts

`GET /api/email-alerts`

Lists suspicious email alerts.

`GET /api/email-alerts/overview`

Returns real metrics from the database.

`GET /api/email-alerts/:id`

Returns alert evidence, sender details, authentication results, URLs, threat-intel results, AI explanation, attachments, and timeline.

`PATCH /api/email-alerts/:id/status`

```json
{ "status": "triaged", "verdict": "phishing" }
```

Statuses: `open`, `triaged`, `false_positive`, `closed`, `incident_created`.  
Verdicts: `safe`, `suspicious`, `phishing`, `malicious`.

`POST /api/email-alerts/:id/assign`

```json
{ "analystId": "00000000-0000-0000-0000-000000000000" }
```

`POST /api/email-alerts/:id/create-incident`

Creates or updates a campaign incident based on sender domain and top URL domain.

## Playbooks

These create real `playbook_runs` and `audit_logs`. Enforcement returns `integration_not_configured` until mailbox/security gateway integrations are added.

`POST /api/playbooks/quarantine-email`

`POST /api/playbooks/block-sender`

`POST /api/playbooks/block-domain`

`POST /api/playbooks/notify-user`

Example:

```json
{ "alertId": "alert-uuid", "sender": "attacker@example.net", "domain": "example.net" }
```

## Reports

`POST /api/reports/email-alert/:id`

Creates a JSON evidence report record.

`GET /api/reports/:id/download`

Downloads the JSON report.
