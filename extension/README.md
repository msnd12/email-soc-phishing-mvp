# Email SOC Browser Extension

This is a Chrome/Edge Manifest V3 companion extension for the Email SOC phishing detection MVP.

It does not replace the backend. The backend still owns Gmail OAuth, real email ingestion, threat-intel scanning, scoring, alerts, and audit logs. The extension gives analysts a small browser surface for the same real flow.

## What It Does

- Logs in to the existing Email SOC backend.
- Shows real alert metrics from PostgreSQL.
- Shows the latest email alerts.
- Starts Gmail OAuth through the backend.
- Triggers `Fetch latest` Gmail ingestion.
- Extracts visible external links from Gmail or Outlook webmail pages without clicking them.
- Sends selected visible links to `/api/threat/scan-url`.
- Opens the full dashboard for deeper investigation.

## What It Does Not Do

- It does not store API keys.
- It does not store Gmail OAuth tokens.
- It does not click suspicious links.
- It does not pretend to quarantine or block messages.
- It does not create email alerts from page scraping; real alerts are created by backend ingestion.

## Setup

1. Start the backend and frontend:

   ```powershell
   npm.cmd run backend:dev
   npm.cmd run frontend:dev
   ```

2. Open Chrome or Edge:

   ```text
   chrome://extensions
   ```

3. Enable `Developer mode`.
4. Click `Load unpacked`.
5. Select this folder:

   ```text
   extension
   ```

6. Copy the extension ID from `chrome://extensions`.
7. Add this to the project `.env`:

   ```text
   EXTENSION_ALLOWED_ORIGINS=chrome-extension://YOUR_EXTENSION_ID
   ```

8. Restart the backend.
9. Open the extension popup and log in with the seeded analyst user.

## Usage

1. Click `Connect Gmail` if no mailbox is connected.
2. Click `Fetch latest` to ingest recent Gmail messages through the Gmail API.
3. Open Gmail or Outlook webmail in the same browser.
4. Open an email.
5. Click `Extract visible links`.
6. Click `Scan links` to send those links to configured threat-intel providers.
7. Review full alerts in the dashboard.

## Security Notes

- Keep `.env` out of Git.
- Use the exact extension origin in `EXTENSION_ALLOWED_ORIGINS`; do not allow all extensions in production.
- The extension stores only the analyst JWT and UI settings in `chrome.storage.local`.
- The extension does not have access to provider API keys.
- The content script only reads visible anchor `href` values and returns them to the popup when you click the extension action.
