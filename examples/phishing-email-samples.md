# Test Phishing Email Examples

Use a mailbox you control. Send these from a separate account to the connected Gmail inbox.

## Suspicious Shortener

Subject:

```text
Urgent password verification required
```

Body:

```text
Your mailbox access will be suspended today. Verify your password immediately:
https://bit.ly/security-reset-test
```

Expected signals:

- Urgent language
- URL shortener
- Risk score should be at least suspicious depending on threat-intel results

## Mismatched Microsoft Anchor

Send as HTML:

```html
<p>Your Microsoft 365 session expired. Sign in again:</p>
<p><a href="https://login-microsoft-support.click/verify">https://microsoft.com</a></p>
```

Expected signals:

- Mismatched anchor text
- Lookalike Microsoft domain
- Suspicious `.click` TLD

## IP Address URL

Subject:

```text
Invoice payment confirmation
```

Body:

```text
Please confirm the pending payment:
http://192.0.2.55/payroll
```

Expected signals:

- IP-address URL
- Payment-themed language

Note: `192.0.2.0/24` is reserved for documentation. Threat-intel providers may return clean or unknown, but the local scoring engine still flags the IP-address URL.
