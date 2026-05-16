# Security Policy

## Secret Handling

Never commit real credentials, API keys, OAuth client secrets, Gmail tokens, database passwords, trained datasets, or `.env` files.

This repository intentionally commits only `.env.example`. Real values must stay in local `.env`, GitHub Actions secrets, or the deployment platform secret store.

Before pushing changes, run:

```powershell
npm.cmd audit --omit=dev
npm.cmd run lint
npm.cmd run test
npm.cmd run build
git status --ignored --short
```

Check that these stay untracked or ignored:

- `.env`
- `.env.*` except `.env.example`
- `backend/datasets/`
- `backend/models/*.json`
- `*.log`
- `node_modules/`

## Required Production Controls

- Use a private GitHub repository unless the project is intentionally open sourced.
- Rotate any API key that was ever pasted into chat, screenshots, logs, or Git history.
- Use different secrets for local development and production.
- Set `JWT_SECRET`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD`, OAuth secrets, and threat-intel API keys from a secret manager.
- Keep `FULL_MESSAGE_STORAGE_ENABLED=false` unless the admin has approved full body storage.
- Restrict `APP_URL`, OAuth redirect URIs, and webhooks to the deployed domain.
- Put the API behind HTTPS.
- Keep PostgreSQL and Redis bound to private interfaces, not public internet interfaces.
- Enable GitHub secret scanning, Dependabot alerts, and branch protection.

## Reporting Vulnerabilities

Open a private issue or contact the project maintainer. Do not publish exploit details publicly until a fix is available.
