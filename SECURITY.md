# Security Policy

AntiNoise is a hackathon security prototype. Do not use it as the sole control protecting a production environment.

## Reporting a vulnerability

If this repository is public, report security issues privately to the repository owners rather than opening a public issue containing exploit details, credentials, tenant information, or sensitive telemetry.

Configure GitHub private vulnerability reporting if the repository will remain public.

## Secrets and telemetry

Do not commit:

- `.env` files
- client secrets or API keys
- access/refresh tokens
- private keys or certificates
- production tenant captures
- user mail/file metadata
- production IP or identity data that should not be public

`fixtures/z_capture_*.json` and `data/` are ignored for this reason.

## Live response

Use disposable test users, applications, resource groups, and VMs. Review `LIVE_ACTIONS` before starting the application. Actions not intentionally configured should remain simulated.
