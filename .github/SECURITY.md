# Security policy

## Report a vulnerability

Use **Security → Report a vulnerability** when private reporting is available.
Include the affected version, impact and a minimal reproduction using synthetic data.
If that option is unavailable, open an issue asking for a private contact; leave out
exploit details. Never post credentials, Telegram sessions or real evidence archives.

Fixes target the latest release. Older versions are not maintained separately.
There is no guaranteed response time or independent security certification.

## Before you deploy

| Boundary | What to know |
| --- | --- |
| Access | One panel token controls every workspace. Keep the panel on localhost, or use HTTPS or an SSH tunnel. |
| Stored data | Credentials are encrypted; messages and media are not. Protect the data directory with disk encryption and restrictive permissions. |
| Evidence | Signatures detect changes against a trusted key. They do not establish truth or complete capture. Keep checkpoints separately. |
| Exports | Archives contain collected content and identifiers. Treat them as sensitive. |

[Security model and data handling](../docs/SECURITY-MODEL.md) · [Deployment](../docs/DEPLOYMENT.md) · [Hardening](../docs/HIGH-ASSURANCE.md)

<!-- operator-notice:start -->

[Author's position](../docs/OPERATOR-INCOMPATIBILITY.md) · [Source record](https://phishdestroy.io/steam_dossier/taylor_wessing) · [MIT License](../LICENSE)


<!-- operator-notice:end -->
