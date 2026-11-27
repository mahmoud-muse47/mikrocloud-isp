# Security architecture

Engineering references used: OWASP Top 10, ASVS, API Security Top 10, NIST CSF 2.0, NIST SSDF. No certification is claimed.

## Controls: status
| Control | Status |
|---|---|
| Separate Admin and Client portals (host-based, session-separated) | DONE, tested locally; live needs a domain |
| Role checks on every route (server side) | DONE, tested |
| Passwords hashed (scrypt, per-user salt) | DONE. Spec asks Argon2id: NOT DONE (Node has no built-in Argon2id; would need a native dependency) |
| Password policy and secure reset (one-time, 24h, admin issued) | DONE, tested locally |
| Login throttle + account lockout | DONE |
| Session cookies HttpOnly, Secure, SameSite; expiry; rotation at login | DONE |
| Device and session history, login history | DONE (Account page) |
| TOTP 2FA with recovery codes | DONE for all users; not forced on super admin |
| Login notifications | NOT DONE (no email/SMS sending) |
| Passkeys | NOT DONE |
| Encryption at rest, AES-256-GCM (device credentials, 2FA secrets) | DONE, tested |
| Key rotation | PARTLY: DATA_KEY_OLD lets old data be read and re-encrypted at startup; tested. No managed KMS (paid/external) |
| CSP with script nonce, HSTS, X-Frame-Options, nosniff | DONE; inline styles and inline event handlers still allowed |
| CSRF tokens | DONE |
| Upload checks (type by magic bytes, size) | DONE; no malware scan |
| Tenant isolation at query layer | DONE, tested locally. No database row-level security |
| Protected RouterOS command system, SSRF rules | NOT DONE: no real router connection exists yet |
| Security & System Monitoring page | DONE (Admin > Security): failed/successful logins, suspicious IPs, locked accounts, open reset requests, privilege and config changes, control status. Not available: API auth failures, router failures, webhook failures, scan results (those features do not exist yet) |
| Central audit log (user, tenant, action, IP, time) | DONE; no correlation ID; not tamper-proof |
| WAF, DDoS, bot protection | NOT DONE in the app: depends on Cloudflare/host. Rate limiting only on login/forgot |
| Encrypted, automated, off-site backups | NOT DONE (see BACKUP_AND_RECOVERY.md) |
| AI security rules | No AI feature exists. Rules for later: tool allowlist, tenant-scoped data only, no raw SQL/RouterOS from model output, human approval for sensitive actions, all actions through normal authorization |

## Branding
Name is read from APP_NAME / System page; logo letter derives from it; colors are CSS variables. Not yet configurable: favicon, logo image, email and invoice branding (no emails exist; invoices are shown in-app).
