# Threat model and register

Method: engineering review against OWASP Top 10 / ASVS / API Top 10 categories. This is not a certification and not a penetration test by an independent party. "Tested" means an automated test in this repo or a manual check on the live site.
Severity and likelihood are my estimates (H/M/L).

| # | Threat | Attack scenario | Modules | Sev | Lik | Mitigation | Verification | Residual risk |
|---|---|---|---|---|---|---|---|---|
| 1 | Unauthorized access | Guess or reuse client password | login | H | M | scrypt hashes, lockout after 5 fails, DB-backed per-IP throttle (30/10 min) | security.test.js brute force | No breached-password check; per-IP only |
| 2 | Account takeover | Stolen password | login, 2FA | H | M | Optional TOTP 2FA + recovery codes, session history | tests | 2FA not enforced for super admin (shown as a warning on the Security page) |
| 3 | Privilege escalation | Client admin edits role/permissions to become super admin | users, employees | H | L | Role from server session only; super admin routes check role; no role field accepted from forms | tests | Low |
| 4 | Tenant data leakage | Change an id in the URL | all tenant modules | H | M | Every query filters company_id from the session; numeric id guard | cross-tenant tests (local, 2 clients) | Live has only 1 real client |
| 5 | SQL injection | Quote characters in forms | all | H | L | Parameterized queries only | injection tests | Low |
| 6 | XSS | Script in names/notes | views | H | M | Output escaping, nonce CSP for scripts | XSS tests | CSP still allows inline styles and inline event handlers |
| 7 | CSRF | Hostile page posts to the app | all POST | M | M | Token on every POST, SameSite cookies | tests | Low |
| 8 | SSRF | Backend fetches a user URL | none today | H | L | No feature fetches user-supplied URLs. Device connections are not implemented yet | n/a | MUST be designed in when real RouterOS connections are added (allowlist, no private/metadata ranges) |
| 9 | Session hijacking | Stolen cookie | sessions | H | L | HttpOnly, Secure, SameSite, rotation on login, 8h expiry | tests | Cookie theft from a compromised device |
| 10 | Brute force | Credential stuffing | login, forgot | M | H | Throttle, lockout, neutral reset answer | tests | Distributed attacks stay under per-IP limit; no CAPTCHA |
| 11 | API abuse | Hammer endpoints | all | M | M | Login/forgot throttled; no public API yet | partial | No general rate limit on other routes |
| 12 | Malicious upload | Fake image / script as logo | logo upload | M | L | Magic-byte check, size limit, stored in DB not on disk | tests | No malware scan |
| 13 | Credential theft (DB copy) | Attacker gets the database | devices, 2FA | H | L | AES-256-GCM for device credentials and 2FA secrets, key in env, not in DB | secure tests | Key derives from DATABASE_URL unless DATA_KEY is set |
| 14 | Payment fraud | Fake payment record | payments | H | L | Manual approval by super admin, no online gateway | manual | Gateways not integrated |
| 15 | Webhook forgery | Fake payment callback | none | H | n/a | No webhooks exist | n/a | Must sign/verify when gateways are added |
| 16 | Router takeover / unauthorized MikroTik commands | Run commands on client routers | devices | H | n/a | Real RouterOS API not implemented | n/a | Command allowlist + preview + audit needed when built |
| 17 | Backup theft | Backup file leaked | autobackup, backup.js | H | L | Automatic backups are AES-256-GCM with a key not stored in the DB; downloads stay encrypted | backup2fa.test.js | Plain `backup.js export` is still unencrypted; DATA_KEY loss or leak breaks the protection |
| 18 | Database compromise | Neon credentials leaked | DB | H | L | Secrets only in env, TLS to Neon | review | Neon account security is the user's |
| 19 | Insider threat | Employee exports data | employees | M | M | Role permissions, audit log | tests | Audit log is not tamper-proof (same DB) |
| 20 | Supply chain | Malicious npm package | build | M | L | Few dependencies, lockfile | npm audit run manually | No automated scanner |
| 21 | DoS | Flood the free instance | hosting | M | H | Cloudflare/Render in front, body size limits | none | Free tier can be exhausted; no WAF rules of our own |
| 22 | Host header spoofing | Fake Host to reach another tenant | portal | M | M | Host allowlist, tenant domain verification | portal.test.js | DNS verification untested against real DNS |
| 23 | AI-assisted attacks / prompt injection / AI tool abuse | Future AI features | none | n/a | n/a | No AI feature exists in the app | n/a | Rules in SECURITY_ARCHITECTURE.md apply when added |
