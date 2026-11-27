# Security audit log

Scope: my own testing of the deployed code (https://mikrocloud-isp.onrender.com) and automated tests. Not an independent penetration test. Not certified.

## Tests run (all passed at last run)
100 tests locally (95 + 5 backup/2FA tests), plus the same 24 security tests against Postgres. Categories: cross-tenant access, SQL injection, XSS, CSRF, session handling, brute force and lockout, privilege escalation, upload spoofing, password reset, encryption round trip and key rotation, host spoofing, portal separation.

## Findings fixed (earlier rounds)
| Finding | Sev | Fix | Retest |
|---|---|---|---|
| Login throttle used proxy IP, not client IP | M | Use Cloudflare real-IP header when behind the proxy | pass |
| Throttle lived in memory | M | Moved to database | pass |
| Non-numeric ids reached queries | L | Param guard | pass |
| Open redirect via back parameter | M | Same-site paths only | pass |
| Logo accepted by extension only | M | Magic-byte check | pass |
| Oversized body gave a stack trace | L | 413 handler | pass |
| Device credentials/2FA secrets key stored next to data | H | Env key, AES-256-GCM, migrated | pass |

## Open findings
| Finding | Sev | Status |
|---|---|---|
| CSP allows inline styles and inline event handlers | L-M | open |
| Backups not encrypted/automated | M | fixed (encrypted, automatic, checked); off-site copy and full live restore test still open |
| Super admin 2FA not enforced | M | fixed when REQUIRE_SUPER_2FA=1 is set |
| Argon2id not used (scrypt instead) | L | open |
| No general rate limit beyond login | M | open |
| DATA_KEY must be set in env or key derives from DATABASE_URL | M | being fixed this release (env var set) |
| Tenant isolation only tested with 2 local clients | M | open |
| Dependency scan and secret scan not automated | L | open |
| DNS verification not tested with a real domain | L | open |

## Unverified
RouterOS command handling, SSRF controls, payment webhooks, AI controls: the features do not exist yet, so nothing was tested.
