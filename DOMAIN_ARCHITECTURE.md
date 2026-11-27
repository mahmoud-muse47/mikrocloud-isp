# Domain architecture

Status legend: DONE and tested, CONFIG-READY (code done, needs a purchased domain to go live), NOT DONE.

## Portals
| Portal | Future host | Env var | Allowed routes |
|---|---|---|---|
| Super Admin | admin.COMPANYDOMAIN | ADMIN_DOMAIN | /admin*, /login (POST), /logout, /lang, /health |
| Client | portal.COMPANYDOMAIN | CLIENT_DOMAIN | everything except /admin* (404) |
| Tenant domain | any verified client domain | stored in tenant_domains | same as Client, only that tenant's users |

While ADMIN_DOMAIN and CLIENT_DOMAIN are empty (today, on Render) the app runs path-based on one host: /admin/login for the platform owner, /login for clients.

## Environment variables (config.js)
APP_NAME, APP_URL, ADMIN_DOMAIN, CLIENT_DOMAIN, ALLOWED_HOSTS, SESSION_DOMAIN, FORCE_HTTPS. No domain or brand is hardcoded. The product name can also be changed live in Super Admin > System.
SESSION_DOMAIN is read and shown but not applied: cookies are host-only on purpose so the admin and client portals never share a session. Do not set it unless you want that.

## Host validation (DONE, tested)
Once ADMIN_DOMAIN, CLIENT_DOMAIN or ALLOWED_HOSTS is set, any other Host header gets 421, except /health. A hostname is accepted only if it equals a configured domain, is in ALLOWED_HOSTS, or is a verified row in tenant_domains. Look-alike hosts (portal.example.com.evil.com) are rejected (tested).

## Session separation (DONE, tested)
A session created on one portal is treated as logged out on the other. A super admin cannot sign in on the client host, a client user cannot sign in on the admin host, and a user of tenant A cannot sign in on tenant B's domain. Backend routes still check the role; the host split is an extra layer.

## Tenant custom domains
- DONE and tested: table, add (format and reserved-name checks), remove, host-to-tenant resolution, tenant-scoped login, deletion with the client.
- DONE, not tested against real DNS: ownership verification by DNS TXT record `_verify.<domain>` = token (Node DNS lookup). Tested only that a missing record does not verify.
- NOT DONE: automatic SSL certificates. Needs a host that provisions certificates per custom domain (Cloudflare for SaaS, Caddy on-demand TLS, or a platform that supports it). Render supports custom domains, each added by hand.

## HTTPS
FORCE_HTTPS=1 redirects http to https using X-Forwarded-Proto (needs TRUST_PROXY). HSTS and Secure cookies turn on with COOKIE_SECURE=1 (already on in production). Tested locally.

## Moving to a real domain (no code change)
1. Buy the domain (needs the owner's approval, not done).
2. Add admin.X and portal.X as custom domains on the host, point DNS.
3. Set ADMIN_DOMAIN, CLIENT_DOMAIN, ALLOWED_HOSTS (keep the old onrender host during the move), FORCE_HTTPS=1, APP_URL.
4. Test both logins, then remove the old host from ALLOWED_HOSTS.
