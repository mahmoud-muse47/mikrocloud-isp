# Production deployment checklist

Current: Render free web service + Neon free Postgres + UptimeRobot ping. Limits: free instance sleeps without the ping, no private networking, no WAF of our own, single instance, no staging environment.

1. Domain and DNS: buy a domain (needs approval). Put it behind Cloudflare (free plan gives TLS, basic DDoS and WAF managed rules). CNAME admin and portal to the Render hostname.
2. Render: add both custom domains (Render issues certificates). Env: ADMIN_DOMAIN, CLIENT_DOMAIN, ALLOWED_HOSTS, APP_URL, FORCE_HTTPS=1, COOKIE_SECURE=1, TRUST_PROXY=1, DATA_KEY (random 32+ bytes), DATABASE_URL. Remove SUPERADMIN_PASSWORD after first start.
3. Cloudflare: rate limit /login and /admin/login, restrict /admin by country or Access if wanted, always-HTTPS, TLS 1.2 minimum.
4. Database: Neon TLS only, separate roles per environment, no public SQL access from untrusted IPs where the plan allows it.
5. Environments: create a second Render service + Neon branch for staging before real customers.
6. Secrets: only in Render env. Never in Git. Rotate DATA_KEY with DATA_KEY_OLD.
7. Monitoring: Admin > Security page, Render logs, UptimeRobot. No alert delivery (no email/SMS) is configured.
8. Updates: `npm audit` and dependency updates before each release; tests must pass.
9. Destructive migrations and infrastructure changes need explicit owner approval.
10. Queue workers / scheduled jobs: the app runs its own in-process timers (auto-reactivation). No separate workers.
