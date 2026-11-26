# MikroCloud ISP Manager

Node.js + Express app. Data lives in standard PostgreSQL (set `DATABASE_URL`). Without it the app falls back to a local SQLite file (development only).

## Run
    DATABASE_URL=postgres://user:pass@host/db?sslmode=require SUPERADMIN_PASSWORD=... npm start

Tables are created automatically on first start. The first start also creates the super admin (`superadmin`) from `SUPERADMIN_PASSWORD`.

## Backup and move to another server (no data loss)
Any of these work on the same database:
- `pg_dump "$DATABASE_URL" > backup.sql` then `psql "$NEW_URL" < backup.sql`
- Built-in JSON export: `DATABASE_URL=... node backup.js export > backup.json`, then on the new database `DATABASE_URL=... node backup.js import < backup.json`
To move: restore into the new Postgres, change `DATABASE_URL` on the host, restart.

## Notes
- The DB layer uses one connection per app instance (synchronous facade). For very large installs move to a pooled async driver; the SQL is standard and unchanged.
- Free Neon Postgres: 0.5-1 GB storage, compute sleeps when idle (data is kept), first request after idle is slower.
