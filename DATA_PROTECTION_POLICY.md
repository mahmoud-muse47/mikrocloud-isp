# Data protection policy (working draft)

- Encrypted in transit: HTTPS (Render/Cloudflare TLS), TLS to Neon. RouterOS transport: not implemented yet; use API-SSL when built.
- Encrypted at rest in the app: device credentials and 2FA secrets (AES-256-GCM). Other customer data (names, phones, invoices) is NOT field-encrypted; it relies on Neon disk encryption (provider feature, not verified by me).
- Keys: DATA_KEY env var (set in Render, never in Git or DB). Rotation: set DATA_KEY_OLD to the previous key, set the new DATA_KEY, redeploy; data is re-encrypted at startup.
- Passwords: scrypt hashes; never logged or returned.
- Retention: deleting a client keeps a full archive copy (deleted_companies). Expired subscriptions never delete data. A configurable retention period and a secure purge workflow are NOT DONE.
- Export: per-client export exists (Admin > client > Export) and full backup.js export.
- Access logging: audit_log and login_history; 90-day pruning of login history.
- Privacy settings and data correction: clients can edit their own data; no dedicated privacy screen.
