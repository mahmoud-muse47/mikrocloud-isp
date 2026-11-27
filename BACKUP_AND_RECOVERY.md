# Backup and recovery

## What exists now
- Automatic backup every 24 hours (checked hourly), made inside the app. Format: JSON, gzip, then AES-256-GCM. The key is derived from DATA_KEY (separate purpose key), so the same DATA_KEY that protects device credentials protects backups. A backup file is useless without DATA_KEY.
- The newest 14 automatic backups are kept in the database (table `backups`, deliberately not part of the backup itself). Manual backups ("Back up now") are never pruned.
- Every backup is checked right after creation: hash, decrypt, parse, per-table row counts. Result is shown on Admin > Backups and on the Security page.
- Download from Admin > Backups (stays encrypted). Offline copy is the real off-site protection: download one regularly or enable the GitHub push below.
- Optional off-site copy: set BACKUP_GITHUB_REPO (owner/name of a PRIVATE repo) and BACKUP_GITHUB_TOKEN (fine-grained token, Contents: read/write on that repo only). Each backup file is then also pushed to that repo, encrypted. Tested against a stubbed GitHub API only unless the status on the Backups page says otherwise.
- Neon keeps its own point-in-time history on its side (window depends on the plan; not verified).
- `node src/backup.js export|import` still works for plain JSON portable copies (not encrypted).

## Restore
1. Download the .mcb file (or fetch it from the off-site repo).
2. `DATA_KEY=... node src/backup.js decrypt < mikrocloud-backup-N.mcb > backup.json`
3. Point DATABASE_URL at an EMPTY database (new Neon database), run the app once so tables exist, then `node src/backup.js import < backup.json`.
4. Start the app with the same DATA_KEY. Log in and check a client end to end.

## Restore test status
- Automated test (every release): create backup, decrypt, load into a fresh empty database, compare row counts of every table and spot values, confirm tampered or wrong-key files are rejected. Passes.
- Live: each live backup is decrypted and its counts checked automatically. A full restore of the live Neon database into a second database has NOT been done.

## Limits, plainly
- Backups stored only in the same database do not survive losing that database or the Neon account. Download copies or enable the off-site push.
- Losing DATA_KEY means encrypted backups and device credentials cannot be opened. The vault entry "MikroCloud DATA_KEY (Render env)" is the recovery copy.
- No immutable/ransomware-proof storage (paid or provider feature).
- Targets: RPO 24h, RTO about 1 hour for a restore by an engineer. These are targets, not measured.
