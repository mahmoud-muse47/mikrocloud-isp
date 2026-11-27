# Backup and recovery

## What exists
- Neon Postgres (free plan) with its own short point-in-time restore window set by Neon. Check the retention shown in the Neon console; I have not verified it.
- `node src/backup.js export > backup.json` and `import < backup.json`. Portable, tested locally (round trip). The file is plain JSON and contains secrets in encrypted form but all other data in the clear: store it encrypted.
- Deleted clients are archived in deleted_companies.

## Not done
Automated schedule, encryption of backup files, off-site and immutable storage, periodic restore tests. A backup counts as valid only after a restore test; none has been scheduled.

## Proposed targets (for the owner to approve)
RPO 24h, RTO 4h, daily export, 30 days retention, encrypted off-site copy (free options: a private GitHub repo with age/gpg-encrypted files, or Cloudflare R2 free tier), monthly restore test into a scratch Neon branch.

## Recovery steps
1. Create a fresh Neon database. 2. Set DATABASE_URL and the same DATA_KEY. 3. Run backup.js import. 4. Start the app. 5. Log in and check one client end to end.
Without the same DATA_KEY the device credentials and 2FA secrets cannot be decrypted. Keep DATA_KEY in a separate safe place.
