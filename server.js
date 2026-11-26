const path = require('node:path');
const crypto = require('node:crypto');
const { open, hashPassword } = require('./db');
const { createApp } = require('./app');

const dbFile = process.env.DATABASE_URL || process.env.DB_FILE || path.join(__dirname, 'data.sqlite');
const db = open(dbFile);
if (!db.prepare("SELECT 1 x FROM users WHERE role='super_admin'").get()) {
  const email = (process.env.SUPERADMIN_EMAIL || 'admin@mikrocloud.local').toLowerCase();
  const pw = process.env.SUPERADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url') + 'aA1';
  db.prepare("INSERT INTO users(name,username,email,password_hash,role) VALUES('Super Admin','superadmin',?,?,'super_admin')").run(email, hashPassword(pw));
  console.log('=== Super admin created ===\n username: superadmin\n email:    ' + email + (process.env.SUPERADMIN_PASSWORD ? '' : '\n password: ' + pw + '   (shown once, change it in Account)'));
}
const port = Number(process.env.PORT || 3000);
createApp(db, { trustProxy: !!process.env.TRUST_PROXY, secureCookies: process.env.COOKIE_SECURE === '1', baseUrl: process.env.BASE_URL })
  .listen(port, () => console.log(`MikroCloud phase 1 on http://localhost:${port}`));
