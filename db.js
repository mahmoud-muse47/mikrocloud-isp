const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');

function open(file) {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
  db.exec(`
CREATE TABLE IF NOT EXISTS companies(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, network_name TEXT DEFAULT '', owner_name TEXT DEFAULT '',
  email TEXT NOT NULL, phone TEXT DEFAULT '', whatsapp TEXT DEFAULT '',
  country TEXT DEFAULT 'EG', city TEXT DEFAULT '', address TEXT DEFAULT '',
  plan TEXT NOT NULL DEFAULT 'trial', status TEXT NOT NULL DEFAULT 'trial',
  trial_ends TEXT, subscription_ends TEXT, notes TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
  name TEXT NOT NULL, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE,
  phone TEXT DEFAULT '', password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('super_admin','company_admin','employee')),
  emp_role TEXT DEFAULT '', permissions TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active',
  failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0,
  last_login_at TEXT, last_login_ip TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf TEXT NOT NULL, ip TEXT, ua TEXT,
  created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS login_history(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, identifier TEXT,
  success INTEGER NOT NULL, reason TEXT DEFAULT '', ip TEXT, ts TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS reset_tokens(
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_by INTEGER);
CREATE TABLE IF NOT EXISTS customers(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  code TEXT NOT NULL, full_name TEXT NOT NULL, phone TEXT DEFAULT '', whatsapp TEXT DEFAULT '',
  email TEXT DEFAULT '', address TEXT DEFAULT '', location TEXT DEFAULT '',
  account_type TEXT DEFAULT 'individual', service_type TEXT DEFAULT 'pppoe',
  package TEXT DEFAULT '', username TEXT DEFAULT '', sub_start TEXT, sub_end TEXT,
  payment_status TEXT DEFAULT 'unpaid', status TEXT DEFAULT 'active', notes TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(company_id, code));
CREATE INDEX IF NOT EXISTS idx_customers_company ON customers(company_id, status);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, user_id INTEGER,
  action TEXT NOT NULL, detail TEXT DEFAULT '', ip TEXT, ts TEXT NOT NULL DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS idx_audit_company ON audit_log(company_id, id);
`);
  return db;
}

function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 64);
  return `scrypt$${salt.toString('hex')}$${h.toString('hex')}`;
}
function verifyPassword(pw, stored) {
  const [alg, s, h] = String(stored).split('$');
  if (alg !== 'scrypt') return false;
  const calc = crypto.scryptSync(pw, Buffer.from(s, 'hex'), 64);
  const real = Buffer.from(h, 'hex');
  return calc.length === real.length && crypto.timingSafeEqual(calc, real);
}
function passwordProblem(pw) {
  if (typeof pw !== 'string' || pw.length < 8) return 'pw_short';
  if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw)) return 'pw_weak';
  return null;
}
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

module.exports = { open, hashPassword, verifyPassword, passwordProblem, sha };
