const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');

function open(file) {
  let target = file;
  if (process.env.MC_TEST_PG && !/^postgres/.test(String(file))) target = 'pglite://memory';
  const isPg = /^(postgres(ql)?|pglite):\/\//.test(String(target));
  let db;
  if (isPg) { const { PgSync } = require('./pgsync'); db = new PgSync(target); db.isPg = true; db.hasCol = (t, c) => db.hasColumn(t, c); }
  else { db = new DatabaseSync(file); db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;'); db.hasCol = (t, c) => !!db.prepare(`SELECT 1 x FROM pragma_table_info('${t}') WHERE name=?`).get(c); }
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
CREATE TABLE IF NOT EXISTS reset_requests(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS tenant_domains(
  id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE, domain TEXT NOT NULL UNIQUE, token TEXT NOT NULL, verified INTEGER NOT NULL DEFAULT 0, verified_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
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

CREATE TABLE IF NOT EXISTS plans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT NOT NULL UNIQUE,
  name_en TEXT NOT NULL, name_ar TEXT NOT NULL, desc_en TEXT DEFAULT '', desc_ar TEXT DEFAULT '', icon TEXT DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1, archived INTEGER NOT NULL DEFAULT 0, sort_order INTEGER NOT NULL DEFAULT 0, recommended INTEGER NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'EGP',
  price_monthly REAL NOT NULL DEFAULT 0, price_quarterly REAL NOT NULL DEFAULT 0, price_semiannual REAL NOT NULL DEFAULT 0, price_annual REAL NOT NULL DEFAULT 0,
  price_custom REAL NOT NULL DEFAULT 0, custom_days INTEGER NOT NULL DEFAULT 0, promo_price REAL NOT NULL DEFAULT 0, discount_pct REAL NOT NULL DEFAULT 0,
  trial_eligible INTEGER NOT NULL DEFAULT 0, trial_days INTEGER NOT NULL DEFAULT 0, setup_fee REAL NOT NULL DEFAULT 0,
  max_admins INTEGER NOT NULL DEFAULT 1, max_employees INTEGER NOT NULL DEFAULT 3, max_subscribers INTEGER NOT NULL DEFAULT 500,
  max_hotspot INTEGER NOT NULL DEFAULT -1, max_pppoe INTEGER NOT NULL DEFAULT -1, max_routers INTEGER NOT NULL DEFAULT 2, max_aps INTEGER NOT NULL DEFAULT 5,
  max_devices INTEGER NOT NULL DEFAULT 10, max_vouchers_batch INTEGER NOT NULL DEFAULT 100, max_vouchers_month INTEGER NOT NULL DEFAULT 1000,
  max_storage_mb INTEGER NOT NULL DEFAULT 500, max_api_ops INTEGER NOT NULL DEFAULT -1,
  modules TEXT NOT NULL DEFAULT 'customers,network');
CREATE TABLE IF NOT EXISTS invoices(
  id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, plan_code TEXT NOT NULL, plan_name_en TEXT DEFAULT '', plan_name_ar TEXT DEFAULT '', period TEXT DEFAULT '',
  amount REAL NOT NULL DEFAULT 0, credit REAL NOT NULL DEFAULT 0, currency TEXT NOT NULL DEFAULT 'EGP', status TEXT NOT NULL DEFAULT 'unpaid',
  note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')), paid_at TEXT);
CREATE TABLE IF NOT EXISTS plan_requests(
  id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  plan_id INTEGER NOT NULL, period TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', requested_by INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')), decided_at TEXT);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
  name TEXT NOT NULL, category TEXT NOT NULL, manufacturer TEXT DEFAULT '', model TEXT DEFAULT '', mac TEXT DEFAULT '', ip TEXT DEFAULT '',
  mgmt_ip TEXT DEFAULT '', serial TEXT DEFAULT '', firmware TEXT DEFAULT '', location TEXT DEFAULT '', building TEXT DEFAULT '', floor TEXT DEFAULT '',
  area TEXT DEFAULT '', parent_id INTEGER, grp TEXT DEFAULT '', protocol TEXT DEFAULT 'manual', notes TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'unknown', last_check TEXT, last_ok TEXT, last_fail TEXT, fails INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE INDEX IF NOT EXISTS idx_devices_company ON devices(company_id);
`);

  for (const [col, def] of [['billing_period', "TEXT DEFAULT 'monthly'"], ['price_paid', 'REAL DEFAULT 0'], ['currency', "TEXT DEFAULT 'EGP'"], ['sub_start', 'TEXT'], ['limit_overrides', "TEXT DEFAULT '{}'"], ['logo', "TEXT DEFAULT ''"], ['legal_name', "TEXT DEFAULT ''"], ['phone2', "TEXT DEFAULT ''"], ['website', "TEXT DEFAULT ''"], ['tax_no', "TEXT DEFAULT ''"], ['description', "TEXT DEFAULT ''"], ['stamp', "TEXT DEFAULT ''"], ['brand_color', "TEXT DEFAULT '#2563eb'"], ['brand_color2', "TEXT DEFAULT '#0f172a'"], ['invoice_footer', "TEXT DEFAULT ''"], ['support_info', "TEXT DEFAULT ''"], ['logo_h', 'INTEGER DEFAULT 48'], ['suspended_until', 'TEXT']]) {
    if (!db.hasCol('companies', col)) db.exec(`ALTER TABLE companies ADD COLUMN ${col} ${def}`);
  }
  if (!db.hasCol('users', 'totp_on')) { db.exec('ALTER TABLE users ADD COLUMN totp_on INTEGER NOT NULL DEFAULT 0'); db.exec("ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''"); db.exec("ALTER TABLE users ADD COLUMN totp_recovery TEXT NOT NULL DEFAULT ''"); }
  if (!db.hasCol('customers', 'package_id')) db.exec('ALTER TABLE customers ADD COLUMN package_id INTEGER');
  for (const [col, def] of [['hb_token', "TEXT DEFAULT ''"], ['hb_interval', 'INTEGER DEFAULT 5'], ['cred_user', "TEXT DEFAULT ''"], ['cred_enc', "TEXT DEFAULT ''"], ['link_verified', 'INTEGER DEFAULT 0'], ['icon', "TEXT DEFAULT ''"]]) {
    if (!db.hasCol('devices', col)) db.exec(`ALTER TABLE devices ADD COLUMN ${col} ${def}`);
  }
  db.exec(`CREATE TABLE IF NOT EXISTS device_alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, device_id INTEGER, severity TEXT NOT NULL, kind TEXT NOT NULL, msg TEXT DEFAULT '', ack INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS device_groups(id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, name TEXT NOT NULL, UNIQUE(company_id,name));
    CREATE TABLE IF NOT EXISTS payment_methods(id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, name_en TEXT DEFAULT '', name_ar TEXT DEFAULT '', desc_en TEXT DEFAULT '', desc_ar TEXT DEFAULT '', instr_en TEXT DEFAULT '', instr_ar TEXT DEFAULT '', account_info TEXT DEFAULT '', currency TEXT NOT NULL DEFAULT 'EGP', min_amount REAL NOT NULL DEFAULT 0, max_amount REAL NOT NULL DEFAULT 0, fee_pct REAL NOT NULL DEFAULT 0, fee_fixed REAL NOT NULL DEFAULT 0, require_ref INTEGER NOT NULL DEFAULT 1, require_proof INTEGER NOT NULL DEFAULT 0, sort_order INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 0, logo TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY AUTOINCREMENT, invoice_id INTEGER NOT NULL REFERENCES invoices(id), company_id INTEGER NOT NULL, method_id INTEGER, method_name TEXT DEFAULT '', amount REAL NOT NULL, fee REAL NOT NULL DEFAULT 0, currency TEXT NOT NULL DEFAULT 'EGP', reference TEXT DEFAULT '', proof TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')), decided_at TEXT, decided_by INTEGER);
    CREATE TABLE IF NOT EXISTS packages(id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE, name TEXT NOT NULL, service_type TEXT NOT NULL DEFAULT 'pppoe', price REAL NOT NULL DEFAULT 0, description TEXT DEFAULT '', rate_down REAL NOT NULL DEFAULT 0, rate_up REAL NOT NULL DEFAULT 0, quota_mb REAL NOT NULL DEFAULT 0, validity_days INTEGER NOT NULL DEFAULT 30, session_minutes INTEGER NOT NULL DEFAULT 0, profile_name TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS cust_invoices(id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE, customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE, package_id INTEGER, package_name TEXT DEFAULT '', amount REAL NOT NULL, discount REAL NOT NULL DEFAULT 0, currency TEXT NOT NULL DEFAULT 'EGP', period_start TEXT, period_end TEXT, status TEXT NOT NULL DEFAULT 'unpaid', paid_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS cust_payments(id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE, customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE, invoice_id INTEGER NOT NULL REFERENCES cust_invoices(id) ON DELETE CASCADE, amount REAL NOT NULL, method TEXT NOT NULL DEFAULT 'cash', note TEXT DEFAULT '', user_id INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE, title TEXT NOT NULL, amount REAL NOT NULL, category TEXT DEFAULT '', spent_on TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS voucher_templates(id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE, name TEXT NOT NULL, is_default INTEGER NOT NULL DEFAULT 0, config TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL DEFAULT (datetime('now')));
    CREATE TABLE IF NOT EXISTS voucher_batches(id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE, number INTEGER NOT NULL, package_id INTEGER, package_name TEXT DEFAULT '', price REAL NOT NULL DEFAULT 0, validity_days INTEGER NOT NULL DEFAULT 30, quota_mb REAL NOT NULL DEFAULT 0, rate_down REAL NOT NULL DEFAULT 0, rate_up REAL NOT NULL DEFAULT 0, profile_name TEXT DEFAULT '', count INTEGER NOT NULL, created_by TEXT DEFAULT '', settings TEXT DEFAULT '{}', expires_on TEXT DEFAULT '', note TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'active', print_count INTEGER NOT NULL DEFAULT 0, printed_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(company_id, number));
    CREATE TABLE IF NOT EXISTS vouchers(id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE, batch_id INTEGER NOT NULL REFERENCES voucher_batches(id) ON DELETE CASCADE, username TEXT NOT NULL, password TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'unused', used_at TEXT, sold_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(company_id, username));
    CREATE INDEX IF NOT EXISTS idx_vouchers_batch ON vouchers(batch_id);
    CREATE TABLE IF NOT EXISTS deleted_companies(id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER, name TEXT NOT NULL, deleted_at TEXT NOT NULL DEFAULT (datetime('now')), deleted_by TEXT DEFAULT '', snapshot TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS app_settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);`);
  if (!db.prepare('SELECT 1 x FROM plans LIMIT 1').get()) {
    const ins = db.prepare(`INSERT INTO plans(code,name_en,name_ar,desc_en,desc_ar,sort_order,recommended,trial_eligible,trial_days,price_monthly,price_quarterly,price_semiannual,price_annual,
      max_admins,max_employees,max_subscribers,max_routers,max_aps,max_devices,modules) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    ins.run('trial', 'Trial', 'تجريبي', 'Free trial to test the platform', 'فترة تجريبية مجانية لتجربة المنصة', 1, 0, 1, 14, 0, 0, 0, 0, 1, 1, 50, 1, 2, 4, 'customers,network');
    ins.run('basic', 'Basic', 'أساسي', 'For small networks', 'للشبكات الصغيرة', 2, 0, 0, 0, 300, 850, 1600, 3000, 1, 3, 500, 2, 5, 10, 'customers,network');
    ins.run('pro', 'Professional', 'احترافي', 'For growing ISPs', 'لشركات الإنترنت المتنامية', 3, 1, 0, 0, 700, 2000, 3800, 7000, 3, 10, 2500, 10, 30, 60, 'customers,network,vouchers,reports');
    ins.run('enterprise', 'Enterprise', 'مؤسسات', 'Custom limits for large operators', 'حدود مخصصة للمشغلين الكبار', 4, 0, 0, 0, 2000, 5700, 10800, 20000, 10, 50, -1, -1, -1, -1, 'customers,network,vouchers,reports,api');
  }
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
