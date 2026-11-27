// Encryption at rest for sensitive fields (device passwords, 2FA secrets).
// AES-256-GCM. Master key comes from the environment (DATA_KEY, or derived from DATABASE_URL),
// so a copy of the database alone cannot decrypt anything. Without either, a key stored in the DB is
// used (local development and tests only).
const crypto = require('node:crypto');
module.exports = function secure(q1, run) {
  const env = process.env.DATA_KEY || process.env.DATABASE_URL || '';
  const envKey = env ? Buffer.from(crypto.hkdfSync('sha256', Buffer.from(env), Buffer.from('mikrocloud-v2'), Buffer.from('data-at-rest'), 32)) : null;
  const dbKey = () => {
    let r = q1("SELECT v FROM app_settings WHERE k='cred_key'");
    if (!r) { run("INSERT INTO app_settings(k,v) VALUES('cred_key',?)", crypto.randomBytes(32).toString('hex')); r = q1("SELECT v FROM app_settings WHERE k='cred_key'"); }
    return Buffer.from(r.v, 'hex');
  };
  const seal = (s, key, prefix) => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv); const e = Buffer.concat([c.update(String(s), 'utf8'), c.final()]); return prefix + [iv, c.getAuthTag(), e].map((b) => b.toString('hex')).join('.'); };
  const open = (s, key) => { const [iv, tag, e] = String(s).split('.').map((x) => Buffer.from(x, 'hex')); const d = crypto.createDecipheriv('aes-256-gcm', key, iv); d.setAuthTag(tag); return Buffer.concat([d.update(e), d.final()]).toString('utf8'); };
  const isV2 = (s) => /^v2\.[0-9a-f]+\.[0-9a-f]+\.[0-9a-f]*$/.test(String(s));
  const isLegacy = (s) => /^[0-9a-f]+\.[0-9a-f]+\.[0-9a-f]*$/.test(String(s));
  const enc = (s) => (envKey ? seal(s, envKey, 'v2.') : seal(s, dbKey(), ''));
  const dec = (s) => {
    s = String(s || ''); if (!s) return '';
    if (isV2(s)) return open(s.slice(3), envKey || (() => { throw new Error('no key'); })());
    if (isLegacy(s)) return open(s, dbKey());
    return s; // plaintext from before encryption was added
  };
  // re-encrypt anything not yet protected by the environment key; remove the DB-stored key once nothing needs it
  const migrate = () => {
    for (const [tb, col, pk] of [['devices', 'cred_enc', 'id'], ['users', 'totp_secret', 'id']]) {
      for (const r of q(`SELECT ${pk} k, ${col} v FROM ${tb} WHERE ${col}<>''`)) {
        if (envKey ? isV2(r.v) : (isLegacy(r.v) && !isV2(r.v))) continue;
        try { run(`UPDATE ${tb} SET ${col}=? WHERE ${pk}=?`, enc(dec(r.v)), r.k); } catch (e) { console.error('migrate', tb, e.message); }
      }
    }
    if (envKey && !q(`SELECT 1 FROM devices WHERE cred_enc<>'' AND cred_enc NOT LIKE 'v2.%'`).length) run("DELETE FROM app_settings WHERE k='cred_key'");
  };
  let q = () => []; const setQ = (f) => { q = f; };
  return { enc, dec, migrate, setQ, protectedByEnv: !!envKey };
};
