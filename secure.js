// Encryption at rest for sensitive fields (device passwords, 2FA secrets).
// AES-256-GCM. Master key comes from the environment (DATA_KEY, or derived from DATABASE_URL),
// so a copy of the database alone cannot decrypt anything. Without either, a key stored in the DB is
// used (local development and tests only).
const crypto = require('node:crypto');
module.exports = function secure(q1, run) {
  const derive = (env) => (env ? Buffer.from(crypto.hkdfSync('sha256', Buffer.from(env), Buffer.from('mikrocloud-v2'), Buffer.from('data-at-rest'), 32)) : null);
  const envKey = derive(process.env.DATA_KEY || process.env.DATABASE_URL || '');
  // key rotation: older keys (previous DATA_KEY, or the DATABASE_URL-derived key used before DATA_KEY was set) can still decrypt,
  // and migrate() re-encrypts everything with the current key
  const oldKeys = [process.env.DATA_KEY_OLD, process.env.DATA_KEY ? process.env.DATABASE_URL : ''].filter(Boolean).map(derive);
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
    if (isV2(s)) {
      if (!envKey) throw new Error('no key');
      for (const k of [envKey, ...oldKeys]) { try { return open(s.slice(3), k); } catch (e) { /* try next key */ } }
      throw new Error('cannot decrypt');
    }
    if (isLegacy(s)) return open(s, dbKey());
    return s; // plaintext from before encryption was added
  };
  // re-encrypt anything not yet protected by the environment key; remove the DB-stored key once nothing needs it
  const migrate = () => {
    for (const [tb, col, pk] of [['devices', 'cred_enc', 'id'], ['users', 'totp_secret', 'id']]) {
      for (const r of q(`SELECT ${pk} k, ${col} v FROM ${tb} WHERE ${col}<>''`)) {
        if (envKey ? (isV2(r.v) && (() => { try { open(r.v.slice(3), envKey); return true; } catch (e) { return false; } })()) : (isLegacy(r.v) && !isV2(r.v))) continue;
        try { run(`UPDATE ${tb} SET ${col}=? WHERE ${pk}=?`, enc(dec(r.v)), r.k); } catch (e) { console.error('migrate', tb, e.message); }
      }
    }
    if (envKey && !q(`SELECT 1 FROM devices WHERE cred_enc<>'' AND cred_enc NOT LIKE 'v2.%'`).length) run("DELETE FROM app_settings WHERE k='cred_key'");
  };
  // purpose-specific key derived from the master key (backups use their own)
  const subkey = (info) => Buffer.from(crypto.hkdfSync('sha256', envKey || dbKey(), Buffer.from('mikrocloud-sub'), Buffer.from(info), 32));
  let q = () => []; const setQ = (f) => { q = f; };
  return { enc, dec, subkey, migrate, setQ, protectedByEnv: !!envKey };
};
