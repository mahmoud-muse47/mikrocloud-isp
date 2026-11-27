'use strict';
// Automated encrypted backups. Format: "mcb1." + base64(iv | tag | AES-256-GCM(gzip(JSON))). Key = HKDF(master DATA_KEY, 'backup').
// Stored in the database (table backups) and optionally pushed to a private GitHub repo (BACKUP_GITHUB_REPO + BACKUP_GITHUB_TOKEN).
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const TABLES = require('./tables');
const KEEP = 14, EVERY_MS = 24 * 3600e3;

// same derivation as secure.js: master -> data-at-rest key -> purpose key
const keyFromMaster = (master) => { const k = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(String(master)), Buffer.from('mikrocloud-v2'), Buffer.from('data-at-rest'), 32)); return Buffer.from(crypto.hkdfSync('sha256', k, Buffer.from('mikrocloud-sub'), Buffer.from('backup'), 32)); };
const seal = (plain, key) => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv); const e = Buffer.concat([c.update(zlib.gzipSync(plain)), c.final()]); return 'mcb1.' + Buffer.concat([iv, c.getAuthTag(), e]).toString('base64'); };
const open = (s, key) => { if (!/^mcb1\.[A-Za-z0-9+/=]+$/.test(s)) throw new Error('not a backup file'); const b = Buffer.from(s.slice(5), 'base64'); const d = crypto.createDecipheriv('aes-256-gcm', key, b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28)); return zlib.gunzipSync(Buffer.concat([d.update(b.subarray(28)), d.final()])).toString('utf8'); };
// for the CLI: decrypt with the master DATA_KEY the backup was made with
const decryptBackup = (s, master) => { if (!master) throw new Error('set DATA_KEY'); return open(s, keyFromMaster(master)); };

module.exports = function autobackup({ db, S, audit, fetchImpl }) {
  const q1 = (s, ...a) => db.prepare(s).get(...a), q = (s, ...a) => db.prepare(s).all(...a), run = (s, ...a) => db.prepare(s).run(...a);
  const key = () => S.subkey('backup');
  const sqlNow = () => new Date().toISOString().slice(0, 19).replace('T', ' ');
  const snapshot = () => {
    const out = { format: 'mikrocloud-backup-1', created: new Date().toISOString(), tables: {} }, counts = {};
    for (const t of TABLES) { const rows = q(`SELECT * FROM ${t}`); out.tables[t] = rows; counts[t] = rows.length; }
    return { json: JSON.stringify(out), counts };
  };
  // integrity check of a stored backup: decrypts, parses, and compares per-table row counts and hash with what was recorded
  const verify = (row) => {
    try {
      if (crypto.createHash('sha256').update(row.data).digest('hex') !== row.sha256) return [0, 'hash mismatch'];
      const o = JSON.parse(open(row.data, key())); const want = JSON.parse(row.counts);
      if (o.format !== 'mikrocloud-backup-1') return [0, 'bad format'];
      for (const t of TABLES) if ((o.tables[t] || []).length !== want[t]) return [0, 'row count mismatch in ' + t];
      return [1, 'decrypted, parsed, row counts match'];
    } catch (e) { return [0, 'cannot decrypt: ' + e.message]; }
  };
  const push = async (id, data, created) => {
    const repo = process.env.BACKUP_GITHUB_REPO, token = process.env.BACKUP_GITHUB_TOKEN;
    if (!repo || !token || !/^[\w.-]+\/[\w.-]+$/.test(repo)) return '';
    const name = `backups/mc-${created.replace(/[^0-9]/g, '').slice(0, 12)}-${id}.mcb`;
    try {
      const r = await (fetchImpl || fetch)(`https://api.github.com/repos/${repo}/contents/${name}`, { method: 'PUT', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', 'user-agent': 'mikrocloud-backup', accept: 'application/vnd.github+json' }, body: JSON.stringify({ message: 'backup ' + id, content: Buffer.from(data).toString('base64') }) });
      return r.ok ? 'github:' + name : 'failed:' + r.status;
    } catch (e) { return 'failed:' + e.message.slice(0, 60); }
  };
  const create = async (kind = 'auto') => {
    const { json, counts } = snapshot();
    const data = seal(json, key()), created = sqlNow();
    const sha = crypto.createHash('sha256').update(data).digest('hex');
    run('INSERT INTO backups(created_at,kind,size,sha256,counts,data) VALUES(?,?,?,?,?,?)', created, kind, data.length, sha, JSON.stringify(counts), data);
    const row = q1('SELECT * FROM backups WHERE sha256=? ORDER BY id DESC LIMIT 1', sha);
    const [ok, note] = verify(row);
    const off = await push(row.id, data, created);
    run('UPDATE backups SET verified=?, note=?, offsite=? WHERE id=?', ok, note, off, row.id);
    const old = q("SELECT id FROM backups WHERE kind='auto' ORDER BY id DESC");
    for (const o of old.slice(KEEP)) run('DELETE FROM backups WHERE id=?', o.id);
    if (audit) { try { run('INSERT INTO audit_log(company_id,user_id,action,detail) VALUES(?,?,?,?)', null, null, 'backup_' + kind, `#${row.id} ${ok ? 'verified' : 'NOT verified'} ${off}`); } catch (e) { /* ignore */ } }
    return { id: row.id, verified: !!ok, note, offsite: off };
  };
  const list = () => q('SELECT id,created_at,kind,size,verified,note,offsite FROM backups ORDER BY id DESC');
  const get = (id) => q1('SELECT * FROM backups WHERE id=?', id);
  const latest = () => q1('SELECT id,created_at,verified,offsite FROM backups ORDER BY id DESC LIMIT 1');
  let busy = false;
  const tick = async () => {
    if (busy) return; busy = true;
    try { const l = latest(); if (!l || Date.now() - Date.parse(l.created_at.replace(' ', 'T') + 'Z') > EVERY_MS) await create('auto'); } catch (e) { console.error('backup', e.message); } finally { busy = false; }
  };
  const start = () => { setTimeout(tick, 120e3).unref(); setInterval(tick, 3600e3).unref(); };
  return { create, list, get, latest, verify, start, tick };
};
module.exports.decryptBackup = decryptBackup;
module.exports.keyFromMaster = keyFromMaster;
