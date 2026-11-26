'use strict';
const { workerData } = require('node:worker_threads');
const { url, flag, port } = workerData;
let client, kind, inTxn = false;

async function connect() {
  if (url.startsWith('pglite://')) {
    const { PGlite } = require('@electric-sql/pglite');
    const dir = url.slice('pglite://'.length);
    client = new PGlite(dir && dir !== 'memory' ? dir : undefined);
    await client.waitReady;
    kind = 'pglite';
    return;
  }
  const pg = require('pg');
  pg.types.setTypeParser(20, (v) => Number(v));    // bigint
  pg.types.setTypeParser(1700, (v) => parseFloat(v)); // numeric
  const ssl = /sslmode=disable|localhost|127\.0\.0\.1/.test(url) ? false : { rejectUnauthorized: false };
  client = new pg.Client({ connectionString: url, ssl, connectionTimeoutMillis: 30000 });
  client.dead = false;
  client.on('error', () => { client.dead = true; });
  client.on('end', () => { client.dead = true; });
  await client.connect();
  kind = 'pg';
}
let ready = connect();

async function run(msg) {
  await ready;
  if (msg.init) return {};
  if (msg.close) { try { await client.end?.(); await client.close?.(); } catch {} return {}; }
  if (kind === 'pg' && client.dead && !inTxn) { ready = connect(); await ready; }
  const t = msg.sql.trim().toUpperCase();
  try {
    let r;
    if (kind === 'pglite') {
      r = msg.multi ? { rows: [], rowCount: 0, _: await client.exec(msg.sql) } : await client.query(msg.sql, msg.params);
      if (!msg.multi) r = { rows: r.rows, rowCount: r.affectedRows != null && !r.rows.length ? r.affectedRows : r.rows.length };
      else r = { rows: [], rowCount: 0 };
      if (!msg.multi && /^(UPDATE|DELETE|INSERT)/i.test(t) && !/RETURNING/i.test(t)) { /* affectedRows used */ }
    } else {
      r = await client.query(msg.multi ? msg.sql : { text: msg.sql, values: msg.params });
      if (Array.isArray(r)) r = r[r.length - 1];
      r = { rows: r.rows || [], rowCount: r.rowCount == null ? 0 : r.rowCount };
    }
    if (t === 'BEGIN') inTxn = true;
    if (t === 'COMMIT' || t === 'ROLLBACK') inTxn = false;
    return r;
  } catch (e) {
    if (t.startsWith('COMMIT') || t.startsWith('ROLLBACK')) inTxn = false;
    return { error: { message: e.message, code: e.code } };
  }
}
let chain = Promise.resolve();
port.on('message', (msg) => {
  chain = chain.then(async () => {
    let res;
    try { res = await run(msg); } catch (e) { res = { error: { message: String(e.message || e) } }; }
    port.postMessage(res);
    Atomics.store(flag, 0, 1);
    Atomics.notify(flag, 0);
  });
});
