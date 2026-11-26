'use strict';
// Synchronous facade over a PostgreSQL connection (worker thread + Atomics).
// Gives the app the same db.prepare(sql).get/all/run + db.exec API it used with SQLite,
// while the data lives in standard PostgreSQL (Neon, Supabase, self-hosted, ...).
const { Worker, MessageChannel, receiveMessageOnPort } = require('node:worker_threads');
const path = require('node:path');

function translate(sql) {
  let i = 0;
  let out = sql.replace(/\?/g, () => '$' + (++i));
  out = out.replace(/datetime\('now'\s*,\s*'([^']+)'\)/gi, "to_char(now() at time zone 'utc' + interval '$1','YYYY-MM-DD HH24:MI:SS')");
  out = out.replace(/datetime\('now'\)/gi, "to_char(now() at time zone 'utc','YYYY-MM-DD HH24:MI:SS')");
  out = out.replace(/\bLIKE\b/g, 'ILIKE');
  return out;
}
function translateDDL(sql) {
  let out = sql.replace(/\bINTEGER\b/g, 'BIGINT').replace(/\bREAL\b/g, 'DOUBLE PRECISION');
  out = out.replace(/BIGINT PRIMARY KEY AUTOINCREMENT/g, 'BIGSERIAL PRIMARY KEY');
  out = out.replace(/datetime\('now'\)/gi, "to_char(now() at time zone 'utc','YYYY-MM-DD HH24:MI:SS')");
  out = out.replace(/PRAGMA[^;]*;/gi, '');
  return out;
}

class PgSync {
  constructor(url) {
    this.flag = new Int32Array(new SharedArrayBuffer(4));
    const { port1, port2 } = new MessageChannel();
    this.port = port1;
    this.worker = new Worker(path.join(__dirname, 'pgworker.js'), { workerData: { url, flag: this.flag, port: port2 }, transferList: [port2] });
    this.worker.unref();
    this.call({ init: true });
    this.idTables = new Set(this.call({ sql: "SELECT table_name FROM information_schema.columns WHERE table_schema=current_schema() AND column_name='id'", params: [] }).rows.map((r) => r.table_name));
  }
  call(msg) {
    Atomics.store(this.flag, 0, 0);
    this.port.postMessage(msg);
    while (Atomics.wait(this.flag, 0, 0, 60000) === 'timed-out') { /* keep waiting; worker enforces its own timeouts */ }
    const r = receiveMessageOnPort(this.port);
    if (!r) throw new Error('pg worker gave no reply');
    if (r.message.error) { const e = new Error(r.message.error.message); e.code = r.message.error.code; throw e; }
    return r.message;
  }
  exec(sql) {
    const t = translateDDL(sql);
    const r = this.call({ sql: t, params: [], multi: true });
    for (const m of t.matchAll(/CREATE TABLE IF NOT EXISTS\s+(\w+)\s*\(\s*(\w+)\s/gi)) if (m[2] === 'id') this.idTables.add(m[1]);
    return r;
  }
  hasColumn(table, col) {
    return this.call({ sql: 'SELECT 1 x FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2', params: [table, col] }).rows.length > 0;
  }
  prepare(sql) {
    let t = translate(sql);
    let ret = false;
    const m = /^\s*INSERT\s+INTO\s+(\w+)/i.exec(t);
    if (m && !/\bRETURNING\b/i.test(t) && this.idTables.has(m[1])) { t += ' RETURNING id'; ret = true; }
    const clean = (a) => a.map((v) => (v === undefined ? null : v));
    return {
      get: (...a) => this.call({ sql: t, params: clean(a) }).rows[0],
      all: (...a) => this.call({ sql: t, params: clean(a) }).rows,
      run: (...a) => {
        const r = this.call({ sql: t, params: clean(a) });
        return { changes: r.rowCount, lastInsertRowid: ret && r.rows[0] ? r.rows[0].id : undefined };
      },
    };
  }
  close() { try { this.call({ close: true }); } catch {} }
}
module.exports = { PgSync, translate, translateDDL };
