'use strict';
// Full logical backup / restore, portable between any servers.
//   DATABASE_URL=postgres://... node backup.js export  > backup.json
//   DATABASE_URL=postgres://... node backup.js import  < backup.json   (target DB must be empty or fresh)
// Plain pg_dump / pg_restore also work on the same database.
const { open } = require('./db');
const TABLES = require('./tables');
const url = process.env.DATABASE_URL;
if (process.argv[2] === 'decrypt') {
  // node backup.js decrypt < file.mcb > backup.json   (needs the same DATA_KEY the backup was made with)
  const { decryptBackup } = require('./autobackup');
  const ch = []; process.stdin.on('data', (c) => ch.push(c)); process.stdin.on('end', () => { try { process.stdout.write(decryptBackup(Buffer.concat(ch).toString('utf8').trim(), process.env.DATA_KEY || process.env.DATABASE_URL || '')); } catch (e) { console.error('Cannot decrypt:', e.message); process.exit(1); } });
} else {
if (!url) { console.error('Set DATABASE_URL'); process.exit(1); }
const db = open(url);
const mode = process.argv[2];
if (mode === 'export') {
  const out = { format: 'mikrocloud-backup-1', created: new Date().toISOString(), tables: {} };
  for (const t of TABLES) out.tables[t] = db.prepare(`SELECT * FROM ${t}`).all();
  process.stdout.write(JSON.stringify(out));
} else if (mode === 'import') {
  const chunks = []; process.stdin.on('data', (c) => chunks.push(c)); process.stdin.on('end', () => {
    const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (data.format !== 'mikrocloud-backup-1') throw new Error('Unknown backup format');
    db.exec('BEGIN');
    try {
      for (const t of [...TABLES].reverse()) db.prepare(`DELETE FROM ${t}`).run();
      for (const t of TABLES) {
        for (const row of data.tables[t] || []) {
          const cols = Object.keys(row);
          db.prepare(`INSERT INTO ${t}(${cols.join(',')}) VALUES(${cols.map(() => '?').join(',')})`).run(...cols.map((c) => row[c]));
        }
        if (db.idTables.has(t)) db.exec(`SELECT setval(pg_get_serial_sequence('${t}','id'), COALESCE((SELECT MAX(id) FROM ${t}),0)+1, false)`);
      }
      db.exec('COMMIT');
      console.error('Restored.');
    } catch (e) { db.exec('ROLLBACK'); console.error('Restore failed, nothing changed:', e.message); process.exit(1); }
    db.close();
  });
} else { console.error('Usage: node backup.js export|import'); process.exit(1); }
if (mode === 'export') db.close();
}
