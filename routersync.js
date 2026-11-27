// Router-initiated sync: PPPoE / Hotspot / User Manager / DHCP lists pushed by the router, and an
// allowlisted command queue the router pulls. The platform never connects to the router.
const crypto = require('node:crypto');
const { esc, page, csrfField } = require('./views');

const NAME = /^[A-Za-z0-9._@-]{1,64}$/;
const MACRE = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
// kind -> [label, RouterOS menu, id-property, [[column, routeros property]...]]  (comment is always last)
const KINDS = {
  ppp_secret: ['PPPoE users', '/ppp secret', [['name', 'name'], ['profile', 'profile'], ['service', 'service'], ['disabled', 'disabled'], ['address', 'remote-address'], ['comment', 'comment']]],
  ppp_active: ['PPPoE sessions', '/ppp active', [['name', 'name'], ['address', 'address'], ['mac', 'caller-id'], ['uptime', 'uptime'], ['service', 'service']]],
  hs_user: ['Hotspot users', '/ip hotspot user', [['name', 'name'], ['profile', 'profile'], ['disabled', 'disabled'], ['uptime', 'uptime'], ['comment', 'comment']]],
  hs_active: ['Hotspot sessions', '/ip hotspot active', [['name', 'user'], ['address', 'address'], ['mac', 'mac-address'], ['uptime', 'uptime']]],
  um_user: ['User Manager users', '/user-manager user', [['name', 'name'], ['disabled', 'disabled'], ['comment', 'comment']]],
  um_session: ['User Manager sessions', '/user-manager session', [['name', 'user'], ['address', 'user-ip'], ['mac', 'calling-station-id'], ['service', 'active']]],
  dhcp: ['DHCP leases', '/ip dhcp-server lease', [['address', 'address'], ['mac', 'mac-address'], ['name', 'host-name'], ['service', 'status'], ['comment', 'comment']]],
};
const ACTIONS = { ppp_disable: 'ppp_secret', ppp_enable: 'ppp_secret', ppp_kick: 'ppp_active', ppp_profile: 'ppp_secret', hs_disable: 'hs_user', hs_enable: 'hs_user', hs_kick: 'hs_active' };
const ACTION_LABEL = { ppp_disable: 'Disable PPPoE user', ppp_enable: 'Enable PPPoE user', ppp_kick: 'Disconnect PPPoE session', ppp_profile: 'Change PPPoE profile', hs_disable: 'Disable hotspot user', hs_enable: 'Enable hotspot user', hs_kick: 'Disconnect hotspot session' };
const clean = (v, m) => String(v ?? '').replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, m);
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---------- RouterOS script generator (router pushes, router pulls) ----------
function loopFor(kind, base, tok) {
  const [, menu, props] = KINDS[kind];
  const gets = props.map(([, p], i) => `    :local v${i} ""; :do {:set v${i} [${menu} get $i ${p}]} on-error={}`).join('\n');
  const row = props.map((_, i) => `$v${i}`).join(' . "|" . ');
  const send = (fin) => `/tool fetch url="${base}/api/router/sync" http-method=post http-header-field="Content-Type: text/plain" http-data=("token=${tok}\\nmac=" . $mac . "\\nname=" . $idn . "\\nkind=${kind}\\nbatch=" . $batch . "\\nfinal=${fin}\\n" . $rows) keep-result=no`;
  return `  :set rows ""; :set cnt 0; :set batch [:rndnum from=1 to=999999999]
  :do {
  :foreach i in=[${menu} find] do={
${gets}
    :set rows ($rows . "r=" . ${row} . "\\n"); :set cnt ($cnt + 1)
    :if ($cnt >= 20) do={ :do {${send(0)}} on-error={}; :set rows ""; :set cnt 0 }
  }
  } on-error={}
  :do {${send(1)}} on-error={}`;
}
function syncScript(base, tok) {
  const loops = Object.keys(KINDS).map((k) => `  # ${KINDS[k][0]}\n${loopFor(k, base, tok)}`).join('\n');
  return `{
  :local rows ""; :local cnt 0; :local batch 0
  :local idn [/system identity get name]
  :local mac ""; :do {:set mac [/interface ethernet get [:pick [/interface ethernet find] 0] mac-address]} on-error={}
${loops}
}`;
}
function cmdScript(base, tok) {
  return `{
  :local idn [/system identity get name]
  :local mac ""; :do {:set mac [/interface ethernet get [:pick [/interface ethernet find] 0] mac-address]} on-error={}
  :local res ""
  :do {:set res [/tool fetch url="${base}/api/router/cmds" http-method=post http-header-field="Content-Type: text/plain" http-data=("token=${tok}\\nmac=" . $mac . "\\nname=" . $idn) output=user as-value]} on-error={}
  :local data ""; :do {:set data ($res->"data")} on-error={}
  :local acks ""
  :while ([:len $data] > 0) do={
    :local p [:find $data ";"]
    :if ([:typeof $p] = "nil") do={ :set p [:len $data] }
    :local line [:pick $data 0 $p]
    :set data ($p >= [:len $data] ? "" : [:pick $data ($p + 1) [:len $data]])
    :local a [:find $line "|"]
    :local id [:pick $line 0 $a]; :local rest [:pick $line ($a + 1) [:len $line]]
    :local b [:find $rest "|"]; :local act [:pick $rest 0 $b]; :set rest [:pick $rest ($b + 1) [:len $rest]]
    :local c [:find $rest "|"]; :local n [:pick $rest 0 $c]; :local arg [:pick $rest ($c + 1) [:len $rest]]
    :local ok 1
    :do {
      :if ($act = "ppp_disable") do={ /ppp secret set [find name=$n] disabled=yes; /ppp active remove [find name=$n] }
      :if ($act = "ppp_enable") do={ /ppp secret set [find name=$n] disabled=no }
      :if ($act = "ppp_kick") do={ /ppp active remove [find name=$n] }
      :if ($act = "ppp_profile") do={ /ppp secret set [find name=$n] profile=$arg; /ppp active remove [find name=$n] }
      :if ($act = "hs_disable") do={ /ip hotspot user set [find name=$n] disabled=yes; /ip hotspot active remove [find user=$n] }
      :if ($act = "hs_enable") do={ /ip hotspot user set [find name=$n] disabled=no }
      :if ($act = "hs_kick") do={ /ip hotspot active remove [find user=$n] }
    } on-error={ :set ok 0 }
    :set acks ($acks . "a=" . $id . "|" . $ok . "\\n")
  }
  :if ([:len $acks] > 0) do={ :do {/tool fetch url="${base}/api/router/ack" http-method=post http-header-field="Content-Type: text/plain" http-data=("token=${tok}\\nmac=" . $mac . "\\nname=" . $idn . "\\n" . $acks) keep-result=no} on-error={} }
}`;
}
// full paste block: identity heartbeat (existing) + sync + command pull
function fullScript(base, tok) {
  const hb = `{
  :local bd ""; :local sn ""; :local mac ""; :local nb ""
  :foreach i in=[/ip neighbor find] do={
    :local m ""; :local n ""; :local p ""; :local a ""
    :do {:set m [/ip neighbor get $i mac-address]} on-error={}
    :do {:set n [/ip neighbor get $i identity]} on-error={}
    :do {:set p [/ip neighbor get $i platform]} on-error={}
    :do {:set a [/ip neighbor get $i address]} on-error={}
    :set nb ($nb . $m . "|" . $n . "|" . $p . "|" . $a . ";")
  }
  :do {:set bd [/system resource get board-name]} on-error={}
  :do {:set sn [/system routerboard get serial-number]} on-error={}
  :do {:set mac [/interface ethernet get [:pick [/interface ethernet find] 0] mac-address]} on-error={}
  :local body ("token=${tok}\\nname=" . [/system identity get name] . "\\nboard=" . $bd . "\\nversion=" . [/system resource get version] . "\\nserial=" . $sn . "\\nmac=" . $mac . "\\nnb=" . $nb)
  :do {/tool fetch url="${base}/api/enroll" http-method=post http-header-field="Content-Type: text/plain" http-data=$body keep-result=no} on-error={:log warning "MikroCloud: send failed"}
}`;
  return `# MikroCloud link - paste the WHOLE block into the MikroTik terminal (RouterOS 7). Needs internet access from the router.
/system script remove [find name=mikrocloud]
/system script remove [find name=mikrocloud-sync]
/system script remove [find name=mikrocloud-cmd]
/system script add name=mikrocloud policy=read,write,test,policy source=${hb}
/system script add name=mikrocloud-sync policy=read,write,test,policy source=${syncScript(base, tok)}
/system script add name=mikrocloud-cmd policy=read,write,test,policy source=${cmdScript(base, tok)}
/system scheduler remove [find name=mikrocloud]
/system scheduler remove [find name=mikrocloud-sync]
/system scheduler remove [find name=mikrocloud-cmd]
/system scheduler add name=mikrocloud interval=5m on-event="/system script run mikrocloud" start-time=startup policy=read,write,test,policy
/system scheduler add name=mikrocloud-sync interval=5m on-event="/system script run mikrocloud-sync" start-time=startup policy=read,write,test,policy
/system scheduler add name=mikrocloud-cmd interval=1m on-event="/system script run mikrocloud-cmd" start-time=startup policy=read,write,test,policy
/system script run mikrocloud
`;
}

function init(h, P, shared) {
  const { app, q, q1, run, audit, ctx, go, needAdmin, nav, deny } = h;
  const hits = new Map();
  const tooMany = (k, max) => { const n = Date.now(), a = (hits.get(k) || []).filter((x) => n - x < 60000); a.push(n); hits.set(k, a); if (hits.size > 5000) hits.clear(); return a.length > max; };
  const parseKV = (body) => { const kv = {}, rs = []; for (const line of String(body || '').split(/\r?\n/).slice(0, 80)) { const k = line.indexOf('='); if (k < 1) continue; const key = line.slice(0, k).trim(), v = line.slice(k + 1); if (key === 'r' || key === 'a') rs.push(v); else if (!(key in kv)) kv[key] = v; } return { kv, rs }; };
  // token -> company, then router -> device (by MAC, else identity name). Never a tenant id from the client.
  function auth(req, res) {
    res.set('Cache-Control', 'no-store');
    if (tooMany('ip:' + req.ip, 120)) { res.status(429).type('text').send('slow down'); return null; }
    const { kv, rs } = parseKV(typeof req.body === 'string' ? req.body : '');
    const tk = String(kv.token || '');
    if (!/^mc_[0-9a-f]{48}$/.test(tk) || (hits.get('bad:' + req.ip) || []).length > 20) { tooMany('bad:' + req.ip, 1e9); res.status(403).type('text').send('invalid key'); return null; }
    const co = q1('SELECT * FROM companies WHERE enroll_hash=?', sha(tk));
    if (!co) { tooMany('bad:' + req.ip, 20); res.status(403).type('text').send('invalid key'); return null; }
    if (['suspended', 'expired', 'cancelled'].includes(co.status) || !P.hasModule(co, 'network')) { res.status(403).type('text').send('not allowed'); return null; }
    if (tooMany('co:' + co.id, 90)) { res.status(429).type('text').send('slow down'); return null; }
    const mac = clean(kv.mac, 17).toUpperCase(), name = clean(kv.name, 80);
    let d = MACRE.test(mac) ? q1('SELECT * FROM devices WHERE company_id=? AND mac=?', co.id, mac) : null;
    if (!d && name) d = q1("SELECT * FROM devices WHERE company_id=? AND name=? AND manufacturer='MikroTik' ORDER BY id LIMIT 1", co.id, name);
    if (!d) { res.status(404).type('text').send('router not enrolled yet'); return null; }
    return { co, d, kv, rs };
  }
  // ---- router pushes a list (chunked). final=1 on the last chunk removes rows not seen in this batch.
  app.post('/api/router/sync', (req, res) => {
    const a = auth(req, res); if (!a) return;
    const kind = String(a.kv.kind || ''), spec = KINDS[kind];
    if (!spec) return res.status(400).type('text').send('bad kind');
    const batch = clean(a.kv.batch, 12).replace(/\D/g, '') || '0', cols = spec[2].map((c) => c[0]);
    const cid = a.co.id, did = a.d.id;
    let n = 0;
    for (const raw of a.rs.slice(0, 40)) {
      const f = raw.split('|'); const row = {};
      cols.forEach((c, i) => { row[c] = i === cols.length - 1 ? f.slice(i).join('|') : f[i]; });
      for (const c of Object.keys(row)) row[c] = clean(row[c], c === 'comment' ? 200 : 80);
      if (row.mac && !MACRE.test(row.mac)) row.mac = row.mac.slice(0, 20);
      const key = kind === 'dhcp' ? (row.mac || row.address) : row.name;
      if (!key) continue;
      const cnt = q1('SELECT COUNT(*) AS n FROM router_items WHERE company_id=? AND device_id=? AND kind=?', cid, did, kind).n;
      const ex = q1('SELECT id FROM router_items WHERE company_id=? AND device_id=? AND kind=? AND item_key=?', cid, did, kind, key);
      const vals = [row.name || '', row.profile || '', row.service || '', row.address || '', row.mac || '', row.uptime || '', /^(true|yes)$/i.test(row.disabled || '') ? 1 : 0, row.comment || '', batch];
      if (ex) run("UPDATE router_items SET name=?, profile=?, service=?, address=?, mac=?, uptime=?, disabled=?, comment=?, batch=?, seen_at=datetime('now') WHERE id=?", ...vals, ex.id);
      else if (cnt < 5000) run('INSERT INTO router_items(company_id,device_id,kind,item_key,name,profile,service,address,mac,uptime,disabled,comment,batch) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)', cid, did, kind, key, ...vals);
      n++;
    }
    if (String(a.kv.final) === '1') run('DELETE FROM router_items WHERE company_id=? AND device_id=? AND kind=? AND batch<>?', cid, did, kind, batch);
    run("UPDATE devices SET last_ok=datetime('now'), last_check=datetime('now'), fails=0 WHERE id=?", did);
    res.type('text').send('ok ' + n);
  });
  // ---- router pulls queued commands (allowlisted actions only), one line per command, ';' separated
  app.post('/api/router/cmds', (req, res) => {
    const a = auth(req, res); if (!a) return;
    const rows = q("SELECT * FROM router_cmds WHERE company_id=? AND device_id=? AND status='queued' ORDER BY id LIMIT 10", a.co.id, a.d.id);
    const out = [];
    for (const c of rows) {
      if (!ACTIONS[c.action] || !NAME.test(c.target) || (c.arg && !NAME.test(c.arg))) { run("UPDATE router_cmds SET status='failed', result='rejected', done_at=datetime('now') WHERE id=?", c.id); continue; }
      run("UPDATE router_cmds SET status='sent', sent_at=datetime('now') WHERE id=?", c.id);
      out.push(`${c.id}|${c.action}|${c.target}|${c.arg || ''}`);
    }
    res.type('text').send(out.join(';'));
  });
  app.post('/api/router/ack', (req, res) => {
    const a = auth(req, res); if (!a) return;
    for (const l of a.rs.slice(0, 20)) {
      const [id, ok] = l.split('|'); if (!/^\d{1,9}$/.test(id || '')) continue;
      run("UPDATE router_cmds SET status=?, result=?, done_at=datetime('now') WHERE id=? AND company_id=? AND device_id=? AND status='sent'", ok === '1' ? 'done' : 'failed', ok === '1' ? 'ok' : 'router error', Number(id), a.co.id, a.d.id);
    }
    res.type('text').send('ok');
  });

  // ---------------- UI ----------------
  const gate = (req, res, next) => { const co = q1('SELECT * FROM companies WHERE id=?', req.user.company_id); return P.hasModule(co, 'network') ? next() : deny(req, res, 'module'); };
  const wrap = (req, title, body) => page(ctx(req), title, body, nav(req));
  const TABS = [['ppp_secret', 'PPPoE users'], ['hs_user', 'Hotspot users'], ['um_user', 'User Manager users'], ['dhcp', 'DHCP leases']];
  const routers = (cid) => q("SELECT id,name FROM devices WHERE company_id=? AND category IN ('main_router','secondary_router','core_router','edge_router') ORDER BY id", cid);
  app.get('/app/network/router-users', needAdmin, gate, (req, res) => {
    const t = req.i.t, cid = req.user.company_id, kind = KINDS[req.query.kind] && TABS.some((x) => x[0] === req.query.kind) ? req.query.kind : 'ppp_secret';
    const rs = routers(cid), did = /^\d{1,9}$/.test(String(req.query.device || '')) ? Number(req.query.device) : 0;
    const rows = q(`SELECT i.*, d.name AS router FROM router_items i JOIN devices d ON d.id=i.device_id WHERE i.company_id=? AND i.kind=? ${did ? 'AND i.device_id=?' : ''} ORDER BY i.name LIMIT 1000`, ...(did ? [cid, kind, did] : [cid, kind]));
    const act = { ppp_secret: new Set(q("SELECT device_id||':'||name AS k FROM router_items WHERE company_id=? AND kind='ppp_active'", cid).map((r) => r.k)), hs_user: new Set(q("SELECT device_id||':'||name AS k FROM router_items WHERE company_id=? AND kind='hs_active'", cid).map((r) => r.k)), um_user: new Set(q("SELECT device_id||':'||name AS k FROM router_items WHERE company_id=? AND kind='um_session'", cid).map((r) => r.k)) };
    const subs = Object.fromEntries(q("SELECT id, username, full_name FROM customers WHERE company_id=? AND username<>''", cid).map((r) => [r.username.toLowerCase(), r]));
    const btn = (r, action, label, arg) => `<form method="post" action="/app/network/command" style="display:inline">${csrfField(ctx(req))}<input type="hidden" name="item" value="${r.id}"><input type="hidden" name="action" value="${action}">${arg ? `<input type="hidden" name="arg" value="${esc(arg)}">` : ''}<button class="btn sec" style="padding:2px 8px">${t(label)}</button></form> `;
    const tabs = TABS.map(([k, l]) => `<a class="btn ${k === kind ? '' : 'sec'}" style="${k === kind ? 'color:#fff' : ''}" href="/app/network/router-users?kind=${k}${did ? '&device=' + did : ''}">${t(l)}</a>`).join(' ');
    const rsel = `<form method="get" style="display:inline"><input type="hidden" name="kind" value="${kind}"><select name="device" onchange="this.form.submit()"><option value="">${t('All routers')}</option>${rs.map((r) => `<option value="${r.id}" ${r.id === did ? 'selected' : ''}>${esc(r.name)}</option>`).join('')}</select></form>`;
    const canAct = ['ppp_secret', 'hs_user'].includes(kind);
    const body = `<div class="card">${tabs} ${rsel}<p class="mut">${t('Read from the router every 5 minutes. Passwords are never read or stored. Actions are queued and the router runs them within a minute.')}</p></div>
<div class="card tbl"><table><tr><th>${t('Router')}</th><th>${t('Name')}</th><th>${t('Profile')}</th><th>${t('Address')}</th><th>${t('MAC address')}</th><th>${t('Status')}</th><th>${t('Subscriber')}</th><th>${t('Comment')}</th>${canAct ? `<th>${t('Actions')}</th>` : ''}</tr>
${rows.map((r) => { const on = act[kind] && act[kind].has(`${r.device_id}:${r.name}`), s = subs[(r.name || '').toLowerCase()]; return `<tr><td>${esc(r.router)}</td><td>${esc(r.name)}</td><td>${esc(r.profile)}</td><td>${esc(r.address)}</td><td>${esc(r.mac)}</td><td>${r.disabled ? t('Disabled') : kind === 'dhcp' ? esc(r.service) : on ? '<b style="color:#16a34a">' + t('Online') + '</b>' : t('Offline')}</td><td>${s ? `<a href="/app/customers/${s.id}">${esc(s.full_name)}</a>` : '-'}</td><td>${esc(r.comment)}</td>${canAct ? `<td>${kind === 'ppp_secret' ? (r.disabled ? btn(r, 'ppp_enable', 'Enable') : btn(r, 'ppp_disable', 'Disable')) + (on ? btn(r, 'ppp_kick', 'Disconnect') : '') : (r.disabled ? btn(r, 'hs_enable', 'Enable') : btn(r, 'hs_disable', 'Disable'))}</td>` : ''}</tr>`; }).join('') || `<tr><td colspan="9" class="mut">${t('No data yet. Paste the connection script from Device Discovery into your MikroTik.')}</td></tr>`}</table></div>`;
    res.set('Cache-Control', 'no-store'); res.send(wrap(req, 'Router Users', body));
  });
  app.get('/app/network/sessions', needAdmin, gate, (req, res) => {
    const t = req.i.t, cid = req.user.company_id;
    const rows = q("SELECT i.*, d.name AS router FROM router_items i JOIN devices d ON d.id=i.device_id WHERE i.company_id=? AND i.kind IN ('ppp_active','hs_active','um_session') ORDER BY i.kind, i.name LIMIT 1000", cid);
    const sub = { ppp_active: 'PPPoE', hs_active: 'Hotspot', um_session: 'User Manager' };
    res.set('Cache-Control', 'no-store');
    res.send(wrap(req, 'Live Sessions', `<div class="card" data-autorefresh="1"><h3>${t('Live Sessions')} (${rows.length})</h3></div><div class="card tbl"><table><tr><th>${t('Type')}</th><th>${t('Router')}</th><th>${t('Name')}</th><th>${t('Address')}</th><th>${t('MAC address')}</th><th>${t('Uptime')}</th></tr>${rows.map((r) => `<tr><td>${sub[r.kind]}</td><td>${esc(r.router)}</td><td>${esc(r.name)}</td><td>${esc(r.address)}</td><td>${esc(r.mac)}</td><td>${esc(r.uptime)}</td></tr>`).join('') || `<tr><td colspan="6" class="mut">${t('No active sessions reported')}</td></tr>`}</table></div>`));
  });
  app.post('/app/network/command', needAdmin, gate, (req, res) => {
    const t = req.i.t, cid = req.user.company_id, b = req.body || {}, action = String(b.action || '');
    const it = /^\d{1,9}$/.test(String(b.item || '')) ? q1('SELECT * FROM router_items WHERE id=? AND company_id=?', Number(b.item), cid) : null;
    if (!it || !ACTIONS[action] || ACTIONS[action] !== it.kind && !(action === 'ppp_kick' && it.kind === 'ppp_secret') && !(action === 'hs_kick' && it.kind === 'hs_user')) return go(res, '/app/network/commands', 'err', t('Invalid'));
    const arg = clean(b.arg, 64);
    if (!NAME.test(it.name) || (arg && !NAME.test(arg))) return go(res, '/app/network/commands', 'err', t('Invalid'));
    if (q1("SELECT COUNT(*) AS n FROM router_cmds WHERE company_id=? AND status IN ('queued','sent')", cid).n >= 50) return go(res, '/app/network/commands', 'err', t('Too many pending commands'));
    run('INSERT INTO router_cmds(company_id,device_id,action,target,arg,created_by) VALUES(?,?,?,?,?,?)', cid, it.device_id, action, it.name, arg, req.user.username);
    audit(req, 'router_command', `${action} ${it.name}`);
    go(res, '/app/network/commands', 'ok', t('Command queued'));
  });
  app.get('/app/network/commands', needAdmin, gate, (req, res) => {
    const t = req.i.t, cid = req.user.company_id;
    const rows = q('SELECT c.*, d.name AS router FROM router_cmds c JOIN devices d ON d.id=c.device_id WHERE c.company_id=? ORDER BY c.id DESC LIMIT 100', cid);
    res.set('Cache-Control', 'no-store');
    res.send(wrap(req, 'Router Commands', `<div class="card"><h3>${t('Router Commands')}</h3><p class="mut">${t('Only these actions can ever run on a router, and only on names the router itself reported. The router pulls them every minute.')}</p></div><div class="card tbl"><table><tr><th>#</th><th>${t('Time')}</th><th>${t('Router')}</th><th>${t('Action')}</th><th>${t('Name')}</th><th>${t('Status')}</th><th>${t('By')}</th></tr>${rows.map((r) => `<tr><td>${r.id}</td><td>${esc(r.created_at)}</td><td>${esc(r.router)}</td><td>${t(ACTION_LABEL[r.action] || r.action)}${r.arg ? ' → ' + esc(r.arg) : ''}</td><td>${esc(r.target)}</td><td>${esc(r.status)} ${esc(r.result)}</td><td>${esc(r.created_by)}</td></tr>`).join('') || `<tr><td colspan="7" class="mut">-</td></tr>`}</table></div>`));
  });
}
module.exports = { init, fullScript, KINDS, ACTIONS, NAME };
