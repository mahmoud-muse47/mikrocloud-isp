// Router-initiated sync: PPPoE / Hotspot / User Manager / DHCP lists pushed by the router, and an
// allowlisted command queue the router pulls. The platform never connects to the router.
const crypto = require('node:crypto');
const { esc, page, csrfField } = require('./views');

const NAME = /^[A-Za-z0-9._@-]{1,64}$/;
const RATE = /^\d{1,6}[kM]\/\d{1,6}[kM]$/;
const MACRE = /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/;
// kind -> [label, RouterOS menu, id-property, [[column, routeros property]...]]  (comment is always last)
const KINDS = {
  ppp_secret: ['PPPoE users', '/ppp secret', [['name', 'name'], ['profile', 'profile'], ['service', 'service'], ['disabled', 'disabled'], ['address', 'remote-address'], ['comment', 'comment']]],
  ppp_active: ['PPPoE sessions', '/ppp active', [['name', 'name'], ['address', 'address'], ['mac', 'caller-id'], ['uptime', 'uptime'], ['service', 'service']]],
  hs_user: ['Hotspot users', '/ip hotspot user', [['name', 'name'], ['profile', 'profile'], ['disabled', 'disabled'], ['uptime', 'uptime'], ['comment', 'comment']]],
  hs_active: ['Hotspot sessions', '/ip hotspot active', [['name', 'user'], ['address', 'address'], ['mac', 'mac-address'], ['uptime', 'uptime']]],
  um_user: ['User Manager users', '/user-manager user', [['name', 'name'], ['disabled', 'disabled'], ['comment', 'comment']]],
  um_session: ['User Manager sessions', '/user-manager session', [['name', 'user'], ['address', 'user-ip'], ['mac', 'calling-station-id'], ['service', 'active']]],
  ppp_profile: ['PPP profiles', '/ppp profile', [['name', 'name'], ['service', 'rate-limit'], ['comment', 'comment']]],
  dhcp: ['DHCP leases', '/ip dhcp-server lease', [['address', 'address'], ['mac', 'mac-address'], ['name', 'host-name'], ['service', 'status'], ['comment', 'comment']]],
};
const ACTIONS = { ppp_disable: 'ppp_secret', ppp_enable: 'ppp_secret', ppp_kick: 'ppp_active', ppp_profile: 'ppp_secret', hs_disable: 'hs_user', hs_enable: 'hs_user', hs_kick: 'hs_active', prof_set: 'ppp_profile' };
const ACTION_LABEL = { ppp_disable: 'Disable PPPoE user', ppp_enable: 'Enable PPPoE user', ppp_kick: 'Disconnect PPPoE session', ppp_profile: 'Change PPPoE profile', hs_disable: 'Disable hotspot user', hs_enable: 'Enable hotspot user', hs_kick: 'Disconnect hotspot session', prof_set: 'Create or update speed profile' };
const clean = (v, m) => String(v ?? '').replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, m);
const publicBase = (req) => (process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || 'https://' + req.get('host')).replace(/\/+$/, '').replace(/^http:\/\//, 'https://');
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');

// ---------- RouterOS installer script (served as /r/<key>.rsc). One script + one scheduler, RouterOS v6 and v7. ----------
function fullScript(base, tok) {
  const K = Object.entries(KINDS).map(([k, v]) => `"${k}"="${v[1]} print as-value:${v[2].map((c) => c[1]).join(',')}"`).join(';\n  ');
  const host = base.replace(/^https?:\/\//, '');
  const main = `{
:global mcN
:if ([:typeof $mcN]!="num") do={:set mcN 0}
:set mcN ($mcN+1)
:local H "${base}"
:local T "${tok}"
:local j
:local say do={:put $m; :log info ("MikroCloud: ".$m)}
:local id [/system identity get name]
:local mac ""
:do {:set mac [/interface ethernet get [:pick [/interface ethernet find] 0] mac-address]} on-error={}
:local pre ("token=".$T."\\nmac=".$mac."\\nname=".$id."\\n")
:local S do={:local r "!"; :do {:local x [/tool fetch url=$u http-method=post http-header-field="Content-Type: text/plain" http-data=$d output=user as-value]; :set r ($x->"data")} on-error={}; :return $r}
:if (($mcN % 5)=1) do={
:local bd ""; :local sn ""; :local nb ""
:do {:set bd [/system resource get board-name]} on-error={}
:do {:set sn [/system routerboard get serial-number]} on-error={}
:do {:foreach n in=[/ip neighbor print as-value] do={:set nb ($nb.($n->"mac-address")."|".($n->"identity")."|".($n->"platform")."|".($n->"address").";")}} on-error={}
:local r [$S u=($H."/api/enroll") d=($pre."board=".$bd."\\nversion=".[/system resource get version]."\\nserial=".$sn."\\nnb=".$nb)]
:if ($r="!") do={
$say m="FAILED: could not register with MikroCloud."
:do {:resolve "${host}"} on-error={$say m="- DNS cannot resolve ${host}. Fix: /ip dns set servers=8.8.8.8"}
:do {:if ([/system device-mode get fetch]=false) do={$say m="- device-mode blocks fetch. Fix: /system device-mode update fetch=yes scheduler=yes (confirm on the device)"}} on-error={}
:local up 1
:do {/tool fetch url=($H."/api/router/ping") output=none} on-error={:set up 0; $say m="- cannot reach the site over https. Check internet, firewall and /system clock."}
:if ($up=1) do={$say m="- site reachable but the key was refused: wrong key, client suspended or plan limit. Get a new key from the client page."}
} else={
:if ($mcN=1) do={$say m="LINKED OK: registered. It shows Online on the panel within a minute."}
:local K {
  ${K}
}
:foreach k,v in=$K do={
:local i [:find $v ":"]
:local cmd [:parse [:pick $v 0 $i]]
:local pr [:toarray [:pick $v ($i+1) [:len $v]]]
:local rows ""; :local n 0; :local b [:rndnum from=1 to=999999999]
:do {:foreach e in=[$cmd] do={
:local ln ""; :local sp ""
:foreach p in=$pr do={:set ln ($ln.$sp.($e->$p)); :set sp "|"}
:set rows ($rows."r=".$ln."\\n"); :set n ($n+1)
:if ($n>=15) do={:set j [$S u=($H."/api/router/sync") d=($pre."kind=".$k."\\nbatch=".$b."\\nfinal=0\\n".$rows)]; :set rows ""; :set n 0}
}} on-error={}
:set j [$S u=($H."/api/router/sync") d=($pre."kind=".$k."\\nbatch=".$b."\\nfinal=1\\n".$rows)]
}
}
}
:local r [$S u=($H."/api/router/cmds") d=$pre]
:if ($r!="!" && [:len $r]>0) do={
:local acks ""
:foreach c in=[:toarray $r] do={
:local a [:find $c "|"]
:local cid [:pick $c 0 $a]
:local rest [:pick $c ($a+1) [:len $c]]
:local b [:find $rest "|"]
:local act [:pick $rest 0 $b]
:set rest [:pick $rest ($b+1) [:len $rest]]
:local d [:find $rest "|"]
:local nm [:pick $rest 0 $d]
:local arg [:pick $rest ($d+1) [:len $rest]]
:local ok 1
:do {
:if ($act="ppp_disable") do={/ppp secret set [find name=$nm] disabled=yes; /ppp active remove [find name=$nm]}
:if ($act="ppp_enable") do={/ppp secret set [find name=$nm] disabled=no}
:if ($act="ppp_kick") do={/ppp active remove [find name=$nm]}
:if ($act="ppp_profile") do={/ppp secret set [find name=$nm] profile=$arg; /ppp active remove [find name=$nm]}
:if ($act="hs_disable") do={/ip hotspot user set [find name=$nm] disabled=yes; /ip hotspot active remove [find user=$nm]}
:if ($act="hs_enable") do={/ip hotspot user set [find name=$nm] disabled=no}
:if ($act="prof_set") do={:local f [/ppp profile find name=$nm]; :if ([:len $f]=0) do={/ppp profile add name=$nm rate-limit=$arg comment="mikrocloud"} else={/ppp profile set $f rate-limit=$arg}}
:if ($act="hs_kick") do={/ip hotspot active remove [find user=$nm]}
} on-error={:set ok 0}
:set acks ($acks."a=".$cid."|".$ok."\\n")
}
:set j [$S u=($H."/api/router/ack") d=($pre.$acks)]
}
}`;
  return `:put "MikroCloud: installing..."
:do {:if ([/system device-mode get scheduler]=false) do={:put "STOP: device-mode blocks scheduler/fetch. Run /system device-mode update fetch=yes scheduler=yes, confirm on the device, then paste again."}} on-error={}
:global mcN 0
/system script remove [find name=mikrocloud]
/system script remove [find name=mikrocloud-sync]
/system script remove [find name=mikrocloud-cmd]
/system scheduler remove [find name=mikrocloud]
/system scheduler remove [find name=mikrocloud-sync]
/system scheduler remove [find name=mikrocloud-cmd]
/system script add name=mikrocloud policy=read,write,test,policy source=${main}
/system scheduler add name=mikrocloud interval=1m start-time=startup on-event="/system script run mikrocloud" policy=read,write,test,policy
:put ("MikroCloud: RouterOS ".[/system resource get version].", checking the connection...")
/system script run mikrocloud
`;
}
const installLine = (base, tok) => `/tool fetch url="${base}/r/${tok}.rsc" dst-path=mc.rsc; :delay 2s; /import mc.rsc; /file remove mc.rsc`;
const rtStatus = (lastOk) => {
  if (!lastOk) return { st: 'none', ago: null };
  const m = Math.max(0, (Date.now() - new Date(String(lastOk).replace(' ', 'T') + 'Z').getTime()) / 60000);
  return { st: m <= 3 ? 'online' : m <= 10 ? 'unstable' : 'offline', ago: Math.floor(m) };
};

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
  app.get('/api/router/ping', (req, res) => { res.set('Cache-Control', 'no-store'); res.type('text').send('ok'); });
  // installer: the router downloads this file with its private key in the path; nothing is created or changed here
  app.get('/r/:f', (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (tooMany('ip:' + req.ip, 60)) return res.status(429).type('text').send('slow down');
    const m = /^(mc_[0-9a-f]{48})\.rsc$/.exec(String(req.params.f || ''));
    const co = m ? q1('SELECT * FROM companies WHERE enroll_hash=?', sha(m[1])) : null;
    if (!co || ['suspended', 'expired', 'cancelled'].includes(co.status) || !P.hasModule(co, 'network')) { tooMany('bad:' + req.ip, 20); return res.status(404).type('text').send('not found'); }
    res.type('text').send(fullScript(publicBase(req), m[1]));
  });
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
    if (autoOn(a.co.id)) { try { queuePlan(a.co.id, a.d.id, 'auto-sync'); } catch { } }
    const rows = q("SELECT * FROM router_cmds WHERE company_id=? AND device_id=? AND status='queued' ORDER BY id LIMIT 10", a.co.id, a.d.id);
    const out = [];
    for (const c of rows) {
      if (!ACTIONS[c.action] || !NAME.test(c.target) || (c.arg && !(c.action === 'prof_set' ? RATE : NAME).test(c.arg))) { run("UPDATE router_cmds SET status='failed', result='rejected', done_at=datetime('now') WHERE id=?", c.id); continue; }
      run("UPDATE router_cmds SET status='sent', sent_at=datetime('now') WHERE id=?", c.id);
      out.push(`${c.id}|${c.action}|${c.target}|${c.arg || ''}`);
    }
    run("UPDATE devices SET last_ok=datetime('now'), last_check=datetime('now'), fails=0 WHERE id=?", a.d.id);
    res.type('text').send(out.join(','));
  });
  app.post('/api/router/ack', (req, res) => {
    const a = auth(req, res); if (!a) return;
    for (const l of a.rs.slice(0, 20)) {
      const [id, ok] = l.split('|'); if (!/^\d{1,9}$/.test(id || '')) continue;
      run("UPDATE router_cmds SET status=?, result=?, done_at=datetime('now') WHERE id=? AND company_id=? AND device_id=? AND status='sent'", ok === '1' ? 'done' : 'failed', ok === '1' ? 'ok' : 'router error', Number(id), a.co.id, a.d.id);
    }
    res.type('text').send('ok');
  });

  // ---------- cloud -> router plan (no passwords involved). Preview = dry run; apply queues commands. Nothing is ever deleted. ----------
  const rateOf = (p) => { const f = (m) => (Number.isInteger(+m) ? `${+m}M` : `${Math.round(+m * 1000)}k`); return `${f(p.rate_up)}/${f(p.rate_down)}`; };
  const autoOn = (cid) => { const r = q1('SELECT v FROM app_settings WHERE k=?', 'autosync:' + cid); return !!r && r.v === '1'; };
  function plan(cid, did) {
    const items = [], info = [], pending = new Set(q("SELECT action||'|'||target||'|'||arg AS k FROM router_cmds WHERE company_id=? AND device_id=? AND status IN ('queued','sent')", cid, did).map((r) => r.k));
    const profs = new Map(q("SELECT name, service FROM router_items WHERE company_id=? AND device_id=? AND kind='ppp_profile'", cid, did).map((r) => [r.name, String(r.service || '').split(' ')[0]]));
    const secs = new Map(q("SELECT name, profile, disabled FROM router_items WHERE company_id=? AND device_id=? AND kind='ppp_secret'", cid, did).map((r) => [r.name, r]));
    const have = new Set(profs.keys()), pk = q("SELECT * FROM packages WHERE company_id=? AND active=1 AND service_type='pppoe'", cid), byId = new Map(pk.map((p) => [p.id, p])), byName = new Map(pk.map((p) => [p.name, p]));
    const add = (action, target, arg, why) => { if (!pending.has(`${action}|${target}|${arg}`)) items.push({ action, target, arg, why }); };
    for (const p of pk) {
      const pn = p.profile_name || p.name;
      if (!(p.rate_down > 0 && p.rate_up > 0)) { info.push(['pkg', p.name, 'No speed set on the package, skipped']); continue; }
      if (!NAME.test(pn)) { info.push(['pkg', p.name, 'Router profile name must use only letters, digits and . _ @ - : set the profile name on the package']); continue; }
      const want = rateOf(p);
      if (!profs.has(pn)) { add('prof_set', pn, want, 'Speed profile does not exist on the router'); have.add(pn); }
      else if (profs.get(pn) !== want) add('prof_set', pn, want, `Speed differs (router ${profs.get(pn) || 'none'}, system ${want})`);
    }
    for (const c of q("SELECT * FROM customers WHERE company_id=? AND service_type='pppoe' AND username<>''", cid)) {
      const sec = secs.get(c.username);
      if (!NAME.test(c.username)) { info.push(['cust', c.username, 'Username has characters the router link does not allow, skipped']); continue; }
      if (!sec) { info.push(['cust', c.username, 'Not on the router. Creating a PPPoE user needs its password, which is not stored yet']); continue; }
      const p = (c.package_id && byId.get(c.package_id)) || byName.get(c.package), pn = p ? (p.profile_name || p.name) : '';
      if (pn && NAME.test(pn) && p.rate_down > 0 && p.rate_up > 0 && have.has(pn) && sec.profile !== pn) add('ppp_profile', c.username, pn, `Package ${p.name}: profile ${sec.profile || '-'} to ${pn}`);
      const wantOff = c.status !== 'active';
      if (wantOff && !sec.disabled) add('ppp_disable', c.username, '', 'Subscriber is suspended in the system');
      else if (!wantOff && sec.disabled) {
        const last = q1("SELECT action FROM router_cmds WHERE company_id=? AND device_id=? AND target=? AND action IN ('ppp_disable','ppp_enable') AND status='done' ORDER BY id DESC LIMIT 1", cid, did, c.username);
        if (last && last.action === 'ppp_disable') add('ppp_enable', c.username, '', 'Subscriber is active again in the system');
        else info.push(['cust', c.username, 'Disabled on the router by hand, left alone']);
      }
    }
    for (const [n] of secs) if (!q1("SELECT 1 AS x FROM customers WHERE company_id=? AND username=?", cid, n)) info.push(['router', n, 'On the router only, not touched']);
    return { items, info };
  }
  function queuePlan(cid, did, by) {
    const { items } = plan(cid, did); let n = 0;
    const open = () => q1("SELECT COUNT(*) AS n FROM router_cmds WHERE company_id=? AND status IN ('queued','sent')", cid).n;
    for (const it of items) { if (open() >= 100) break; run('INSERT INTO router_cmds(company_id,device_id,action,target,arg,created_by) VALUES(?,?,?,?,?,?)', cid, did, it.action, it.target, it.arg, by); n++; }
    return n;
  }
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
  const syncRouters = (cid) => q("SELECT id,name,last_ok FROM devices WHERE company_id=? AND protocol='heartbeat' ORDER BY id", cid);
  app.get('/app/network/sync', needAdmin, gate, (req, res) => {
    const t = req.i.t, cid = req.user.company_id, c = ctx(req), rs = syncRouters(cid), auto = autoOn(cid);
    const blocks = rs.map((r) => { const p = plan(cid, r.id); const seen = q1("SELECT COUNT(*) AS n FROM router_items WHERE company_id=? AND device_id=? AND kind='ppp_secret'", cid, r.id).n;
      return `<div class="card tbl"><h3>${esc(r.name)}</h3>${seen === 0 && !q1("SELECT 1 AS x FROM router_items WHERE company_id=? AND device_id=? AND kind='ppp_profile'", cid, r.id) ? `<p class="mut">${t('No data from this router yet. Wait for the first sync (up to 5 minutes after linking).')}</p>` : ''}
<table><tr><th>${t('Action')}</th><th>${t('Name')}</th><th>${t('Value')}</th><th>${t('Reason')}</th></tr>${p.items.map((i) => `<tr><td>${t(ACTION_LABEL[i.action])}</td><td>${esc(i.target)}</td><td>${esc(i.arg)}</td><td>${esc(i.why)}</td></tr>`).join('') || `<tr><td colspan="4" class="mut">${t('Nothing to change. The router matches the system.')}</td></tr>`}</table>
${p.info.length ? `<details><summary class="mut">${t('Not changed')} (${p.info.length})</summary><table>${p.info.slice(0, 200).map((i) => `<tr><td>${esc(i[1])}</td><td class="mut">${t(i[2])}</td></tr>`).join('')}</table></details>` : ''}
${p.items.length ? `<form method="post" action="/app/network/sync/apply">${csrfField(c)}<input type="hidden" name="device" value="${r.id}"><button class="btn">${t('Apply these changes')} (${p.items.length})</button></form>` : ''}</div>`; }).join('');
    res.set('Cache-Control', 'no-store');
    res.send(wrap(req, 'Cloud Sync', `<div class="card"><h3>${t('Cloud sync')}</h3><p class="mut">${t('Preview of what the system would change on the router. Nothing runs until you apply it. Applied changes are queued and the router runs them within a minute. Nothing is ever deleted from the router, and only speed profiles, subscriber profile and enable/disable are synced. Creating a new PPPoE user needs its password and is not done yet.')}</p>
<form method="post" action="/app/network/sync/auto">${csrfField(c)}<input type="hidden" name="on" value="${auto ? 0 : 1}"><p>${t('Automatic sync')}: <b>${auto ? t('On') : t('Off')}</b> <button class="btn sec">${auto ? t('Turn off') : t('Turn on')}</button></p></form></div>${blocks || `<div class="card"><p class="mut">${t('No router is linked yet.')}</p></div>`}`));
  });
  app.post('/app/network/sync/apply', needAdmin, gate, (req, res) => {
    const t = req.i.t, cid = req.user.company_id, d = syncRouters(cid).find((r) => String(r.id) === String(req.body && req.body.device));
    if (!d) return go(res, '/app/network/sync', 'err', t('Invalid'));
    const n = queuePlan(cid, d.id, req.user.username); audit(req, 'router_sync_applied', `${d.name}: ${n}`);
    go(res, '/app/network/commands', 'ok', `${t('Command queued')}: ${n}`);
  });
  app.post('/app/network/sync/auto', needAdmin, gate, (req, res) => {
    const on = req.body && String(req.body.on) === '1' ? '1' : '0', k = 'autosync:' + req.user.company_id;
    run('DELETE FROM app_settings WHERE k=?', k); run('INSERT INTO app_settings(k,v) VALUES(?,?)', k, on); audit(req, on === '1' ? 'router_autosync_on' : 'router_autosync_off', '');
    go(res, '/app/network/sync', 'ok', req.i.t('Saved'));
  });
  app.get('/app/network/commands', needAdmin, gate, (req, res) => {
    const t = req.i.t, cid = req.user.company_id;
    const rows = q('SELECT c.*, d.name AS router FROM router_cmds c JOIN devices d ON d.id=c.device_id WHERE c.company_id=? ORDER BY c.id DESC LIMIT 100', cid);
    res.set('Cache-Control', 'no-store');
    res.send(wrap(req, 'Router Commands', `<div class="card"><h3>${t('Router Commands')}</h3><p class="mut">${t('Only these actions can ever run on a router, and only on names the router itself reported. The router pulls them every minute.')}</p></div><div class="card tbl"><table><tr><th>#</th><th>${t('Time')}</th><th>${t('Router')}</th><th>${t('Action')}</th><th>${t('Name')}</th><th>${t('Status')}</th><th>${t('By')}</th></tr>${rows.map((r) => `<tr><td>${r.id}</td><td>${esc(r.created_at)}</td><td>${esc(r.router)}</td><td>${t(ACTION_LABEL[r.action] || r.action)}${r.arg ? ' → ' + esc(r.arg) : ''}</td><td>${esc(r.target)}</td><td>${esc(r.status)} ${esc(r.result)}</td><td>${esc(r.created_by)}</td></tr>`).join('') || `<tr><td colspan="7" class="mut">-</td></tr>`}</table></div>`));
  });
}
module.exports = { init, RATE, fullScript, installLine, rtStatus, publicBase, KINDS, ACTIONS, NAME };
