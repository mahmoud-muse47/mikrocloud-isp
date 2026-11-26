const crypto = require('node:crypto');
const { esc, page, csrfField, field, select } = require('./views');
const { ROUTER_CATS, AP_CATS } = require('./plans');

const CATS = [
  ['main_router', 'Main MikroTik Router'], ['secondary_router', 'Secondary MikroTik Router'], ['core_router', 'Core Router'], ['edge_router', 'Edge Router'],
  ['ap', 'Wireless Access Point (AP)'], ['outdoor_ap', 'Outdoor Access Point'], ['indoor_ap', 'Indoor Access Point'], ['cpe', 'Wireless CPE'],
  ['switch', 'Network Switch'], ['managed_switch', 'Managed Switch'], ['poe_switch', 'PoE Switch'], ['controller', 'Wireless Controller'],
  ['repeater', 'Repeater'], ['bridge', 'Bridge Device'], ['ont', 'Fiber ONT/ONU'], ['other', 'Other network devices'],
];
const KINDS = {
  all: null, routers_main: ['main_router', 'core_router', 'edge_router'], routers_secondary: ['secondary_router'], aps: ['ap', 'outdoor_ap', 'indoor_ap', 'controller'],
  wireless: ['cpe', 'repeater', 'bridge', 'ap', 'outdoor_ap', 'indoor_ap'], switches: ['switch', 'managed_switch', 'poe_switch'], fiber: ['ont'],
};
const PAGES = [['all', 'All Devices', '/app/network'], ['routers_main', 'Main Routers', '/app/network/main-routers'], ['routers_secondary', 'Secondary Routers', '/app/network/secondary-routers'],
  ['aps', 'Access Points', '/app/network/access-points'], ['wireless', 'Wireless Devices', '/app/network/wireless'], ['switches', 'Switches', '/app/network/switches'], ['fiber', 'Fiber Devices', '/app/network/fiber'],
  ['topology', 'Network Topology', '/app/network/topology'], ['discovery', 'Device Discovery', '/app/network/discovery'], ['groups', 'Device Groups', '/app/network/groups'],
  ['alerts', 'Device Alerts', '/app/network/alerts'], ['logs', 'Device Activity Logs', '/app/network/logs']];
const MAC = /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/;
const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const clean = (v, max = 200) => String(v ?? '').trim().slice(0, max);
const nowSql = () => new Date().toISOString().slice(0, 19).replace('T', ' ');

function init(h, P) {
  const { app, db, q, q1, run, audit, ctx, go, deny, needAdmin, nav } = h;

  const keyOf = () => {
    let r = q1("SELECT v FROM app_settings WHERE k='cred_key'");
    if (!r) { run("INSERT INTO app_settings(k,v) VALUES('cred_key',?)", crypto.randomBytes(32).toString('hex')); r = q1("SELECT v FROM app_settings WHERE k='cred_key'"); }
    return Buffer.from(r.v, 'hex');
  };
  const encrypt = (s) => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', keyOf(), iv); const e = Buffer.concat([c.update(s, 'utf8'), c.final()]); return [iv, c.getAuthTag(), e].map((b) => b.toString('hex')).join('.'); };
  const decrypt = (s) => { const [iv, tag, e] = String(s).split('.').map((x) => Buffer.from(x, 'hex')); const d = crypto.createDecipheriv('aes-256-gcm', keyOf(), iv); d.setAuthTag(tag); return Buffer.concat([d.update(e), d.final()]).toString('utf8'); };

  const catLabel = (d, t) => { const c = CATS.find((x) => x[0] === d.category); return c ? t(c[1]) : String(d.category).replace(/^custom:/, ''); };
  // status is derived ONLY from heartbeat results: never "online" just because a record exists
  function liveStatus(d) {
    if (!d.last_ok) return 'unknown';
    const iv = Math.max(1, d.hb_interval || 5), age = (Date.now() - new Date(d.last_ok.replace(' ', 'T') + 'Z').getTime()) / 60000;
    return age <= iv * 2 ? 'online' : age <= iv * 5 ? 'unstable' : 'offline';
  }
  const dot = (st, t) => `<span title="${t(st[0].toUpperCase() + st.slice(1))}" style="display:inline-block;width:12px;height:12px;border-radius:50%;background:${{ online: '#16a34a', unknown: '#9ca3af', offline: '#dc2626', unstable: '#eab308' }[st]}"></span>`;
  function evaluate(cid) {
    for (const d of q('SELECT * FROM devices WHERE company_id=?', cid)) {
      const st = liveStatus(d);
      if (st === d.status) continue;
      const sev = st === 'offline' ? 'critical' : st === 'unstable' ? 'warning' : 'info';
      const kind = st === 'online' ? 'device_restored' : st === 'offline' ? 'device_offline' : st === 'unstable' ? 'device_unstable' : 'device_unknown';
      run('UPDATE devices SET status=?, fails=? WHERE id=?', st, st === 'online' ? 0 : d.fails + 1, d.id);
      run('INSERT INTO device_alerts(company_id,device_id,severity,kind,msg) VALUES(?,?,?,?,?)', cid, d.id, sev, kind, d.name);
    }
  }
  const timer = setInterval(() => { try { for (const c of q('SELECT id FROM companies')) evaluate(c.id); } catch { } }, 60000);
  timer.unref();

  const gate = (req, res, next) => {
    const co = q1('SELECT * FROM companies WHERE id=?', req.user.company_id);
    if (!P.hasModule(co, 'network')) return deny(req, res);
    evaluate(co.id); next();
  };
  const own = (req, res) => { const d = q1('SELECT * FROM devices WHERE id=? AND company_id=?', Number(req.params.id), req.user.company_id); if (!d) { deny(req, res, 404); return null; } return d; };
  const sub = (req, active, body) => {
    const t = req.i.t;
    return `<div class="card" style="padding:10px"><div class="checks">${PAGES.map(([k, l, u]) => `<a class="btn ${k === active ? '' : 'sec'}" style="margin:2px" href="${u}">${t(l)}</a>`).join('')}</div></div>${body}`;
  };
  const gName = (d) => d.grp || '-';

  function table(req, rows) {
    const t = req.i.t, byId = Object.fromEntries(q('SELECT id,name FROM devices WHERE company_id=?', req.user.company_id).map((r) => [r.id, r.name]));
    return `<div class="card tbl"><table><tr><th></th><th>${t('Device name')}</th><th>${t('Device type')}</th><th>${t('Manufacturer')}</th><th>${t('Device model')}</th><th>${t('IP address')}</th><th>${t('MAC address')}</th><th>${t('Location')}</th><th>${t('Parent device')}</th><th>${t('Connection status')}</th><th>${t('Last connection')}</th><th>${t('Uptime')}</th><th></th></tr>
${rows.map((d) => { const st = liveStatus(d); return `<tr><td>${dot(st, t)}</td><td><a href="/app/network/devices/${d.id}">${esc(d.name)}</a></td><td>${esc(catLabel(d, t))}</td><td>${esc(d.manufacturer)}</td><td>${esc(d.model)}</td><td>${esc(d.ip)}</td><td>${esc(d.mac)}</td><td>${esc([d.location, d.building, d.area].filter(Boolean).join(' / '))}</td><td>${esc(byId[d.parent_id] || '-')}</td><td>${t(st[0].toUpperCase() + st.slice(1))}</td><td>${esc(d.last_ok || '-')}</td><td>${t('Not reported')}</td><td><a href="/app/network/devices/${d.id}">${t('View')}</a></td></tr>`; }).join('') || `<tr><td colspan="13">${t('No results')}</td></tr>`}</table></div>`;
  }
  const listPage = (key, title) => (req, res) => {
    const t = req.i.t, c = ctx(req), cats = KINDS[key];
    const all = q('SELECT * FROM devices WHERE company_id=? ORDER BY id DESC', req.user.company_id);
    const rows = cats ? all.filter((d) => cats.includes(d.category)) : all;
    const sm = { online: 0, unknown: 0, offline: 0, unstable: 0 }; rows.forEach((d) => { sm[liveStatus(d)]++; });
    res.send(page(c, title, sub(req, key, `<div class="card"><a class="btn" href="/app/network/devices/new">${t('Add Network Device')}</a> <span class="mut">${Object.entries(sm).map(([k, v]) => `${dot(k, t)} ${v}`).join(' &nbsp; ')}</span></div>${table(req, rows)}`), nav(req)));
  };
  app.get('/app/network', needAdmin, gate, listPage('all', 'All Devices'));
  app.get('/app/network/main-routers', needAdmin, gate, listPage('routers_main', 'Main Routers'));
  app.get('/app/network/secondary-routers', needAdmin, gate, listPage('routers_secondary', 'Secondary Routers'));
  app.get('/app/network/access-points', needAdmin, gate, listPage('aps', 'Access Points'));
  app.get('/app/network/wireless', needAdmin, gate, listPage('wireless', 'Wireless Devices'));
  app.get('/app/network/switches', needAdmin, gate, listPage('switches', 'Switches'));
  app.get('/app/network/fiber', needAdmin, gate, listPage('fiber', 'Fiber Devices'));

  const devForm = (req, c, d = {}, isNew = true) => {
    const t = req.i.t, groups = q('SELECT name FROM device_groups WHERE company_id=? ORDER BY name', req.user.company_id), others = q('SELECT id,name FROM devices WHERE company_id=? AND id<>? ORDER BY name', req.user.company_id, d.id || 0);
    const isCustom = String(d.category || '').startsWith('custom:');
    return `<form method="post" action="${isNew ? '/app/network/devices' : `/app/network/devices/${d.id}`}">${csrfField(c)}<div class="card"><div class="row2">
${field(t('Device name'), 'name', d.name, { req: true })}${select(t('Device category'), 'category', isCustom ? 'other' : d.category || 'ap', CATS.map(([k, l]) => [k, t(l)]))}
${field(t('Custom category (optional)'), 'custom_category', isCustom ? d.category.slice(7) : '')}${field(t('Manufacturer'), 'manufacturer', d.manufacturer)}${field(t('Device model'), 'model', d.model)}
${field(t('MAC address'), 'mac', d.mac)}${field(t('IP address'), 'ip', d.ip)}${field(t('Management IP'), 'mgmt_ip', d.mgmt_ip)}${field(t('Serial number'), 'serial', d.serial)}${field(t('Firmware version'), 'firmware', d.firmware)}
${field(t('Device location'), 'location', d.location)}${field(t('Building'), 'building', d.building)}${field(t('Floor'), 'floor', d.floor)}${field(t('Area'), 'area', d.area)}
${select(t('Parent device'), 'parent_id', d.parent_id || '', [['', '-'], ...others.map((o) => [o.id, o.name])])}${select(t('Device group'), 'grp', d.grp || '', [['', '-'], ...groups.map((g) => [g.name, g.name])])}
${select(t('Management protocol'), 'protocol', d.protocol || 'manual', [['manual', t('Manual registration')], ['heartbeat', t('Heartbeat')], ['routeros_api', 'RouterOS API'], ['snmp', 'SNMP']])}
${field(t('Heartbeat interval (minutes)'), 'hb_interval', d.hb_interval || 5, { type: 'number' })}
${isNew ? `${field(t('Username'), 'cred_user', '')}${field(t('Password'), 'cred_pass', '', { type: 'password' })}` : ''}
<div style="grid-column:1/-1">${field(t('Notes'), 'notes', d.notes, { ta: true })}</div></div></div><p><button>${t('Save')}</button></p></form>`;
  };
  app.get('/app/network/devices/new', needAdmin, gate, (req, res) => { const c = ctx(req); res.send(page(c, 'Add Network Device', sub(req, 'all', devForm(req, c)), nav(req))); });
  function parseDev(req, existing) {
    const b = req.body, cid = req.user.company_id, t = req.i.t;
    const name = clean(b.name, 120); if (!name) return { err: t('required') };
    let cat = CATS.some((x) => x[0] === b.category) ? b.category : 'other';
    if (clean(b.custom_category, 40)) cat = 'custom:' + clean(b.custom_category, 40);
    const mac = clean(b.mac, 20).toUpperCase().replace(/-/g, ':'), ip = clean(b.ip, 45), mip = clean(b.mgmt_ip, 45);
    if (mac && !MAC.test(mac)) return { err: t('Invalid MAC address') };
    for (const v of [ip, mip]) if (v && !IPV4.test(v)) return { err: t('Invalid IP address') };
    const dupId = existing ? existing.id : 0;
    if (mac && q1('SELECT 1 x FROM devices WHERE company_id=? AND mac=? AND id<>?', cid, mac, dupId)) return { err: t('Duplicate device (same MAC address)') };
    if (ip && q1('SELECT 1 x FROM devices WHERE company_id=? AND ip=? AND id<>?', cid, ip, dupId)) return { err: t('Duplicate device (same IP address)') };
    let parent = b.parent_id ? Number(b.parent_id) : null;
    if (parent && (!q1('SELECT 1 x FROM devices WHERE id=? AND company_id=?', parent, cid) || parent === dupId)) return { err: t('Invalid parent device') };
    if (parent && existing) { let p = parent, n = 0; while (p && n++ < 50) { if (p === existing.id) return { err: t('Invalid parent device') }; p = (q1('SELECT parent_id FROM devices WHERE id=?', p) || {}).parent_id; } }
    const grp = clean(b.grp, 60);
    if (grp && !q1('SELECT 1 x FROM device_groups WHERE company_id=? AND name=?', cid, grp)) return { err: t('Invalid parent device') };
    return { v: [name, cat, clean(b.manufacturer, 80), clean(b.model, 80), mac, ip, mip, clean(b.serial, 80), clean(b.firmware, 60), clean(b.location, 120), clean(b.building, 80), clean(b.floor, 40), clean(b.area, 80), parent, grp,
      ['manual', 'heartbeat', 'routeros_api', 'snmp'].includes(b.protocol) ? b.protocol : 'manual', clean(b.notes, 1000), Math.round(Math.min(1440, Math.max(1, Number(b.hb_interval) || 5)))], cat };
  }
  app.post('/app/network/devices', needAdmin, gate, (req, res) => {
    const t = req.i.t, cid = req.user.company_id, r = parseDev(req, null);
    if (r.err) return go(res, '/app/network/devices/new', 'err', r.err);
    const lm = P.checkLimit(cid, 'max_devices') || (ROUTER_CATS.includes(r.cat) && P.checkLimit(cid, 'max_routers')) || (AP_CATS.includes(r.cat) && P.checkLimit(cid, 'max_aps'));
    if (lm) { audit(req, 'limit_blocked', lm.key); return go(res, '/app/network/devices/new', 'err', P.limitMsg(t, lm)); }
    const token = crypto.randomBytes(20).toString('hex');
    const id = run(`INSERT INTO devices(company_id,name,category,manufacturer,model,mac,ip,mgmt_ip,serial,firmware,location,building,floor,area,parent_id,grp,protocol,notes,hb_interval,hb_token) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, cid, ...r.v, token).lastInsertRowid;
    if (req.body.cred_pass) run('UPDATE devices SET cred_user=?, cred_enc=? WHERE id=?', clean(req.body.cred_user, 80), encrypt(String(req.body.cred_pass).slice(0, 200)), id);
    audit(req, 'device_registered', `${r.v[0]} (${r.cat})`);
    go(res, `/app/network/devices/${id}`, 'ok', t('Created'));
  });
  app.get('/app/network/devices/:id', needAdmin, gate, (req, res) => {
    const d = own(req, res); if (!d) return;
    const t = req.i.t, c = ctx(req), st = liveStatus(d);
    const base = `${req.protocol}://${req.get('host')}`, hb = `${base}/api/heartbeat/${d.hb_token}`;
    const alerts = q('SELECT * FROM device_alerts WHERE device_id=? AND company_id=? ORDER BY id DESC LIMIT 15', d.id, d.company_id);
    const logs = q("SELECT * FROM audit_log WHERE company_id=? AND action LIKE 'device_%' AND detail LIKE ? ORDER BY id DESC LIMIT 15", d.company_id, `%${d.name}%`);
    const kv = (k, v) => `<tr><td class="mut">${t(k)}</td><td>${esc(v || '-')}</td></tr>`;
    res.send(page(c, d.name, sub(req, 'all', `<div class="card"><h3>${dot(st, t)} ${esc(d.name)} <span class="mut">${t(st[0].toUpperCase() + st.slice(1))}</span></h3><div class="tbl"><table>
${kv('Device type', catLabel(d, t))}${kv('Manufacturer', d.manufacturer)}${kv('Device model', d.model)}${kv('MAC address', d.mac)}${kv('IP address', d.ip)}${kv('Management IP', d.mgmt_ip)}${kv('Serial number', d.serial)}${kv('Firmware version', d.firmware)}
${kv('Device location', [d.location, d.building, d.floor, d.area].filter(Boolean).join(' / '))}${kv('Device group', gName(d))}${kv('Management protocol', d.protocol)}${kv('Last successful connection', d.last_ok)}${kv('Last failed check', d.last_fail)}${kv('Consecutive failures', String(d.fails))}
${kv('Credentials', d.cred_enc ? `${d.cred_user} / ******** (${t('encrypted')})` : t('None'))}</table></div>
<p class="mut">${t('CPU, memory, temperature, signal, clients and traffic are not shown: this device has no connected management adapter, and only metrics the device actually reports are displayed.')}</p></div>
<div class="card"><h3>${t('Heartbeat monitoring')}</h3><p class="mut">${t('Status comes only from heartbeats sent by the device or a script on the client network. Run this on the MikroTik scheduler (interval equal to the heartbeat interval):')}</p>
<input readonly onfocus="this.select()" value="${esc(`/tool fetch url="${hb}" keep-result=no`)}"></div>
<div class="card"><h3>${t('Available management actions')}</h3><p class="mut">${t('None. Reboot, Wi-Fi changes, backup and similar actions need a device adapter (RouterOS API, SNMP or vendor API), which is not connected in this version. Nothing is shown as done unless a device confirms it.')}</p></div>
<div class="card"><h3>${t('Edit')}</h3>${devForm(req, c, d, false)}
<form method="post" action="/app/network/devices/${d.id}/credentials" class="row">${csrfField(c)}${field(t('Username'), 'cred_user', d.cred_user)}${field(t('New password'), 'cred_pass', '', { type: 'password', req: true })}<div style="padding-top:22px"><button class="sec">${t('Rotate credentials')}</button></div></form>
<form method="post" action="/app/network/devices/${d.id}/delete" onsubmit="return confirm('?')">${csrfField(c)}<button class="bad">${t('Delete')}</button></form></div>
<div class="card tbl"><h3>${t('Device Alerts')}</h3><table>${alerts.map((a) => `<tr><td>${esc(a.created_at)}</td><td>${esc(a.severity)}</td><td>${t(a.kind)}</td></tr>`).join('') || `<tr><td>${t('No results')}</td></tr>`}</table></div>
<div class="card tbl"><h3>${t('Device Activity Logs')}</h3><table>${logs.map((a) => `<tr><td>${esc(a.ts)}</td><td>${esc(a.action)}</td><td>${esc(a.detail)}</td></tr>`).join('') || `<tr><td>${t('No results')}</td></tr>`}</table></div>`), nav(req)));
  });
  app.post('/app/network/devices/:id', needAdmin, gate, (req, res) => {
    const d = own(req, res); if (!d) return;
    const t = req.i.t, r = parseDev(req, d);
    if (r.err) return go(res, `/app/network/devices/${d.id}`, 'err', r.err);
    if (!(ROUTER_CATS.includes(d.category) || AP_CATS.includes(d.category)) && (ROUTER_CATS.includes(r.cat) || AP_CATS.includes(r.cat))) {
      const lm = ROUTER_CATS.includes(r.cat) ? P.checkLimit(d.company_id, 'max_routers') : P.checkLimit(d.company_id, 'max_aps');
      if (lm) return go(res, `/app/network/devices/${d.id}`, 'err', P.limitMsg(t, lm));
    }
    run(`UPDATE devices SET name=?,category=?,manufacturer=?,model=?,mac=?,ip=?,mgmt_ip=?,serial=?,firmware=?,location=?,building=?,floor=?,area=?,parent_id=?,grp=?,protocol=?,notes=?,hb_interval=? WHERE id=? AND company_id=?`, ...r.v, d.id, d.company_id);
    const changed = []; if (d.ip !== r.v[5]) changed.push('ip'); if (d.mac !== r.v[4]) changed.push('mac');
    audit(req, 'device_edited', `${r.v[0]}${changed.length ? ' changed: ' + changed.join(',') : ''}`);
    go(res, `/app/network/devices/${d.id}`, 'ok', t('Saved'));
  });
  app.post('/app/network/devices/:id/credentials', needAdmin, gate, (req, res) => {
    const d = own(req, res); if (!d) return;
    const pw = String(req.body.cred_pass || ''); if (!pw) return go(res, `/app/network/devices/${d.id}`, 'err', req.i.t('required'));
    run('UPDATE devices SET cred_user=?, cred_enc=? WHERE id=?', clean(req.body.cred_user, 80), encrypt(pw.slice(0, 200)), d.id);
    audit(req, 'device_credentials_changed', d.name);
    go(res, `/app/network/devices/${d.id}`, 'ok', req.i.t('Saved'));
  });
  app.post('/app/network/devices/:id/delete', needAdmin, gate, (req, res) => {
    const d = own(req, res); if (!d) return;
    run('UPDATE devices SET parent_id=NULL WHERE parent_id=? AND company_id=?', d.id, d.company_id);
    run('DELETE FROM devices WHERE id=? AND company_id=?', d.id, d.company_id);
    audit(req, 'device_deleted', d.name);
    go(res, '/app/network', 'ok', req.i.t('Deleted'));
  });
  // heartbeat from a device / script (GET so a MikroTik fetch can call it). The token identifies the device.
  app.get('/api/heartbeat/:token', (req, res) => {
    const tok = String(req.params.token || '');
    if (!/^[0-9a-f]{40}$/.test(tok)) return res.status(404).json({ ok: false });
    const d = q1('SELECT * FROM devices WHERE hb_token=?', tok);
    if (!d) return res.status(404).json({ ok: false });
    run('UPDATE devices SET last_ok=?, last_check=?, fails=0 WHERE id=?', nowSql(), nowSql(), d.id);
    evaluate(d.company_id);
    res.json({ ok: true });
  });

  app.get('/app/network/topology', needAdmin, gate, (req, res) => {
    const t = req.i.t, c = ctx(req), rows = q('SELECT * FROM devices WHERE company_id=? ORDER BY name', req.user.company_id);
    const kids = (id) => rows.filter((r) => (r.parent_id || null) === id);
    const node = (d, depth) => `<li>${dot(liveStatus(d), t)} <a href="/app/network/devices/${d.id}">${esc(d.name)}</a> <span class="mut">${esc(catLabel(d, t))}</span> <span class="badge">${t('Manual link')}</span>${depth < 20 && kids(d.id).length ? `<ul>${kids(d.id).map((k) => node(k, depth + 1)).join('')}</ul>` : ''}</li>`;
    res.send(page(c, 'Network Topology', sub(req, 'topology', `<div class="card"><p class="mut">${t('Every link here is a manually configured parent relationship. No link is verified automatically, and none is guessed from IP addresses. Set the parent on each device page.')}</p>
<div id="topo" style="transform-origin:top left"><ul style="list-style:none;padding-inline-start:20px"><li><b>${t('Internet')}</b><ul style="list-style:none;padding-inline-start:20px">${kids(null).map((d) => node(d, 0)).join('') || `<li>${t('No results')}</li>`}</ul></li></ul></div>
<p><button class="sec" type="button" onclick="z(0.1)">+</button> <button class="sec" type="button" onclick="z(-0.1)">-</button></p><script>var zz=1;function z(d){zz=Math.max(.4,Math.min(2,zz+d));document.getElementById('topo').style.transform='scale('+zz+')'}</script></div>`), nav(req)));
  });
  app.get('/app/network/discovery', needAdmin, gate, (req, res) => {
    const t = req.i.t, c = ctx(req);
    res.send(page(c, 'Device Discovery', sub(req, 'discovery', `<div class="card"><h3>${t('Device Discovery')}</h3><p>${t('Automatic discovery (RouterOS API, SNMP, LLDP, ARP/DHCP) is not available in this version. The platform runs on the internet and cannot reach private networks, and scanning is limited to what an authorized agent inside the client network reports. Register devices manually and use heartbeat monitoring.')}</p><a class="btn" href="/app/network/devices/new">${t('Add Network Device')}</a></div>`), nav(req)));
  });
  app.get('/app/network/groups', needAdmin, gate, (req, res) => {
    const t = req.i.t, c = ctx(req), cid = req.user.company_id;
    const groups = q('SELECT * FROM device_groups WHERE company_id=? ORDER BY name', cid);
    const devs = q('SELECT * FROM devices WHERE company_id=?', cid);
    res.send(page(c, 'Device Groups', sub(req, 'groups', `<div class="card"><form method="post" action="/app/network/groups" class="row">${csrfField(c)}${field(t('Name'), 'name', '', { req: true })}<div style="padding-top:22px"><button>${t('Add')}</button></div></form></div>
<div class="card tbl"><table><tr><th>${t('Name')}</th><th>${t('Devices')}</th><th>${t('Status')}</th></tr>${groups.map((g) => { const m = devs.filter((d) => d.grp === g.name), sm = { online: 0, unknown: 0, offline: 0, unstable: 0 }; m.forEach((d) => { sm[liveStatus(d)]++; });
      return `<tr><td>${esc(g.name)}</td><td>${m.map((d) => `<a href="/app/network/devices/${d.id}">${esc(d.name)}</a>`).join(', ') || '-'}</td><td>${Object.entries(sm).map(([k, v]) => `${dot(k, t)} ${v}`).join(' ')}</td></tr>`; }).join('') || `<tr><td colspan="3">${t('No results')}</td></tr>`}</table></div>`), nav(req)));
  });
  app.post('/app/network/groups', needAdmin, gate, (req, res) => {
    const n = clean(req.body.name, 60); if (!n) return go(res, '/app/network/groups', 'err', req.i.t('required'));
    try { run('INSERT INTO device_groups(company_id,name) VALUES(?,?)', req.user.company_id, n); } catch { return go(res, '/app/network/groups', 'err', req.i.t('duplicate')); }
    audit(req, 'device_group_created', n); go(res, '/app/network/groups', 'ok', req.i.t('Created'));
  });
  app.get('/app/network/alerts', needAdmin, gate, (req, res) => {
    const t = req.i.t, c = ctx(req), rows = q('SELECT a.*, d.name dname FROM device_alerts a LEFT JOIN devices d ON d.id=a.device_id WHERE a.company_id=? ORDER BY a.id DESC LIMIT 200', req.user.company_id);
    res.send(page(c, 'Device Alerts', sub(req, 'alerts', `<div class="card"><p class="mut">${t('Alerts are shown in the app only. Email and Telegram notifications are not available in this version.')}</p></div><div class="card tbl"><table><tr><th>${t('Time')}</th><th>${t('Severity')}</th><th>${t('Alert')}</th><th>${t('Device name')}</th><th></th></tr>${rows.map((a) => `<tr><td>${esc(a.created_at)}</td><td>${esc(a.severity)}</td><td>${t(a.kind)}</td><td>${esc(a.dname || a.msg)}</td><td>${a.ack ? t('Acknowledged') : `<form class="inline" method="post" action="/app/network/alerts/${a.id}/ack">${csrfField(c)}<button class="sec">${t('Acknowledge')}</button></form>`}</td></tr>`).join('') || `<tr><td colspan="5">${t('No results')}</td></tr>`}</table></div>`), nav(req)));
  });
  app.post('/app/network/alerts/:id/ack', needAdmin, gate, (req, res) => {
    run('UPDATE device_alerts SET ack=1 WHERE id=? AND company_id=?', Number(req.params.id), req.user.company_id);
    go(res, '/app/network/alerts', 'ok', req.i.t('Updated'));
  });
  app.get('/app/network/logs', needAdmin, gate, (req, res) => {
    const t = req.i.t, c = ctx(req), s = clean(req.query.q, 60);
    const rows = q("SELECT * FROM audit_log WHERE company_id=? AND action LIKE 'device_%' AND (action LIKE ? OR detail LIKE ?) ORDER BY id DESC LIMIT 200", req.user.company_id, `%${s}%`, `%${s}%`);
    res.send(page(c, 'Device Activity Logs', sub(req, 'logs', `<div class="card"><form method="get" class="row"><div><input name="q" value="${esc(s)}" placeholder="${t('Search')}"></div><div><button>${t('Search')}</button></div></form></div><div class="card tbl"><table><tr><th>${t('Time')}</th><th>${t('Action')}</th><th>${t('Detail')}</th></tr>${rows.map((a) => `<tr><td>${esc(a.ts)}</td><td>${esc(a.action)}</td><td>${esc(a.detail)}</td></tr>`).join('') || `<tr><td colspan="3">${t('No results')}</td></tr>`}</table></div>`), nav(req)));
  });
  return { liveStatus, evaluate, decrypt };
}
module.exports = { init, CATS };
