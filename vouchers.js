'use strict';
const crypto = require('crypto');
const qrcode = require('qrcode-generator');
const { esc, page, csrfField, badge, field, select, infoGrid } = require('./views');

const clean = (v, max = 300) => String(v ?? '').trim().slice(0, max);
const nz = (v, def, min, max) => { const n = Number(v); return Number.isFinite(n) && n >= min && n <= max ? n : def; };
const validImg = (s) => s === '' || (/^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$/.test(s) && s.length <= 300000);
const hex = (v, def) => (/^#[0-9a-fA-F]{6}$/.test(v || '') ? v : def);
const today = () => new Date().toISOString().slice(0, 10);
const FONTS = ['Arial', 'Tahoma', 'Verdana', 'Georgia', 'Courier New', 'system-ui'];
const UNITS = { mm: 1, cm: 10, px: 25.4 / 96 };
const mm = (n, unit) => Math.round(n * (UNITS[unit] || 1) * 100) / 100;

const DEFAULT_CFG = { unit: 'mm', w: 85.6, h: 54, orient: 'landscape', bg: '#ffffff', bg_image: '', color: '#0f172a', accent: '#2563eb', font: 'Arial', size: 13, weight: '600', align: 'center', border: 0.3, radius: 3, logo: '', logo_w: 22, logo_h: 10, logo_pos: 'top', show_net: 1, show_phone: 1, show_pkg: 1, show_price: 1, show_exp: 1, show_valid: 1, show_user: 1, show_pass: 1, show_qr: 1, text: '', page_w: 210, page_h: 297, margin: 8, gap_h: 2, gap_v: 2, cut: 1, page_unit: 'mm' };
const PRESETS = [
  ['Classic', {}],
  ['Dark', { bg: '#0f172a', color: '#f8fafc', accent: '#38bdf8', radius: 4 }],
  ['Minimal', { bg: '#ffffff', color: '#111827', accent: '#111827', border: 0.2, radius: 0, weight: '500', show_qr: 0 }],
];

function normCfg(b, base = DEFAULT_CFG) {
  const c = { ...base };
  c.unit = Object.keys(UNITS).includes(b.unit) ? b.unit : base.unit;
  c.page_unit = c.unit === 'px' ? 'mm' : c.unit;
  const maxW = c.unit === 'px' ? 2000 : c.unit === 'cm' ? 30 : 300;
  c.w = nz(b.w, base.w, 1, maxW); c.h = nz(b.h, base.h, 1, maxW);
  c.orient = b.orient === 'portrait' ? 'portrait' : 'landscape';
  c.bg = hex(b.bg, base.bg); c.color = hex(b.color, base.color); c.accent = hex(b.accent, base.accent);
  c.bg_image = b.bg_image === undefined ? base.bg_image : (validImg(String(b.bg_image)) ? String(b.bg_image) : base.bg_image);
  if (b.rm_bg_image) c.bg_image = '';
  c.logo = b.logo === undefined ? base.logo : (validImg(String(b.logo)) ? String(b.logo) : base.logo);
  if (b.rm_logo) c.logo = '';
  c.font = FONTS.includes(b.font) ? b.font : base.font;
  c.size = nz(b.size, base.size, 6, 40); c.weight = ['400', '500', '600', '700'].includes(b.weight) ? b.weight : base.weight;
  c.align = ['left', 'center', 'right'].includes(b.align) ? b.align : base.align;
  c.border = nz(b.border, base.border, 0, 5); c.radius = nz(b.radius, base.radius, 0, 20);
  c.logo_w = nz(b.logo_w, base.logo_w, 2, 120); c.logo_h = nz(b.logo_h, base.logo_h, 2, 120);
  c.logo_pos = ['top', 'left', 'right'].includes(b.logo_pos) ? b.logo_pos : base.logo_pos;
  for (const k of ['show_net', 'show_phone', 'show_pkg', 'show_price', 'show_exp', 'show_valid', 'show_user', 'show_pass', 'show_qr', 'cut']) c[k] = b._f ? (b[k] ? 1 : 0) : base[k];
  c.text = clean(b.text, 200);
  c.page_w = nz(b.page_w, base.page_w, 20, 1000); c.page_h = nz(b.page_h, base.page_h, 20, 1000);
  c.margin = nz(b.margin, base.margin, 0, 50); c.gap_h = nz(b.gap_h, base.gap_h, 0, 50); c.gap_v = nz(b.gap_v, base.gap_v, 0, 50);
  return c;
}
const cardMm = (c) => { let w = mm(c.w, c.unit), h = mm(c.h, c.unit); if (c.orient === 'portrait' && w > h) [w, h] = [h, w]; if (c.orient === 'landscape' && h > w) [w, h] = [h, w]; return [w, h]; };
function layoutOf(c) {
  const [w, h] = cardMm(c);
  const cols = Math.floor((c.page_w - 2 * c.margin + c.gap_h) / (w + c.gap_h)), rows = Math.floor((c.page_h - 2 * c.margin + c.gap_v) / (h + c.gap_v));
  return { w, h, cols, rows, per: Math.max(0, cols * rows) };
}
function qrSvg(text) { const qr = qrcode(0, 'M'); qr.addData(text); qr.make(); return qr.createSvgTag({ cellSize: 2, margin: 0, scalable: true }); }

function renderCard(c, v, ctxd, t) {
  const [w, h] = cardMm(c);
  const logo = c.logo ? `<img src="${esc(c.logo)}" style="width:${c.logo_w}mm;height:${c.logo_h}mm;object-fit:contain" alt="">` : '';
  const lines = [];
  if (c.show_net && ctxd.net) lines.push(`<div style="font-size:${c.size * 1.15}pt;font-weight:700;color:${c.accent}">${esc(ctxd.net)}</div>`);
  if (c.show_pkg && v.package) lines.push(`<div style="font-size:${c.size * 0.85}pt">${esc(v.package)}${c.show_valid && v.validity ? ` - ${esc(v.validity)}` : ''}</div>`);
  if (c.show_user) lines.push(`<div style="font-size:${c.size}pt">${esc(t('Username'))}: <b style="font-family:'Courier New',monospace;font-size:${c.size * 1.2}pt">${esc(v.username)}</b></div>`);
  if (c.show_pass) lines.push(`<div style="font-size:${c.size}pt">${esc(t('Password'))}: <b style="font-family:'Courier New',monospace;font-size:${c.size * 1.2}pt">${esc(v.password)}</b></div>`);
  if (c.show_price && v.price !== '') lines.push(`<div style="font-size:${c.size * 0.9}pt">${esc(t('Price'))}: ${esc(v.price)}</div>`);
  if (c.show_exp && v.expires) lines.push(`<div style="font-size:${c.size * 0.75}pt">${esc(t('Valid until'))}: ${esc(v.expires)}</div>`);
  if (c.show_phone && ctxd.phone) lines.push(`<div style="font-size:${c.size * 0.75}pt">${esc(ctxd.phone)}</div>`);
  if (c.text) lines.push(`<div style="font-size:${c.size * 0.75}pt">${esc(c.text)}</div>`);
  const qr = c.show_qr ? `<div style="width:${Math.min(w, h) * 0.3}mm;height:${Math.min(w, h) * 0.3}mm;flex:none">${qrSvg(v.username)}</div>` : '';
  const flexDir = c.logo_pos === 'top' ? 'column' : c.logo_pos === 'left' ? 'row' : 'row-reverse';
  const ai = c.align === 'center' ? 'center' : c.align === 'left' ? 'flex-start' : 'flex-end';
  return `<div class="vc" style="width:${w}mm;height:${h}mm;background:${esc(c.bg)}${c.bg_image ? ` url(${esc(c.bg_image)}) center/cover` : ''};color:${esc(c.color)};font-family:${esc(c.font)},sans-serif;font-weight:${c.weight};text-align:${c.align};border:${c.border}mm solid ${esc(c.accent)};border-radius:${c.radius}mm;display:flex;flex-direction:${flexDir};align-items:center;justify-content:space-around;gap:1.5mm;padding:2mm;box-sizing:border-box;overflow:hidden;line-height:1.25">${logo}${flexDir === 'column' ? '<div style="display:flex;flex-direction:row;align-items:center;justify-content:space-around;gap:2mm;width:100%;min-width:0">' : ''}<div style="display:flex;flex-direction:column;align-items:${ai};justify-content:center;gap:0.8mm;min-width:0">${lines.join('')}</div>${qr}${flexDir === 'column' ? '</div>' : ''}</div>`;
}
const sample = (t) => ({ username: 'NET-A7K92M', password: '48271', package: 'Gold 10M', price: '50 EGP', validity: `30 ${t('days')}`, expires: today() });

function init(h) {
  const { app, q, q1, run, audit, ctx, go, deny, needAdmin, nav, P } = h;
  const needV = [needAdmin, (req, res, next) => (P.hasModule(q1('SELECT * FROM companies WHERE id=?', req.user.company_id), 'vouchers') ? next() : deny(req, res, 'module'))];
  const getCo = (cid) => q1('SELECT * FROM companies WHERE id=?', cid);
  const ctxd = (co) => ({ net: co.network_name || co.name, phone: co.phone || co.whatsapp || '' });

  function ensureTemplates(cid) {
    if (q1('SELECT count(*) n FROM voucher_templates WHERE company_id=?', cid).n) return;
    PRESETS.forEach(([name, o], i) => run('INSERT INTO voucher_templates(company_id,name,is_default,config) VALUES(?,?,?,?)', cid, name, i === 0 ? 1 : 0, JSON.stringify({ ...DEFAULT_CFG, ...o })));
  }
  const cfgOf = (tp) => ({ ...DEFAULT_CFG, ...JSON.parse(tp.config || '{}') });
  const getTpl = (req, id) => q1('SELECT * FROM voucher_templates WHERE id=? AND company_id=?', id, req.user.company_id);
  const getBatch = (req, id) => q1('SELECT * FROM voucher_batches WHERE id=? AND company_id=?', id, req.user.company_id);

  // ---------- generation
  function charset(o) {
    let s = '';
    if (o.mode === 'numeric') s = '0123456789';
    else if (o.mode === 'alpha_upper') s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    else if (o.mode === 'alpha_lower') s = 'abcdefghijklmnopqrstuvwxyz';
    else if (o.mode === 'custom') s = o.custom || '';
    else { if (o.upper) s += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; if (o.lower) s += 'abcdefghijklmnopqrstuvwxyz'; if (o.nums) s += '0123456789'; s += o.custom || ''; }
    const ex = new Set((o.exclude || '').split(''));
    return [...new Set(s.split(''))].filter((ch) => !ex.has(ch) && /\S/.test(ch));
  }
  const rnd = (set, len) => { let s = ''; for (let i = 0; i < len; i++) s += set[crypto.randomInt(set.length)]; return s; };
  function parseGen(b) {
    const o = {
      count: Math.round(Number(b.count)), package_id: Number(b.package_id), prefix: clean(b.prefix, 12), suffix: clean(b.suffix, 12), prefix_pos: b.prefix_pos === 'after' ? 'after' : 'before',
      mode: ['numeric', 'alpha_upper', 'alpha_lower', 'mixed', 'custom'].includes(b.mode) ? b.mode : 'numeric', upper: b.upper ? 1 : 0, lower: b.lower ? 1 : 0, nums: b.nums ? 1 : 0, custom: clean(b.custom, 80), exclude: clean(b.exclude, 80),
      len: Math.round(Number(b.len)), sequential: b.sequential ? 1 : 0, seq_start: Math.round(nz(b.seq_start, 1, 0, 1e12)),
      pass_mode: ['same', 'random', 'numeric'].includes(b.pass_mode) ? b.pass_mode : 'random', pass_len: Math.round(nz(b.pass_len, 6, 3, 32)), expires_on: /^\d{4}-\d{2}-\d{2}$/.test(b.expires_on || '') ? b.expires_on : '', note: clean(b.note, 200),
    };
    return o;
  }
  function genCodes(cid, o) {
    const set = charset(o);
    if (!(o.len >= 3 && o.len <= 32)) return { err: 'Invalid code length' };
    if (o.sequential) {
      if (o.seq_start + o.count > 10 ** Math.min(o.len, 15)) return { err: 'Code length too short for this count' };
    } else {
      if (set.length < 2) return { err: 'Character set is too small' };
      if (Math.pow(set.length, o.len) < o.count * 3) return { err: 'Code length too short for this count' };
    }
    const wrap = (core) => (o.prefix_pos === 'after' ? `${core}${o.prefix}` : `${o.prefix}${core}`) + o.suffix;
    const out = []; const seen = new Set();
    const existing = (names) => new Set(q(`SELECT username FROM vouchers WHERE company_id=? AND username IN (${names.map(() => '?').join(',')})`, cid, ...names).map((r) => r.username));
    let guard = 0;
    while (out.length < o.count) {
      if (++guard > 50) return { err: 'Could not generate unique codes' };
      const need = o.count - out.length, cand = [];
      for (let i = 0; i < need; i++) {
        const core = o.sequential ? String(o.seq_start + out.length + i + (guard - 1) * 0).padStart(o.len, '0') : rnd(set, o.len);
        const u = wrap(core); if (!seen.has(u)) { seen.add(u); cand.push(u); }
      }
      const ex = cand.length ? existing(cand) : new Set();
      if (o.sequential && ex.size) return { err: 'Some sequential codes already exist' };
      for (const u of cand) if (!ex.has(u)) out.push(u);
    }
    return { codes: out, set };
  }
  const passFor = (o, user, set) => (o.pass_mode === 'same' ? user : o.pass_mode === 'numeric' ? rnd([...'0123456789'], o.pass_len) : rnd(set.length > 1 ? set : [...'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'], o.pass_len));

  app.post('/app/vouchers/generate', needV, (req, res) => {
    const cid = req.user.company_id, t = req.i.t, o = parseGen(req.body), back = '/app/vouchers';
    if (!(o.count >= 1 && o.count <= 5000)) return go(res, back, 'err', t('Invalid count'));
    const pk = q1('SELECT * FROM packages WHERE id=? AND company_id=? AND active=1', o.package_id, cid);
    if (!pk) return go(res, back, 'err', t('Package required'));
    for (const [k, add] of [['max_vouchers_batch', o.count], ['max_vouchers_month', o.count]]) { const lim = P.checkLimit(cid, k, add); if (lim) return go(res, back, 'err', P.limitMsg(lim, req.i)); }
    const g = genCodes(cid, o);
    if (g.err) return go(res, back, 'err', t(g.err));
    const num = (q1('SELECT COALESCE(MAX(number),0) m FROM voucher_batches WHERE company_id=?', cid).m || 0) + 1;
    try {
      const bid = run('INSERT INTO voucher_batches(company_id,number,package_id,package_name,price,validity_days,quota_mb,rate_down,rate_up,profile_name,count,created_by,settings,expires_on,note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', cid, num, pk.id, pk.name, pk.price, pk.validity_days, pk.quota_mb, pk.rate_down, pk.rate_up, pk.profile_name, o.count, req.user.username, JSON.stringify(o), o.expires_on, o.note).lastInsertRowid;
      for (const u of g.codes) run('INSERT INTO vouchers(company_id,batch_id,username,password) VALUES(?,?,?,?)', cid, bid, u, passFor(o, u, g.set));
      audit(req, 'voucher_batch_created', `#${num} x${o.count}`);
      go(res, `/app/vouchers/batch/${bid}`, 'ok', t('Saved'));
    } catch (e) {
      go(res, back, 'err', t('Could not save'));
    }
  });

  const chk = (n, label, v, t) => `<label style="display:inline-flex;gap:6px;align-items:center;color:var(--tx);margin:4px 12px 4px 0"><input type="checkbox" style="width:auto" name="${n}" value="1" ${v ? 'checked' : ''}> ${t(label)}</label>`;
  app.get('/app/vouchers', needV, (req, res) => {
    const cid = req.user.company_id, t = req.i.t, c = ctx(req); ensureTemplates(cid);
    const pk = q('SELECT * FROM packages WHERE company_id=? AND active=1 ORDER BY name', cid);
    const rows = q('SELECT b.*, (SELECT count(*) FROM vouchers v WHERE v.batch_id=b.id AND v.status=\'used\') used, (SELECT count(*) FROM vouchers v WHERE v.batch_id=b.id AND v.status=\'sold\') sold FROM voucher_batches b WHERE company_id=? ORDER BY id DESC LIMIT 100', cid);
    const lim = P.limitsOf(getCo(cid));
    res.send(page(c, 'Vouchers', `<div class="card tbl"><h3>${t('Voucher batches')}</h3><p><a class="btn sec" href="/app/vouchers/templates">${t('Card templates')}</a></p><table><tr><th>#</th><th>${t('Date')}</th><th>${t('Package name')}</th><th>${t('Cards')}</th><th>${t('Sold')}</th><th>${t('Used')}</th><th>${t('Printed')}</th><th>${t('Status')}</th><th></th></tr>
${rows.map((b) => `<tr><td>${b.number}</td><td>${esc(String(b.created_at).slice(0, 10))}</td><td>${esc(b.package_name)}</td><td>${b.count}</td><td>${b.sold}</td><td>${b.used}</td><td>${b.print_count}x</td><td>${badge(b.status, t)}</td><td><a href="/app/vouchers/batch/${b.id}">${t('View')}</a></td></tr>`).join('') || `<tr><td colspan="9" class="mut">${t('No results')}</td></tr>`}</table></div>
<div class="card"><h3>${t('Generate cards')}</h3>${pk.length ? `<p class="mut">${t('Max cards per batch')}: ${lim.max_vouchers_batch < 0 ? t('Unlimited') : lim.max_vouchers_batch} | ${t('Max cards per month')}: ${lim.max_vouchers_month < 0 ? t('Unlimited') : lim.max_vouchers_month}</p>
<form method="post" action="/app/vouchers/generate">${csrfField(c)}<div class="row">${field(t('Number of cards'), 'count', '50', { type: 'number', req: true })}${select(t('Package name'), 'package_id', '', pk.map((p) => [String(p.id), `${p.name} (${p.service_type})`]))}${field(t('Prefix'), 'prefix', '')}${select(t('Prefix position'), 'prefix_pos', 'before', [['before', t('Before the code')], ['after', t('After the code')]])}${field(t('Suffix'), 'suffix', '')}${field(t('Code length'), 'len', '6', { type: 'number', req: true })}
${select(t('Character type'), 'mode', 'numeric', [['numeric', t('Numbers only')], ['alpha_upper', t('Uppercase letters')], ['alpha_lower', t('Lowercase letters')], ['mixed', t('Custom mix')], ['custom', t('Custom character set')]])}${field(t('Custom characters'), 'custom', '')}${field(t('Excluded characters'), 'exclude', '0O1Il')}
${select(t('Password'), 'pass_mode', 'numeric', [['same', t('Same as username')], ['numeric', t('Random numbers')], ['random', t('Random from the character set')]])}${field(t('Password length'), 'pass_len', '5', { type: 'number' })}${field(t('Card valid until (optional)'), 'expires_on', '', { type: 'date' })}${field(t('Note'), 'note', '')}</div>
<p>${chk('upper', 'Uppercase letters', 1, t)}${chk('lower', 'Lowercase letters', 0, t)}${chk('nums', 'Numbers', 1, t)} (${t('used with Custom mix')})</p>
<p>${chk('sequential', 'Sequential numbering', 0, t)} ${t('Start at')}: <input type="number" name="seq_start" value="1" style="width:120px;display:inline-block"></p><p><button>${t('Generate')}</button></p></form>` : `<p class="mut">${t('Create a package first')}: <a href="/app/packages">${t('Packages')}</a></p>`}</div>`, nav(req)));
  });

  // ---------- batches
  const vstatus = (v, b) => (v.status === 'disabled' ? 'disabled' : (v.status === 'used' ? 'used' : (b.expires_on && b.expires_on < today() ? 'expired' : v.status)));
  app.get('/app/vouchers/batch/:id', needV, (req, res) => {
    const b = getBatch(req, req.params.id), t = req.i.t, c = ctx(req); if (!b) return res.status(404).send(page(c, 'Error', `<div class="card"><h3>${t('Not found')}</h3></div>`));
    const f = clean(req.query.f, 12), s = clean(req.query.q, 40);
    let vs = q('SELECT * FROM vouchers WHERE batch_id=? ORDER BY id', b.id).map((v) => ({ ...v, eff: vstatus(v, b) }));
    const count = (k) => vs.filter((v) => v.eff === k).length;
    if (['unused', 'sold', 'used', 'disabled', 'expired'].includes(f)) vs = vs.filter((v) => v.eff === f);
    if (s) vs = vs.filter((v) => v.username.toLowerCase().includes(s.toLowerCase()));
    const tpls = q('SELECT * FROM voucher_templates WHERE company_id=? ORDER BY is_default DESC, id', b.company_id);
    const price = Number(b.price) || 0, soldTotal = (count('sold') + count('used')) * price;
    res.send(page(c, `Batch ${b.number}`, `<div class="card"><div class="head"><h3>${t('Batch')} #${b.number} ${badge(b.status, t)}</h3><div class="acts"><a class="btn sec" href="/app/vouchers/batch/${b.id}/export.csv">CSV</a></div></div>
${infoGrid([[t('Date'), esc(String(b.created_at).slice(0, 10))], [t('Package name'), esc(b.package_name)], [t('Price'), esc(b.price)], [t('Cards'), b.count], [t('Unused'), count('unused')], [t('Sold'), count('sold')], [t('Used'), count('used')], [t('Disabled'), count('disabled')], [t('Expired'), count('expired')], [t('Sales value'), esc(soldTotal)], [t('Created by'), esc(b.created_by)], [t('Printed'), `${b.print_count}x${b.printed_at ? ' (' + esc(String(b.printed_at).slice(0, 10)) + ')' : ''}`]])}
<form method="get" action="/app/vouchers/batch/${b.id}/print" class="row">${select(t('Card template'), 'tpl', '', tpls.map((x) => [String(x.id), x.name + (x.is_default ? ' *' : '')]))}<div style="padding-top:22px"><button>${t('Print preview')}</button></div></form>
<form class="inline" method="post" action="/app/vouchers/batch/${b.id}/printed">${csrfField(c)}<button class="sec">${t('Mark as printed')}</button></form>
<form class="inline" method="post" action="/app/vouchers/batch/${b.id}/disable" onsubmit="return confirm('${t('Disable all unused cards?')}')">${csrfField(c)}<button class="bad">${t('Disable unused cards')}</button></form></div>
<div class="card tbl"><form method="get" class="row">${select(t('Status'), 'f', f, [['', t('All')], ['unused', t('Unused')], ['sold', t('Sold')], ['used', t('Used')], ['disabled', t('Disabled')], ['expired', t('Expired')]])}${field(t('Search'), 'q', s)}<div style="padding-top:22px"><button>${t('Search')}</button></div></form>
<table><tr><th>${t('Username')}</th><th>${t('Password')}</th><th>${t('Status')}</th><th></th></tr>${vs.map((v) => `<tr><td><code>${esc(v.username)}</code></td><td><code>${esc(v.password)}</code></td><td>${badge(v.eff, t)}</td><td>${v.eff === 'unused' || v.eff === 'expired' ? `<form class="inline" method="post" action="/app/vouchers/${v.id}/status">${csrfField(c)}<input type="hidden" name="to" value="sold"><button class="sec">${t('Mark sold')}</button></form>` : ''}${v.eff === 'sold' || v.eff === 'unused' ? `<form class="inline" method="post" action="/app/vouchers/${v.id}/status">${csrfField(c)}<input type="hidden" name="to" value="used"><button class="sec">${t('Mark used')}</button></form>` : ''}${v.eff === 'unused' ? `<form class="inline" method="post" action="/app/vouchers/${v.id}/status">${csrfField(c)}<input type="hidden" name="to" value="disabled"><button class="bad">${t('Disable')}</button></form>` : ''}</td></tr>`).join('') || `<tr><td colspan="4" class="mut">${t('No results')}</td></tr>`}</table></div>`, nav(req)));
  });
  app.post('/app/vouchers/:vid/status', needV, (req, res) => {
    const v = q1('SELECT * FROM vouchers WHERE id=? AND company_id=?', req.params.vid, req.user.company_id); if (!v) return res.sendStatus(404);
    const to = req.body.to, ok = { unused: ['sold', 'used', 'disabled'], sold: ['used'], expired: ['sold'] }[v.status] || [];
    if (!ok.includes(to)) return go(res, `/app/vouchers/batch/${v.batch_id}`, 'err', req.i.t('Invalid action'));
    run(`UPDATE vouchers SET status=?, ${to === 'used' ? "used_at=datetime('now')" : to === 'sold' ? "sold_at=datetime('now')" : 'used_at=used_at'} WHERE id=?`, to, v.id);
    audit(req, 'voucher_' + to, v.username); go(res, `/app/vouchers/batch/${v.batch_id}`, 'ok', req.i.t('Updated'));
  });
  app.post('/app/vouchers/batch/:id/disable', needV, (req, res) => {
    const b = getBatch(req, req.params.id); if (!b) return res.sendStatus(404);
    run("UPDATE vouchers SET status='disabled' WHERE batch_id=? AND status='unused'", b.id);
    audit(req, 'voucher_batch_disabled', `#${b.number}`); go(res, `/app/vouchers/batch/${b.id}`, 'ok', req.i.t('Updated'));
  });
  app.post('/app/vouchers/batch/:id/printed', needV, (req, res) => {
    const b = getBatch(req, req.params.id); if (!b) return res.sendStatus(404);
    run("UPDATE voucher_batches SET print_count=print_count+1, printed_at=datetime('now') WHERE id=?", b.id);
    audit(req, 'voucher_batch_printed', `#${b.number}`); go(res, `/app/vouchers/batch/${b.id}`, 'ok', req.i.t('Updated'));
  });
  app.get('/app/vouchers/batch/:id/export.csv', needV, (req, res) => {
    const b = getBatch(req, req.params.id); if (!b) return res.sendStatus(404);
    const cell = (s) => { let x = String(s ?? ''); if (/^[=+\-@]/.test(x)) x = "'" + x; return `"${x.replace(/"/g, '""')}"`; };
    const rows = q('SELECT * FROM vouchers WHERE batch_id=? ORDER BY id', b.id);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', `attachment; filename="batch-${b.number}.csv"`);
    audit(req, 'voucher_batch_exported', `#${b.number}`);
    res.send('\ufeff' + ['username,password,status,package,price', ...rows.map((v) => [v.username, v.password, vstatus(v, b), b.package_name, b.price].map(cell).join(','))].join('\n'));
  });
  app.get('/app/vouchers/batch/:id/print', needV, (req, res) => {
    const b = getBatch(req, req.params.id), t = req.i.t; if (!b) return res.sendStatus(404);
    ensureTemplates(b.company_id);
    const tp = q1('SELECT * FROM voucher_templates WHERE id=? AND company_id=?', Number(req.query.tpl) || 0, b.company_id) || q1('SELECT * FROM voucher_templates WHERE company_id=? ORDER BY is_default DESC, id LIMIT 1', b.company_id);
    const c = cfgOf(tp), L = layoutOf(c), co = getCo(b.company_id), cd = ctxd(co);
    if (L.per < 1) return go(res, `/app/vouchers/batch/${b.id}`, 'err', t('Card does not fit on the page'));
    const vs = q('SELECT * FROM vouchers WHERE batch_id=? AND status<>\'disabled\' ORDER BY id', b.id);
    const pages = []; for (let i = 0; i < vs.length; i += L.per) pages.push(vs.slice(i, i + L.per));
    const cardsHtml = (v) => `<div class="cell">${renderCard(c, { username: v.username, password: v.password, package: b.package_name, price: b.price ? `${b.price} ${co.currency || ''}` : '', validity: `${b.validity_days} ${t('days')}`, expires: b.expires_on }, cd, t)}</div>`;
    res.send(`<!doctype html><html dir="${req.i.rtl ? 'rtl' : 'ltr'}"><head><meta charset="utf-8"><title>Batch ${b.number}</title><style>
@page{size:${c.page_w}mm ${c.page_h}mm;margin:0}body{margin:0;background:#e5e7eb}.sheet{width:${c.page_w}mm;height:${c.page_h}mm;background:#fff;margin:0 auto 6mm;padding:${c.margin}mm;box-sizing:border-box;display:grid;grid-template-columns:repeat(${L.cols},${L.w}mm);grid-auto-rows:${L.h}mm;gap:${c.gap_v}mm ${c.gap_h}mm;align-content:start;justify-content:start;page-break-after:always;overflow:hidden}
.cell{${c.cut ? 'outline:0.15mm dashed #888;outline-offset:0.4mm;' : ''}}.bar{position:sticky;top:0;background:#0f172a;color:#fff;padding:8px 14px;font:14px Arial;display:flex;gap:12px;align-items:center}.bar button{padding:6px 14px}
@media print{body{background:#fff}.bar{display:none}.sheet{margin:0}}</style></head><body><div class="bar"><b>${esc(t('Batch'))} #${b.number}</b><span>${esc(tp.name)} - ${L.w}x${L.h} mm - ${L.per}/${esc(t('page'))} - ${vs.length} ${esc(t('Cards'))}</span><button onclick="window.print()">${esc(t('Print / Save as PDF'))}</button><a style="color:#93c5fd" href="/app/vouchers/batch/${b.id}">${esc(t('Back'))}</a></div>
${pages.map((p) => `<div class="sheet">${p.map(cardsHtml).join('')}</div>`).join('')}</body></html>`);
  });

  // ---------- templates / designer
  app.get('/app/vouchers/templates', needV, (req, res) => {
    const cid = req.user.company_id, t = req.i.t, c = ctx(req); ensureTemplates(cid);
    const rows = q('SELECT * FROM voucher_templates WHERE company_id=? ORDER BY is_default DESC, id', cid), co = getCo(cid);
    res.send(page(c, 'Card templates', `<div class="card"><div class="head"><h3>${t('Card templates')}</h3><div class="acts"><a class="btn" href="/app/vouchers/templates/new">${t('New template')}</a><a class="btn sec" href="/app/vouchers">${t('Back')}</a></div></div>
<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px;margin-top:12px">${rows.map((x) => `<div class="card" style="margin:0"><b>${esc(x.name)}</b> ${x.is_default ? badge('active', t) : ''}<div style="margin:10px 0;zoom:.9">${renderCard(cfgOf(x), sample(t), ctxd(co), t)}</div><a class="btn sec" href="/app/vouchers/templates/${x.id}">${t('Edit')}</a> ${x.is_default ? '' : `<form class="inline" method="post" action="/app/vouchers/templates/${x.id}/default">${csrfField(c)}<button class="sec">${t('Set as default')}</button></form>`}</div>`).join('')}</div></div>`, nav(req)));
  });
  function designer(req, res, tp) {
    const t = req.i.t, c = ctx(req), cfg = tp ? cfgOf(tp) : { ...DEFAULT_CFG }, co = getCo(req.user.company_id), L = layoutOf(cfg);
    const act = tp ? `/app/vouchers/templates/${tp.id}` : '/app/vouchers/templates';
    const num = (k, label, step = '0.1') => `<div><label>${t(label)}</label><input type="number" step="${step}" name="${k}" value="${esc(cfg[k])}"></div>`;
    const col = (k, label) => `<div><label>${t(label)}</label><input type="color" name="${k}" value="${esc(cfg[k])}"></div>`;
    res.send(page(c, 'Card designer', `<div class="card"><h3>${tp ? esc(tp.name) : t('New template')}</h3>
<div class="row2"><form id="df" method="post" action="${act}">${csrfField(c)}<input type="hidden" name="_f" value="1">
<div class="row">${field(t('Template name'), 'name', tp ? tp.name : '', { req: true })}${select(t('Unit'), 'unit', cfg.unit, [['mm', 'mm'], ['cm', 'cm'], ['px', 'px']])}${num('w', 'Card width')}${num('h', 'Card height')}${select(t('Orientation'), 'orient', cfg.orient, [['landscape', t('Landscape')], ['portrait', t('Portrait')]])}${select(t('Font'), 'font', cfg.font, FONTS.map((f) => [f, f]))}${num('size', 'Font size (pt)', '1')}${select(t('Font weight'), 'weight', cfg.weight, [['400', '400'], ['500', '500'], ['600', '600'], ['700', '700']])}${select(t('Text alignment'), 'align', cfg.align, [['left', t('Left')], ['center', t('Center')], ['right', t('Right')]])}
${col('bg', 'Background color')}${col('color', 'Text color')}${col('accent', 'Accent color')}${num('border', 'Border (mm)')}${num('radius', 'Rounded corners (mm)')}${num('logo_w', 'Logo width (mm)')}${num('logo_h', 'Logo height (mm)')}${select(t('Logo position'), 'logo_pos', cfg.logo_pos, [['top', t('Top')], ['left', t('Left')], ['right', t('Right')]])}</div>
<div class="row"><div><label>${t('Logo')}</label><input type="file" accept="image/*" onchange="mcImg(this,'logo')"><input type="hidden" name="logo" id="logo" value="${esc(cfg.logo)}">${cfg.logo ? `<label style="display:flex;gap:6px;color:var(--tx)"><input type="checkbox" style="width:auto" name="rm_logo" value="1"> ${t('Remove')}</label>` : ''}</div><div><label>${t('Background image')}</label><input type="file" accept="image/*" onchange="mcImg(this,'bg_image')"><input type="hidden" name="bg_image" id="bg_image" value="${esc(cfg.bg_image)}">${cfg.bg_image ? `<label style="display:flex;gap:6px;color:var(--tx)"><input type="checkbox" style="width:auto" name="rm_bg_image" value="1"> ${t('Remove')}</label>` : ''}</div></div>
<p>${[['show_net', 'Network name'], ['show_phone', 'Phone'], ['show_pkg', 'Package name'], ['show_price', 'Price'], ['show_exp', 'Expiration date'], ['show_valid', 'Validity period'], ['show_user', 'Username'], ['show_pass', 'Password'], ['show_qr', 'QR code'], ['cut', 'Cutting lines']].map(([k, l]) => chk(k, l, cfg[k], t)).join('')}</p>
${field(t('Custom text'), 'text', cfg.text)}
<h4>${t('Page layout')} (mm)</h4><div class="row">${num('page_w', 'Page width')}${num('page_h', 'Page height')}${num('margin', 'Margins')}${num('gap_h', 'Horizontal spacing')}${num('gap_v', 'Vertical spacing')}</div>
<p class="mut" id="per">${t('Cards per page')}: ${L.per} (${L.cols} x ${L.rows})</p>
<p><button>${t('Save')}</button> <a class="btn sec" href="/app/vouchers/templates">${t('Back')}</a></p></form>
<div><h4>${t('Live preview')}</h4><div id="pv" style="padding:10px;background:#e5e7eb;border-radius:10px;overflow:auto">${renderCard(cfg, sample(t), ctxd(co), t)}</div></div></div>
${tp ? `<form method="post" action="/app/vouchers/templates/${tp.id}/delete" onsubmit="return confirm('${t('Delete')}?')">${csrfField(c)}<button class="bad">${t('Delete')}</button></form>` : ''}</div>
<script>function mcImg(i,id){var f=i.files[0];if(!f)return;if(f.size>200000){alert('Max 200KB');i.value='';return}var r=new FileReader();r.onload=function(){document.getElementById(id).value=r.result;upd()};r.readAsDataURL(f)}
var tm;function upd(){clearTimeout(tm);tm=setTimeout(function(){var f=document.getElementById('df');fetch('/app/vouchers/templates/preview',{method:'POST',body:new URLSearchParams(new FormData(f)),headers:{'content-type':'application/x-www-form-urlencoded'},credentials:'same-origin'}).then(function(r){return r.json()}).then(function(j){document.getElementById('pv').innerHTML=j.html;document.getElementById('per').textContent=j.per}).catch(function(){})},200)}
document.getElementById('df').addEventListener('input',upd);document.getElementById('df').addEventListener('change',upd)</script>`, nav(req)));
  }
  app.get('/app/vouchers/templates/new', needV, (req, res) => designer(req, res, null));
  app.post('/app/vouchers/templates/preview', needV, (req, res) => {
    const t = req.i.t, cfg = normCfg({ ...req.body, _f: 1 }), L = layoutOf(cfg), co = getCo(req.user.company_id);
    res.json({ html: renderCard(cfg, sample(t), ctxd(co), t), per: `${t('Cards per page')}: ${L.per} (${L.cols} x ${L.rows})` });
  });
  app.get('/app/vouchers/templates/:id', needV, (req, res) => { const tp = getTpl(req, req.params.id); if (!tp) return res.status(404).send('Not found'); designer(req, res, tp); });
  app.post('/app/vouchers/templates', needV, (req, res) => {
    const t = req.i.t, name = clean(req.body.name, 80), cid = req.user.company_id; if (!name) return go(res, '/app/vouchers/templates/new', 'err', t('required'));
    const cfg = normCfg({ ...req.body, _f: 1 }); if (layoutOf(cfg).per < 1) return go(res, '/app/vouchers/templates/new', 'err', t('Card does not fit on the page'));
    run('INSERT INTO voucher_templates(company_id,name,is_default,config) VALUES(?,?,0,?)', cid, name, JSON.stringify(cfg)); audit(req, 'voucher_template_created', name); go(res, '/app/vouchers/templates', 'ok', t('Saved'));
  });
  app.post('/app/vouchers/templates/:id', needV, (req, res) => {
    const tp = getTpl(req, req.params.id), t = req.i.t; if (!tp) return res.sendStatus(404);
    const name = clean(req.body.name, 80); if (!name) return go(res, `/app/vouchers/templates/${tp.id}`, 'err', t('required'));
    const cfg = normCfg({ ...req.body, _f: 1 }, cfgOf(tp)); if (layoutOf(cfg).per < 1) return go(res, `/app/vouchers/templates/${tp.id}`, 'err', t('Card does not fit on the page'));
    run('UPDATE voucher_templates SET name=?, config=? WHERE id=?', name, JSON.stringify(cfg), tp.id); audit(req, 'voucher_template_updated', name); go(res, `/app/vouchers/templates/${tp.id}`, 'ok', t('Saved'));
  });
  app.post('/app/vouchers/templates/:id/default', needV, (req, res) => {
    const tp = getTpl(req, req.params.id); if (!tp) return res.sendStatus(404);
    run('UPDATE voucher_templates SET is_default=0 WHERE company_id=?', tp.company_id); run('UPDATE voucher_templates SET is_default=1 WHERE id=?', tp.id); go(res, '/app/vouchers/templates', 'ok', req.i.t('Updated'));
  });
  app.post('/app/vouchers/templates/:id/delete', needV, (req, res) => {
    const tp = getTpl(req, req.params.id); if (!tp) return res.sendStatus(404);
    if (tp.is_default) return go(res, `/app/vouchers/templates/${tp.id}`, 'err', req.i.t('Default template cannot be deleted'));
    run('DELETE FROM voucher_templates WHERE id=?', tp.id); go(res, '/app/vouchers/templates', 'ok', req.i.t('Deleted'));
  });
}
module.exports = { init, charset: null };
