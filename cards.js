'use strict';
// Cards section (client panel): overview, list, expired, sales reports, distributors.
// Data = our own voucher tables. Router column = read-only read-back from the hotspot list sync.
const { esc, page, csrfField, field, select } = require('./views');

const clean = (v, max = 300) => String(v ?? '').trim().slice(0, max);
const today = () => new Date().toISOString().slice(0, 10);
const day = (s) => String(s || '').slice(0, 10);
const DATE = /^\d{4}-\d{2}-\d{2}$/;

function effStatus(v, b) {
  if (v.status === 'disabled') return 'disabled';
  if (v.status === 'used') return 'used';
  if (b.expires_on && b.expires_on < today()) return 'expired';
  return v.status; // unused | sold
}
function reasonOf(v, b, t) {
  const s = effStatus(v, b);
  if (s === 'expired') return `${t('Validity date passed')}: ${b.expires_on}`;
  if (s === 'disabled') return t('Disabled manually in the panel');
  if (s === 'used') return t('Marked as used');
  return '';
}

function init(h) {
  const { app, q, q1, run, audit, ctx, go, deny, needAdmin, nav, P } = h;
  const needV = [needAdmin, (req, res, next) => (P.hasModule(q1('SELECT * FROM companies WHERE id=?', req.user.company_id), 'vouchers') ? next() : deny(req, res, 'module'))];
  const getCo = (cid) => q1('SELECT * FROM companies WHERE id=?', cid);

  function load(cid) {
    const bs = {}; for (const b of q('SELECT * FROM voucher_batches WHERE company_id=?', cid)) bs[b.id] = b;
    const ds = {}; for (const d of q('SELECT * FROM distributors WHERE company_id=? ORDER BY name', cid)) ds[d.id] = d;
    const rt = {}; for (const r of q("SELECT name, disabled, uptime, device_id FROM router_items WHERE company_id=? AND kind='hs_user'", cid)) rt[r.name] = r;
    const hasRouter = Object.keys(rt).length > 0;
    const rows = q('SELECT * FROM vouchers WHERE company_id=? ORDER BY id DESC', cid).map((v) => {
      const b = bs[v.batch_id] || {}, eff = effStatus(v, b), r = rt[v.username];
      return { ...v, b, eff, dist: ds[b.distributor_id] || null, price: Number(b.price) || 0, router: !hasRouter ? '' : !r ? 'missing' : r.disabled ? 'disabled' : (r.uptime && r.uptime !== '0s' ? 'seen' : 'present') };
    });
    return { rows, bs, ds, hasRouter };
  }
  const sold = (v) => v.status === 'sold' || v.status === 'used';
  const saleDay = (v) => day(v.sold_at || v.used_at || v.created_at);
  const money = (n, co) => `${Math.round(n * 100) / 100} ${esc(co.currency || '')}`;
  const kpi = (v, l, t, color) => `<div class="stat"${color ? ` style="border-top:4px solid ${color}"` : ''}><b>${v}</b><span>${t(l)}</span></div>`;
  const bars = (data, color) => {
    const max = Math.max(1, ...data.map((d) => d[1]));
    return `<div style="direction:ltr">${data.map(([l, v, lab]) => `<div style="display:flex;align-items:center;gap:8px;margin:4px 0;font-size:13px"><span style="width:110px;text-align:end;color:var(--mut);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(l)}</span><div style="flex:1;background:#f1f5f9;border-radius:6px;height:18px"><div style="width:${Math.round(v / max * 100)}%;min-width:${v ? 3 : 0}px;height:18px;border-radius:6px;background:${color}"></div></div><b style="width:90px">${esc(lab ?? v)}</b></div>`).join('') || '<span class="mut">-</span>'}</div>`;
  };
  const lastDays = (n) => { const o = []; for (let i = n - 1; i >= 0; i--) o.push(new Date(Date.now() - i * 864e5).toISOString().slice(0, 10)); return o; };
  const statusBadge = (s, t) => `<span class="badge ${s === 'sold' || s === 'unused' ? 'active' : s === 'expired' || s === 'disabled' ? 'expired' : ''}">${esc(t(s[0].toUpperCase() + s.slice(1)))}</span>`;
  const routerBadge = (r, t) => (!r ? '<span class="mut">-</span>' : `<span class="badge ${r === 'missing' ? 'expired' : r === 'disabled' ? 'suspended' : 'active'}">${esc(t({ missing: 'Not on router', disabled: 'Disabled on router', seen: 'Seen on router', present: 'On router' }[r]))}</span>`);

  function summary(rows) {
    const c = (k) => rows.filter((v) => v.eff === k).length, s = rows.filter(sold);
    return { total: rows.length, unused: c('unused'), sold: c('sold'), used: c('used'), expired: c('expired'), disabled: c('disabled'), active: c('unused') + c('sold'), soldCount: s.length, soldValue: s.reduce((a, v) => a + v.price, 0), unsoldValue: rows.filter((v) => v.eff === 'unused').reduce((a, v) => a + v.price, 0) };
  }

  app.get('/app/cards', needV, (req, res) => {
    const cid = req.user.company_id, t = req.i.t, c = ctx(req), co = getCo(cid), { rows, hasRouter } = load(cid), s = summary(rows);
    const days = lastDays(14), byDay = {}; for (const v of rows.filter(sold)) { const d = saleDay(v); byDay[d] = (byDay[d] || 0) + v.price; }
    const byPkg = {}; for (const v of rows.filter(sold)) { const k = v.b.package_name || '-'; byPkg[k] = (byPkg[k] || 0) + v.price; }
    const byDist = {}; for (const v of rows.filter(sold)) { const k = v.dist ? v.dist.name : t('No distributor'); byDist[k] = (byDist[k] || 0) + v.price; }
    const lim = new Date(Date.now() + 7 * 864e5).toISOString().slice(0, 10);
    const near = rows.filter((v) => v.b.expires_on && (v.eff === 'unused' || v.eff === 'sold') && v.b.expires_on <= lim).length;
    res.send(page(c, 'Cards', `<div class="head" style="margin-bottom:14px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px"><h3>${t('Cards')}</h3><div class="acts"><a class="btn" style="color:#fff" href="/app/vouchers">${t('Create cards')}</a> <a class="btn sec" href="/app/cards/list">${t('All cards')}</a> <a class="btn sec" href="/app/cards/sales">${t('Sales reports')}</a> <a class="btn sec" href="/app/cards/distributors">${t('Distributors')}</a></div></div>
<div class="grid">${kpi(s.total, 'Total cards', t)}${kpi(s.active, 'Active cards', t, '#16a34a')}${kpi(s.unused, 'Unused', t)}${kpi(s.soldCount, 'Sold cards', t, '#2563eb')}${kpi(s.used, 'Used', t)}${kpi(s.expired, 'Expired', t, '#dc2626')}${kpi(s.disabled, 'Disabled', t)}${kpi(near, 'Expiring in 7 days', t, '#d97706')}</div>
<div class="grid" style="margin-top:12px">${kpi(money(s.soldValue, co), 'Sales value', t, '#16a34a')}${kpi(money(s.unsoldValue, co), 'Unsold stock value', t)}</div>
<div class="row2" style="margin-top:16px"><div class="card"><h3>${t('Sales in the last 14 days')}</h3>${bars(days.map((d) => [d.slice(5), byDay[d] || 0, byDay[d] ? money(byDay[d], co) : '']), '#16a34a')}</div>
<div class="card"><h3>${t('Sales by package')}</h3>${bars(Object.entries(byPkg).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => [k, v, money(v, co)]), '#2563eb')}</div></div>
<div class="card"><h3>${t('Sales by distributor')}</h3>${bars(Object.entries(byDist).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => [k, v, money(v, co)]), '#7c3aed')}</div>
<p class="mut">${hasRouter ? t('The Router column is read from the last hotspot list sync. It is display only and does not change card status.') : t('No hotspot list has been synced from a router yet, so router status is not shown. Sold/used are recorded by you.')}</p>`, nav(req)));
  });

  const FILTERS = [['', 'All'], ['active', 'Active'], ['unused', 'Unused'], ['sold', 'Sold'], ['used', 'Used'], ['expired', 'Expired'], ['disabled', 'Disabled']];
  function pick(rows, f) {
    if (f === 'active') return rows.filter((v) => v.eff === 'unused' || v.eff === 'sold');
    if (['unused', 'sold', 'used', 'expired', 'disabled'].includes(f)) return rows.filter((v) => v.eff === f);
    return rows;
  }
  function listPage(req, res, forced) {
    const cid = req.user.company_id, t = req.i.t, c = ctx(req), co = getCo(cid), { rows, bs, ds, hasRouter } = load(cid);
    const f = forced || clean(req.query.f, 12), sq = clean(req.query.q, 40).toLowerCase(), bf = Number(req.query.batch) || 0, df = Number(req.query.dist) || 0, pf = clean(req.query.pkg, 80);
    let vs = pick(rows, f);
    if (sq) vs = vs.filter((v) => v.username.toLowerCase().includes(sq));
    if (bf) vs = vs.filter((v) => v.batch_id === bf);
    if (df) vs = vs.filter((v) => v.b.distributor_id === df);
    if (pf) vs = vs.filter((v) => v.b.package_name === pf);
    const total = vs.length, pg = Math.max(1, parseInt(req.query.page, 10) || 1), per = 50, shown = vs.slice((pg - 1) * per, pg * per);
    const pkgs = [...new Set(rows.map((v) => v.b.package_name).filter(Boolean))];
    const qs = (o) => '?' + new URLSearchParams({ ...(forced ? {} : { f }), q: sq, batch: bf || '', dist: df || '', pkg: pf, ...o }).toString();
    const base = forced ? '/app/cards/expired' : '/app/cards/list';
    const title = forced === 'expired' ? 'Expired cards' : 'All cards';
    const exp = f === 'expired';
    res.send(page(c, title, `<div class="card"><div class="head" style="margin-bottom:14px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px"><h3>${t(title)} (${total})</h3><div class="acts"><a class="btn sec" href="${base}/export.csv${qs({})}">CSV</a> <a class="btn" style="color:#fff" href="/app/vouchers">${t('Create cards')}</a></div></div>
<form method="get" action="${base}" class="row">${forced ? '' : select(t('Status'), 'f', f, FILTERS.map(([k, l]) => [k, t(l)]))}${select(t('Package name'), 'pkg', pf, [['', t('All')], ...pkgs.map((p) => [p, p])])}${select(t('Batch'), 'batch', String(bf || ''), [['', t('All')], ...Object.values(bs).sort((a, b) => b.number - a.number).map((b) => [String(b.id), '#' + b.number])])}${select(t('Distributor'), 'dist', String(df || ''), [['', t('All')], ...Object.values(ds).map((d) => [String(d.id), d.name])])}${field(t('Search'), 'q', sq)}<div style="padding-top:22px"><button>${t('Search')}</button></div></form></div>
<div class="card tbl"><table><tr><th>${t('Username')}</th><th>${t('Password')}</th><th>${t('Package name')}</th><th>${t('Batch')}</th><th>${t('Price')}</th><th>${t('Distributor')}</th><th>${t('Status')}</th>${exp ? `<th>${t('Reason')}</th>` : ''}<th>${t('Valid until')}</th>${hasRouter ? `<th>${t('Router')}</th>` : ''}</tr>
${shown.map((v) => `<tr><td><code>${esc(v.username)}</code></td><td><code>${esc(v.password)}</code></td><td>${esc(v.b.package_name || '')}</td><td><a href="/app/vouchers/batch/${v.batch_id}">#${esc(v.b.number)}</a></td><td>${v.price ? money(v.price, co) : '-'}</td><td>${v.dist ? esc(v.dist.name) : '<span class="mut">-</span>'}</td><td>${statusBadge(v.eff, t)}</td>${exp ? `<td>${esc(reasonOf(v, v.b, t))}</td>` : ''}<td>${esc(v.b.expires_on || '-')}</td>${hasRouter ? `<td>${routerBadge(v.router, t)}</td>` : ''}</tr>`).join('') || `<tr><td colspan="10" class="mut">${t('No results')}</td></tr>`}</table>
<div class="pager">${pg > 1 ? `<a class="btn sec" href="${base}${qs({ page: pg - 1 })}">&laquo;</a>` : ''}<span class="mut">${pg} / ${Math.max(1, Math.ceil(total / per))}</span>${pg * per < total ? `<a class="btn sec" href="${base}${qs({ page: pg + 1 })}">&raquo;</a>` : ''}</div></div>`, nav(req)));
  }
  app.get('/app/cards/list', needV, (req, res) => listPage(req, res, ''));
  app.get('/app/cards/expired', needV, (req, res) => listPage(req, res, 'expired'));
  const cell = (s) => { let x = String(s ?? ''); if (/^[=+\-@]/.test(x)) x = "'" + x; return `"${x.replace(/"/g, '""')}"`; };
  function csv(req, res, forced) {
    const { rows } = load(req.user.company_id), f = forced || clean(req.query.f, 12), t = req.i.t, vs = pick(rows, f);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', 'attachment; filename="cards.csv"');
    audit(req, 'cards_exported', f || 'all');
    res.send('\ufeff' + ['username,password,package,batch,price,distributor,status,reason,valid_until', ...vs.map((v) => [v.username, v.password, v.b.package_name, v.b.number, v.price, v.dist ? v.dist.name : '', v.eff, reasonOf(v, v.b, t), v.b.expires_on].map(cell).join(','))].join('\n'));
  }
  app.get('/app/cards/list/export.csv', needV, (req, res) => csv(req, res, ''));
  app.get('/app/cards/expired/export.csv', needV, (req, res) => csv(req, res, 'expired'));

  function salesOf(req) {
    const { rows, ds } = load(req.user.company_id);
    const from = DATE.test(req.query.from || '') ? req.query.from : new Date(Date.now() - 29 * 864e5).toISOString().slice(0, 10), to = DATE.test(req.query.to || '') ? req.query.to : today(), df = Number(req.query.dist) || 0;
    let vs = rows.filter(sold).filter((v) => saleDay(v) >= from && saleDay(v) <= to); if (df) vs = vs.filter((v) => v.b.distributor_id === df);
    return { vs, ds, from, to, df };
  }
  app.get('/app/cards/sales', needV, (req, res) => {
    const cid = req.user.company_id, t = req.i.t, c = ctx(req), co = getCo(cid), { vs, ds, from, to, df } = salesOf(req);
    const grp = (keyFn) => { const m = {}; for (const v of vs) { const k = keyFn(v); (m[k] = m[k] || { n: 0, val: 0 }); m[k].n++; m[k].val += v.price; } return Object.entries(m); };
    const byDay = grp(saleDay).sort(), byPkg = grp((v) => v.b.package_name || '-').sort((a, b) => b[1].val - a[1].val), byDist = grp((v) => (v.dist ? v.dist.name : t('No distributor'))).sort((a, b) => b[1].val - a[1].val);
    const tot = vs.reduce((a, v) => a + v.price, 0);
    const tbl = (head, data, col) => `<div class="card tbl"><h3>${t(head)}</h3><table><tr><th>${t(col)}</th><th>${t('Cards sold')}</th><th>${t('Sales value')}</th></tr>${data.map(([k, o]) => `<tr><td>${esc(k)}</td><td>${o.n}</td><td>${money(o.val, co)}</td></tr>`).join('') || `<tr><td colspan="3" class="mut">${t('No results')}</td></tr>`}</table></div>`;
    res.send(page(c, 'Sales reports', `<div class="card"><h3>${t('Sales reports')}</h3><form method="get" class="row">${field(t('From'), 'from', from, { type: 'date' })}${field(t('To'), 'to', to, { type: 'date' })}${select(t('Distributor'), 'dist', String(df || ''), [['', t('All')], ...Object.values(ds).map((d) => [String(d.id), d.name])])}<div style="padding-top:22px"><button>${t('Search')}</button> <a class="btn sec" href="/app/cards/sales/export.csv?from=${from}&to=${to}&dist=${df || ''}">CSV</a></div></form>
<div class="grid" style="margin-top:12px">${kpi(vs.length, 'Cards sold', t, '#2563eb')}${kpi(money(tot, co), 'Sales value', t, '#16a34a')}${kpi(vs.length ? money(tot / vs.length, co) : '-', 'Average per card', t)}</div>
<p class="mut">${t('Sales are the cards you marked as sold or used. The value is the package price of the batch.')}</p></div>
<div class="card"><h3>${t('By day')}</h3>${bars(byDay.map(([k, o]) => [k.slice(5), o.val, money(o.val, co)]), '#16a34a')}</div>
<div class="row2">${tbl('By package', byPkg, 'Package name')}${tbl('By distributor', byDist, 'Distributor')}</div>${tbl('By day', byDay, 'Date')}`, nav(req)));
  });
  app.get('/app/cards/sales/export.csv', needV, (req, res) => {
    const { vs, from, to } = salesOf(req);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', 'attachment; filename="card-sales.csv"');
    audit(req, 'card_sales_exported', `${from}..${to}`);
    res.send('\ufeff' + ['date,username,package,batch,price,distributor,status', ...vs.map((v) => [saleDay(v), v.username, v.b.package_name, v.b.number, v.price, v.dist ? v.dist.name : '', v.eff].map(cell).join(','))].join('\n'));
  });

  const getDist = (req, id) => q1('SELECT * FROM distributors WHERE id=? AND company_id=?', id, req.user.company_id);
  app.get('/app/cards/distributors', needV, (req, res) => {
    const cid = req.user.company_id, t = req.i.t, c = ctx(req), co = getCo(cid), { rows, ds } = load(cid);
    const st = {}; for (const d of Object.values(ds)) st[d.id] = { n: 0, sold: 0, val: 0 };
    for (const v of rows) { const s = st[v.b.distributor_id]; if (s) { s.n++; if (sold(v)) { s.sold++; s.val += v.price; } } }
    const nb = {}; for (const b of q('SELECT distributor_id, count(*) n FROM voucher_batches WHERE company_id=? GROUP BY distributor_id', cid)) nb[b.distributor_id] = b.n;
    res.send(page(c, 'Distributors', `<div class="card tbl"><h3>${t('Distributors')}</h3><table><tr><th>${t('Name')}</th><th>${t('Phone')}</th><th>${t('Batches')}</th><th>${t('Cards')}</th><th>${t('Cards sold')}</th><th>${t('Sales value')}</th><th></th></tr>
${Object.values(ds).map((d) => `<tr><td>${esc(d.name)}${d.note ? `<br><small class="mut">${esc(d.note)}</small>` : ''}</td><td>${esc(d.phone || '-')}</td><td>${nb[d.id] || 0}</td><td>${st[d.id].n}</td><td>${st[d.id].sold}</td><td>${money(st[d.id].val, co)}</td><td><a href="/app/cards/list?dist=${d.id}">${t('View')}</a> <form class="inline" method="post" action="/app/cards/distributors/${d.id}/delete" onsubmit="return confirm('${t('Delete')}?')">${csrfField(c)}<button class="bad">${t('Delete')}</button></form></td></tr>`).join('') || `<tr><td colspan="7" class="mut">${t('No results')}</td></tr>`}</table></div>
<div class="card"><h3>${t('Add distributor')}</h3><form method="post" action="/app/cards/distributors">${csrfField(c)}<div class="row">${field(t('Name'), 'name', '', { req: true })}${field(t('Phone'), 'phone', '')}${field(t('Notes'), 'note', '')}</div><p><button>${t('Add')}</button></p></form>
<p class="mut">${t('Choose the distributor when you create a batch of cards. A distributor with batches cannot be deleted.')}</p></div>`, nav(req)));
  });
  app.post('/app/cards/distributors', needV, (req, res) => {
    const t = req.i.t, cid = req.user.company_id, name = clean(req.body.name, 80), back = '/app/cards/distributors';
    if (!name) return go(res, back, 'err', t('required'));
    if (q1('SELECT 1 x FROM distributors WHERE company_id=? AND lower(name)=lower(?)', cid, name)) return go(res, back, 'err', t('Already exists'));
    if (q1('SELECT count(*) n FROM distributors WHERE company_id=?', cid).n >= 200) return go(res, back, 'err', t('Limit reached'));
    run('INSERT INTO distributors(company_id,name,phone,note) VALUES(?,?,?,?)', cid, name, clean(req.body.phone, 40), clean(req.body.note, 200));
    audit(req, 'distributor_added', name); go(res, back, 'ok', t('Saved'));
  });
  app.post('/app/cards/distributors/:id/delete', needV, (req, res) => {
    const t = req.i.t, d = getDist(req, req.params.id), back = '/app/cards/distributors'; if (!d) return res.sendStatus(404);
    if (q1('SELECT count(*) n FROM voucher_batches WHERE company_id=? AND distributor_id=?', d.company_id, d.id).n) return go(res, back, 'err', t('This distributor has batches and cannot be deleted'));
    run('DELETE FROM distributors WHERE id=?', d.id); audit(req, 'distributor_deleted', d.name); go(res, back, 'ok', t('Deleted'));
  });
  app.post('/app/vouchers/batch/:id/distributor', needV, (req, res) => {
    const t = req.i.t, b = q1('SELECT * FROM voucher_batches WHERE id=? AND company_id=?', req.params.id, req.user.company_id); if (!b) return res.sendStatus(404);
    const did = Number(req.body.distributor_id) || 0;
    if (did && !getDist(req, did)) return go(res, `/app/vouchers/batch/${b.id}`, 'err', t('Invalid'));
    run('UPDATE voucher_batches SET distributor_id=? WHERE id=?', did, b.id); audit(req, 'batch_distributor', `#${b.number}`); go(res, `/app/vouchers/batch/${b.id}`, 'ok', t('Updated'));
  });
  return { summary: (cid) => summary(load(cid).rows) };
}
module.exports = { init, effStatus };
