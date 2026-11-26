'use strict';
const { esc, page, csrfField } = require('./views');

const today = () => new Date().toISOString().slice(0, 10);
const addDays = (d, n) => { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
const dateOk = (s) => (/^\d{4}-\d{2}-\d{2}$/.test(s || '') ? s : null);
const r2 = (n) => Math.round(Number(n || 0) * 100) / 100;
const monthsBack = (n) => { const out = []; const d = new Date(); d.setUTCDate(1); for (let i = n - 1; i >= 0; i--) { const x = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - i, 1)); out.push(x.toISOString().slice(0, 7)); } return out; };
const csvCell = (v) => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };

// ---------- inline SVG charts (no external libraries)
function barChart(labels, series, colors, names) {
  const W = 560, H = 220, pl = 44, pb = 28, pt = 14, pr = 8;
  const max = Math.max(1, ...series.flat());
  const gw = (W - pl - pr) / labels.length, bw = Math.min(26, (gw - 8) / series.length);
  let g = '';
  for (let k = 0; k <= 4; k++) { const y = pt + (H - pt - pb) * (1 - k / 4); g += `<line x1="${pl}" x2="${W - pr}" y1="${y}" y2="${y}" stroke="#e2e8f0"/><text x="${pl - 6}" y="${y + 4}" font-size="10" text-anchor="end" fill="#64748b">${Math.round(max * k / 4)}</text>`; }
  labels.forEach((l, i) => {
    series.forEach((s, j) => {
      const h = (H - pt - pb) * (s[i] / max), x = pl + gw * i + (gw - bw * series.length) / 2 + bw * j, y = H - pb - h;
      g += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${Math.max(0, h).toFixed(1)}" rx="3" fill="${colors[j]}"><title>${esc(names[j])} ${esc(l)}: ${s[i]}</title></rect>`;
    });
    g += `<text x="${(pl + gw * i + gw / 2).toFixed(1)}" y="${H - 8}" font-size="10" text-anchor="middle" fill="#64748b">${esc(l.slice(2))}</text>`;
  });
  const legend = names.map((n, j) => `<span style="display:inline-flex;align-items:center;gap:5px;margin-inline-end:14px;font-size:12px;color:#475569"><i style="width:10px;height:10px;border-radius:3px;background:${colors[j]}"></i>${esc(n)}</span>`).join('');
  return `<svg viewBox="0 0 ${W} ${H}" style="width:100%;max-width:640px;direction:ltr" role="img">${g}</svg><div>${legend}</div>`;
}
function hBars(rows, color = '#2563eb') {
  const max = Math.max(1, ...rows.map((r) => r[1]));
  return rows.length ? rows.map(([l, v]) => `<div style="display:grid;grid-template-columns:110px 1fr 56px;gap:8px;align-items:center;margin:6px 0;font-size:13px"><span style="color:#475569;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(l)}</span><div style="background:#e2e8f0;border-radius:6px;height:14px"><div style="width:${Math.max(2, (v / max) * 100).toFixed(1)}%;height:14px;border-radius:6px;background:${color}"></div></div><b style="text-align:end">${v}</b></div>`).join('') : '<p class="mut">-</p>';
}

function init(h) {
  const { app, q, q1, ctx, needAdmin, deny, nav, P } = h;
  const cur = (cid) => (q1('SELECT currency FROM companies WHERE id=?', cid) || {}).currency || 'EGP';
  const needR = [needAdmin, (req, res, next) => (P.hasModule(q1('SELECT * FROM companies WHERE id=?', req.user.company_id), 'reports') ? next() : deny(req, res))];

  function monthly(cid, n) {
    const ms = monthsBack(n), from = ms[0] + '-01';
    const rev = Object.fromEntries(q("SELECT substr(created_at,1,7) m, SUM(amount) s FROM cust_payments WHERE company_id=? AND created_at>=? GROUP BY 1", cid, from).map((r) => [r.m, r2(r.s)]));
    const exp = Object.fromEntries(q("SELECT substr(spent_on,1,7) m, SUM(amount) s FROM expenses WHERE company_id=? AND spent_on>=? GROUP BY 1", cid, from).map((r) => [r.m, r2(r.s)]));
    return { ms, rev: ms.map((m) => rev[m] || 0), exp: ms.map((m) => exp[m] || 0) };
  }

  // alerts computed live from existing data (no extra tables, nothing to keep in sync)
  function alerts(cid, t) {
    const td = today(), in7 = addDays(td, 7), out = [];
    const soon = q("SELECT id, full_name, sub_end FROM customers WHERE company_id=? AND status='active' AND sub_end>=? AND sub_end<=? ORDER BY sub_end LIMIT 50", cid, td, in7);
    const expired = q1("SELECT count(*) n FROM customers WHERE company_id=? AND status='active' AND sub_end IS NOT NULL AND sub_end<?", cid, td).n;
    const od = q1("SELECT count(*) n FROM cust_invoices WHERE company_id=? AND status<>'paid' AND status<>'void' AND period_end<?", cid, td).n;
    const pend = q1("SELECT count(*) n FROM payments WHERE company_id=? AND status='pending'", cid);
    if (soon.length) out.push({ k: 'warn', title: `${t('Expiring within 7 days')}: ${soon.length}`, items: soon.map((c) => ({ href: `/app/customers/${c.id}`, text: `${c.full_name} - ${t('Ends')} ${c.sub_end}` })) });
    if (expired) out.push({ k: 'bad', title: `${t('Expired subscriptions')}: ${expired}`, items: [] , href: '/app/customers?status=active' });
    if (od) out.push({ k: 'bad', title: `${t('Overdue invoices')}: ${od}`, items: [], href: '/app/finance' });
    if (pend && pend.n) out.push({ k: 'info', title: `${t('Pending payment approvals')}: ${pend.n}`, items: [], href: '/app/subscription' });
    try {
      const co = q1('SELECT * FROM companies WHERE id=?', cid), lim = P.limitsOf(co), use = P.usageOf(cid);
      for (const k of Object.keys(lim || {})) { const l = lim[k], u = use[k]; if (l && l > 0 && u >= l * 0.8) out.push({ k: u >= l ? 'bad' : 'warn', title: `${t('Plan limit nearly reached')}: ${t(P.LIMITS.find((x) => x[0] === k)?.[1] || k)} ${u}/${l}`, items: [], href: '/app/subscription' }); }
    } catch (e) { /* limits are optional here */ }
    return out;
  }
  const alertHtml = (a) => a.map((x) => `<div class="flash ${x.k === 'bad' ? 'err' : x.k === 'warn' ? 'warn' : 'ok'}" style="margin:8px 0"><b>${x.href ? `<a href="${x.href}">${esc(x.title)}</a>` : esc(x.title)}</b>${x.items.length ? '<ul style="margin:6px 0 0;padding-inline-start:20px">' + x.items.map((i) => `<li><a href="${i.href}">${esc(i.text)}</a></li>`).join('') + '</ul>' : ''}</div>`).join('');

  function dashboard(req) {
    const t = req.i.t, cid = req.user.company_id, co = cur(cid);
    const m = monthly(cid, 6);
    const total = (a) => r2(a.reduce((x, y) => x + y, 0));
    const st = q('SELECT status, count(*) n FROM customers WHERE company_id=? GROUP BY status', cid).map((r) => [r.status === 'active' ? t('Active') : t('Suspended'), Number(r.n)]);
    const sv = q('SELECT service_type, count(*) n FROM customers WHERE company_id=? GROUP BY service_type', cid).map((r) => [String(r.service_type || '').toUpperCase(), Number(r.n)]);
    const meth = q('SELECT method, SUM(amount) s FROM cust_payments WHERE company_id=? GROUP BY method ORDER BY 2 DESC', cid).map((r) => [r.method, r2(r.s)]);
    const al = alerts(cid, t);
    const stat = (v, l) => `<div class="stat"><b>${esc(v)}</b><span>${t(l)}</span></div>`;
    return `<div class="grid" style="margin-top:12px">${stat(total(m.rev) + ' ' + co, 'Revenue')}${stat(total(m.exp) + ' ' + co, 'Expenses')}${stat(r2(total(m.rev) - total(m.exp)) + ' ' + co, 'Net profit')}</div><p class="mut" style="margin:4px 0">${t('Last 6 months')}</p>
${al.length ? `<div class="card"><h3>${t('Notifications')}</h3>${alertHtml(al)}</div>` : ''}
<div class="card"><h3>${t('Revenue vs expenses')}</h3>${barChart(m.ms, [m.rev, m.exp], ['#2563eb', '#f59e0b'], [t('Revenue'), t('Expenses')])}</div>
<div class="grid"><div class="card"><h3>${t('Customers by status')}</h3>${hBars(st, '#16a34a')}</div><div class="card"><h3>${t('Customers by service')}</h3>${hBars(sv, '#7c3aed')}</div><div class="card"><h3>${t('Collections by method')}</h3>${hBars(meth, '#2563eb')}</div></div>`;
  }

  app.get('/app/notifications', needAdmin, (req, res) => {
    const t = req.i.t, c = ctx(req), al = alerts(req.user.company_id, t);
    res.send(page(c, 'Notifications', `<div class="card"><h3>${t('Notifications')}</h3>${al.length ? alertHtml(al) : `<p class="mut">${t('No notifications')}</p>`}</div>`, nav(req)));
  });

  function range(req) {
    const to = dateOk(req.query.to) || today(), from = dateOk(req.query.from) || addDays(to, -89);
    return { from, to, toX: addDays(to, 1) };
  }
  function data(cid, r) {
    const byMonth = {};
    const bump = (m, k, v) => { (byMonth[m] = byMonth[m] || { rev: 0, exp: 0, inv: 0, cust: 0, cards: 0 })[k] += v; };
    q('SELECT substr(created_at,1,7) m, SUM(amount) s FROM cust_payments WHERE company_id=? AND created_at>=? AND created_at<? GROUP BY 1', cid, r.from, r.toX).forEach((x) => bump(x.m, 'rev', r2(x.s)));
    q('SELECT substr(spent_on,1,7) m, SUM(amount) s FROM expenses WHERE company_id=? AND spent_on>=? AND spent_on<=? GROUP BY 1', cid, r.from, r.to).forEach((x) => bump(x.m, 'exp', r2(x.s)));
    q('SELECT substr(created_at,1,7) m, count(*) n FROM cust_invoices WHERE company_id=? AND created_at>=? AND created_at<? GROUP BY 1', cid, r.from, r.toX).forEach((x) => bump(x.m, 'inv', Number(x.n)));
    q('SELECT substr(created_at,1,7) m, count(*) n FROM customers WHERE company_id=? AND created_at>=? AND created_at<? GROUP BY 1', cid, r.from, r.toX).forEach((x) => bump(x.m, 'cust', Number(x.n)));
    q("SELECT substr(created_at,1,7) m, count(*) n FROM vouchers WHERE company_id=? AND status IN ('sold','used') AND created_at>=? AND created_at<? GROUP BY 1", cid, r.from, r.toX).forEach((x) => bump(x.m, 'cards', Number(x.n)));
    const months = Object.keys(byMonth).sort();
    const byPkg = q('SELECT i.package_name p, count(*) n, SUM(i.amount-i.discount) s FROM cust_invoices i WHERE i.company_id=? AND i.created_at>=? AND i.created_at<? GROUP BY 1 ORDER BY 3 DESC', cid, r.from, r.toX).map((x) => ({ p: x.p || '-', n: Number(x.n), s: r2(x.s) }));
    const byMethod = q('SELECT method m, count(*) n, SUM(amount) s FROM cust_payments WHERE company_id=? AND created_at>=? AND created_at<? GROUP BY 1 ORDER BY 3 DESC', cid, r.from, r.toX).map((x) => ({ m: x.m, n: Number(x.n), s: r2(x.s) }));
    const sum = (k) => r2(months.reduce((a, m) => a + byMonth[m][k], 0));
    return { months, byMonth, byPkg, byMethod, rev: sum('rev'), exp: sum('exp') };
  }

  app.get('/app/reports', needR, (req, res) => {
    const t = req.i.t, c = ctx(req), cid = req.user.company_id, co = cur(cid), r = range(req), d = data(cid, r);
    const qs = `from=${r.from}&to=${r.to}`;
    const tbl = (head, rows) => `<div class="tbl"><table><tr>${head.map((x) => `<th>${esc(x)}</th>`).join('')}</tr>${rows.map((x) => `<tr>${x.map((y) => `<td>${esc(y)}</td>`).join('')}</tr>`).join('') || `<tr><td colspan="${head.length}" class="mut">-</td></tr>`}</table></div>`;
    const stat = (v, l) => `<div class="stat"><b>${esc(v)}</b><span>${t(l)}</span></div>`;
    res.send(page(c, 'Reports', `<div class="card"><h3>${t('Reports')}</h3><form method="get" class="row"><label>${t('From')}<input type="date" name="from" value="${r.from}"></label><label>${t('To')}<input type="date" name="to" value="${r.to}"></label><button>${t('Apply')}</button></form></div>
<div class="grid">${stat(d.rev + ' ' + co, 'Revenue')}${stat(d.exp + ' ' + co, 'Expenses')}${stat(r2(d.rev - d.exp) + ' ' + co, 'Net profit')}</div>
${d.months.length ? `<div class="card"><h3>${t('Revenue vs expenses')}</h3>${barChart(d.months, [d.months.map((m) => d.byMonth[m].rev), d.months.map((m) => d.byMonth[m].exp)], ['#2563eb', '#f59e0b'], [t('Revenue'), t('Expenses')])}</div>` : ''}
<div class="card"><h3>${t('By month')} <a class="btn sec" href="/app/reports/export.csv?${qs}&type=month">${t('Export CSV')}</a></h3>${tbl([t('Month'), t('Revenue'), t('Expenses'), t('Net profit'), t('Invoices issued'), t('New customers'), t('Cards sold')], d.months.map((m) => { const x = d.byMonth[m]; return [m, x.rev, x.exp, r2(x.rev - x.exp), x.inv, x.cust, x.cards]; }))}</div>
<div class="card"><h3>${t('By package')} <a class="btn sec" href="/app/reports/export.csv?${qs}&type=package">${t('Export CSV')}</a></h3>${tbl([t('Package'), t('Count'), t('Amount')], d.byPkg.map((x) => [x.p, x.n, x.s]))}</div>
<div class="card"><h3>${t('By payment method')} <a class="btn sec" href="/app/reports/export.csv?${qs}&type=method">${t('Export CSV')}</a></h3>${tbl([t('Method'), t('Count'), t('Amount')], d.byMethod.map((x) => [x.m, x.n, x.s]))}</div>`, nav(req)));
  });

  app.get('/app/reports/export.csv', needR, (req, res) => {
    const cid = req.user.company_id, r = range(req), d = data(cid, r), type = req.query.type;
    let rows;
    if (type === 'package') rows = [['package', 'count', 'amount'], ...d.byPkg.map((x) => [x.p, x.n, x.s])];
    else if (type === 'method') rows = [['method', 'count', 'amount'], ...d.byMethod.map((x) => [x.m, x.n, x.s])];
    else rows = [['month', 'revenue', 'expenses', 'net', 'invoices', 'new_customers', 'cards_sold'], ...d.months.map((m) => { const x = d.byMonth[m]; return [m, x.rev, x.exp, r2(x.rev - x.exp), x.inv, x.cust, x.cards]; })];
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="report-${type === 'package' || type === 'method' ? type : 'month'}-${r.from}_${r.to}.csv"`);
    res.send('\ufeff' + rows.map((x) => x.map(csvCell).join(',')).join('\r\n') + '\r\n');
  });

  return { dashboard, alerts };
}
module.exports = { init };
