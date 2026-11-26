'use strict';
const { esc, page, csrfField, badge, field, select, infoGrid } = require('./views');

const clean = (v, max = 300) => String(v ?? '').trim().slice(0, max);
const num = (v, def = 0, min = 0, max = 1e9) => { const n = Number(v); return Number.isFinite(n) && n >= min && n <= max ? Math.round(n * 100) / 100 : def; };
const today = () => new Date().toISOString().slice(0, 10);
const addDays = (d, n) => { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
const METHODS = ['cash', 'bank_transfer', 'mobile_wallet', 'other'];
const money = (n, cur) => `${Number(n).toFixed(2).replace(/\.00$/, '')} ${cur || 'EGP'}`;

function init(h) {
  const { app, q, q1, run, audit, ctx, go, needAdmin, nav } = h;
  const cur = (cid) => (q1('SELECT currency FROM companies WHERE id=?', cid) || {}).currency || 'EGP';
  const paidOf = (id) => q1("SELECT COALESCE(SUM(amount),0) s FROM cust_payments WHERE invoice_id=?", id).s;
  const dueOf = (inv) => Math.max(0, Math.round((inv.amount - inv.discount - paidOf(inv.id)) * 100) / 100);
  const getPkg = (req, id) => q1('SELECT * FROM packages WHERE id=? AND company_id=?', id, req.user.company_id);
  const getInv = (req, id) => q1('SELECT * FROM cust_invoices WHERE id=? AND company_id=?', id, req.user.company_id);
  const invNo = (i) => `C-${String(i.created_at || '').slice(0, 4)}-${String(i.id).padStart(6, '0')}`;
  const L = (req) => req.i.t;

  function pkgValues(b) {
    const o = { name: clean(b.name, 120), service_type: b.service_type === 'hotspot' ? 'hotspot' : 'pppoe', price: num(b.price, -1), description: clean(b.description, 500), rate_down: num(b.rate_down, -1, 0, 100000), rate_up: num(b.rate_up, -1, 0, 100000), quota_mb: num(b.quota_mb, -1, 0, 1e9), validity_days: Math.round(num(b.validity_days, -1, 1, 3650)), session_minutes: Math.round(num(b.session_minutes, 0, 0, 525600)), profile_name: clean(b.profile_name, 80) };
    if (!o.name || o.price < 0 || o.rate_down < 0 || o.rate_up < 0 || o.quota_mb < 0 || o.validity_days < 1) return null;
    return o;
  }
  const pkgForm = (c, t, v, action) => `<form method="post" action="${action}">${csrfField(c)}<div class="row">${field(t('Package name'), 'name', v.name, { req: true })}${select(t('Service type'), 'service_type', v.service_type || 'pppoe', [['pppoe', 'PPPoE'], ['hotspot', 'Hotspot']])}${field(t('Price'), 'price', v.price ?? '', { type: 'number', req: true })}${field(t('Validity (days)'), 'validity_days', v.validity_days || 30, { type: 'number', req: true })}${field(t('Download speed (Mbps)'), 'rate_down', v.rate_down ?? 0, { type: 'number' })}${field(t('Upload speed (Mbps)'), 'rate_up', v.rate_up ?? 0, { type: 'number' })}${field(t('Data quota (MB, 0 = unlimited)'), 'quota_mb', v.quota_mb ?? 0, { type: 'number' })}${field(t('Session duration (minutes, 0 = unlimited)'), 'session_minutes', v.session_minutes ?? 0, { type: 'number' })}${field(t('Router profile name'), 'profile_name', v.profile_name)}${field(t('Description'), 'description', v.description)}</div><p><button>${t('Save')}</button></p></form>`;

  // ---------- packages
  app.get('/app/packages', needAdmin, (req, res) => {
    const t = L(req), c = ctx(req), cid = req.user.company_id, co = cur(cid);
    const rows = q('SELECT p.*, (SELECT count(*) FROM customers x WHERE x.package_id=p.id) used FROM packages p WHERE company_id=? ORDER BY id DESC', cid);
    res.send(page(c, 'Packages', `<div class="card tbl"><h3>${t('Packages')}</h3><table><tr><th>${t('Package name')}</th><th>${t('Service type')}</th><th>${t('Price')}</th><th>${t('Speed')}</th><th>${t('Data quota')}</th><th>${t('Validity (days)')}</th><th>${t('Subscribers')}</th><th>${t('Status')}</th><th></th></tr>
${rows.map((p) => `<tr><td>${esc(p.name)}</td><td>${p.service_type === 'hotspot' ? 'Hotspot' : 'PPPoE'}</td><td>${esc(money(p.price, co))}</td><td>${p.rate_down}/${p.rate_up} Mbps</td><td>${p.quota_mb ? p.quota_mb + ' MB' : t('Unlimited')}</td><td>${p.validity_days}</td><td>${p.used}</td><td>${badge(p.active ? 'active' : 'inactive', t)}</td><td><a href="/app/packages/${p.id}">${t('Edit')}</a></td></tr>`).join('') || `<tr><td colspan="9" class="mut">${t('No results')}</td></tr>`}</table></div>
<div class="card"><h3>${t('New package')}</h3>${pkgForm(c, t, {}, '/app/packages')}</div>`, nav(req)));
  });
  app.post('/app/packages', needAdmin, (req, res) => {
    const o = pkgValues(req.body), t = L(req);
    if (!o) return go(res, '/app/packages', 'err', t('required'));
    try { run('INSERT INTO packages(company_id,name,service_type,price,description,rate_down,rate_up,quota_mb,validity_days,session_minutes,profile_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)', req.user.company_id, o.name, o.service_type, o.price, o.description, o.rate_down, o.rate_up, o.quota_mb, o.validity_days, o.session_minutes, o.profile_name); } catch (e) { return go(res, '/app/packages', 'err', t('Could not save')); }
    audit(req, 'package_created', o.name);
    go(res, '/app/packages', 'ok', t('Saved'));
  });
  app.get('/app/packages/:id', needAdmin, (req, res) => {
    const p = getPkg(req, req.params.id), t = L(req), c = ctx(req);
    if (!p) return res.status(404).send(page(c, 'Error', `<div class="card"><h3>${t('Not found')}</h3></div>`));
    const used = q1('SELECT count(*) n FROM customers WHERE package_id=?', p.id).n;
    res.send(page(c, p.name, `<div class="card"><h3>${esc(p.name)} ${badge(p.active ? 'active' : 'inactive', t)}</h3>${pkgForm(c, t, p, `/app/packages/${p.id}`)}
<p class="mut">${t('Editing a package never changes invoices that were already issued.')}</p>
<form class="inline" method="post" action="/app/packages/${p.id}/toggle">${csrfField(c)}<button class="sec">${p.active ? t('Deactivate') : t('Activate')}</button></form>
<form class="inline" method="post" action="/app/packages/${p.id}/delete" onsubmit="return confirm('${t('Delete')}?')">${csrfField(c)}<button class="bad">${t('Delete')}</button></form>${used ? `<p class="mut">${t('Used by subscribers: deactivate instead of deleting.')} (${used})</p>` : ''}</div>`, nav(req)));
  });
  app.post('/app/packages/:id', needAdmin, (req, res) => {
    const p = getPkg(req, req.params.id), t = L(req); if (!p) return res.sendStatus(404);
    const o = pkgValues(req.body); if (!o) return go(res, `/app/packages/${p.id}`, 'err', t('required'));
    run('UPDATE packages SET name=?,service_type=?,price=?,description=?,rate_down=?,rate_up=?,quota_mb=?,validity_days=?,session_minutes=?,profile_name=? WHERE id=? AND company_id=?', o.name, o.service_type, o.price, o.description, o.rate_down, o.rate_up, o.quota_mb, o.validity_days, o.session_minutes, o.profile_name, p.id, req.user.company_id);
    audit(req, 'package_updated', o.name); go(res, `/app/packages/${p.id}`, 'ok', t('Saved'));
  });
  app.post('/app/packages/:id/toggle', needAdmin, (req, res) => {
    const p = getPkg(req, req.params.id); if (!p) return res.sendStatus(404);
    run('UPDATE packages SET active=? WHERE id=?', p.active ? 0 : 1, p.id); audit(req, 'package_toggled', p.name); go(res, `/app/packages/${p.id}`, 'ok', L(req)('Updated'));
  });
  app.post('/app/packages/:id/delete', needAdmin, (req, res) => {
    const p = getPkg(req, req.params.id); if (!p) return res.sendStatus(404);
    if (q1('SELECT count(*) n FROM customers WHERE package_id=?', p.id).n || q1('SELECT count(*) n FROM cust_invoices WHERE package_id=?', p.id).n) return go(res, `/app/packages/${p.id}`, 'err', L(req)('Used by subscribers: deactivate instead of deleting.'));
    run('DELETE FROM packages WHERE id=?', p.id); audit(req, 'package_deleted', p.name); go(res, '/app/packages', 'ok', L(req)('Deleted'));
  });

  // ---------- renewal -> invoice
  app.post('/app/customers/:id/renew', needAdmin, (req, res) => {
    const cid = req.user.company_id, t = L(req);
    const cu = q1('SELECT * FROM customers WHERE id=? AND company_id=?', req.params.id, cid); if (!cu) return res.sendStatus(404);
    const back = `/app/customers/${cu.id}`;
    const p = getPkg(req, req.body.package_id);
    if (!p || !p.active) return go(res, back, 'err', t('required'));
    const discount = num(req.body.discount, 0, 0, p.price);
    const start = cu.sub_end && cu.sub_end > today() ? cu.sub_end : today();
    const end = addDays(start, p.validity_days);
    const cu2 = cur(cid);
    run("INSERT INTO cust_invoices(company_id,customer_id,package_id,package_name,amount,discount,currency,period_start,period_end,status) VALUES(?,?,?,?,?,?,?,?,?,'unpaid')", cid, cu.id, p.id, p.name, p.price, discount, cu2, start, end);
    run("UPDATE customers SET package_id=?, package=?, service_type=?, sub_start=COALESCE(sub_start,?), sub_end=?, status='active', payment_status='unpaid' WHERE id=?", p.id, p.name, p.service_type, start, end, cu.id);
    audit(req, 'customer_renewed', `${cu.code} ${p.name}`);
    go(res, back, 'ok', t('Saved'));
  });

  // ---------- collect payment
  app.post('/app/billing/:id/collect', needAdmin, (req, res) => {
    const inv = getInv(req, req.params.id), t = L(req); if (!inv) return res.sendStatus(404);
    const back = `/app/customers/${inv.customer_id}`;
    if (inv.status !== 'unpaid') return go(res, back, 'err', t('Invoice is not payable'));
    const due = dueOf(inv), amount = num(req.body.amount, 0, 0.01, 1e9);
    const method = METHODS.includes(req.body.method) ? req.body.method : 'cash';
    if (!amount || amount > due + 0.001) return go(res, back, 'err', t('Invalid amount'));
    run('INSERT INTO cust_payments(company_id,customer_id,invoice_id,amount,method,note,user_id) VALUES(?,?,?,?,?,?,?)', inv.company_id, inv.customer_id, inv.id, amount, method, clean(req.body.note, 200), req.user.id);
    if (dueOf(inv) <= 0.001) {
      run("UPDATE cust_invoices SET status='paid', paid_at=datetime('now') WHERE id=?", inv.id);
      if (!q1("SELECT 1 x FROM cust_invoices WHERE customer_id=? AND status='unpaid'", inv.customer_id)) run("UPDATE customers SET payment_status='paid' WHERE id=?", inv.customer_id);
    }
    audit(req, 'payment_collected', `${inv.id} ${amount}`);
    go(res, back, 'ok', t('Saved'));
  });
  app.post('/app/billing/:id/void', needAdmin, (req, res) => {
    const inv = getInv(req, req.params.id), t = L(req); if (!inv) return res.sendStatus(404);
    if (inv.status !== 'unpaid' || paidOf(inv.id) > 0) return go(res, `/app/customers/${inv.customer_id}`, 'err', t('Invoice is not payable'));
    run("UPDATE cust_invoices SET status='void' WHERE id=?", inv.id);
    if (!q1("SELECT 1 x FROM cust_invoices WHERE customer_id=? AND status='unpaid'", inv.customer_id)) run("UPDATE customers SET payment_status='paid' WHERE id=?", inv.customer_id);
    audit(req, 'invoice_voided', String(inv.id)); go(res, `/app/customers/${inv.customer_id}`, 'ok', t('Updated'));
  });

  // ---------- printable docs
  const docPage = (req, title, body, co) => {
    const t = L(req), c = ctx(req);
    const brand = `<div style="display:flex;justify-content:space-between;align-items:center;border-bottom:3px solid ${esc(co.brand_color || '#2563eb')};padding-bottom:10px;margin-bottom:12px"><div>${co.logo ? `<img src="${esc(co.logo)}" style="height:${Number(co.logo_h) || 48}px;max-width:220px;object-fit:contain" alt="">` : ''}<h2 style="margin:4px 0">${esc(co.network_name || co.name)}</h2><div class="mut">${esc(co.phone || '')} ${esc(co.address || '')}</div></div><h2>${esc(title)}</h2></div>`;
    const foot = `<p class="mut" style="margin-top:18px">${esc(co.invoice_footer || '')}</p>${co.stamp ? `<img src="${esc(co.stamp)}" style="height:80px;object-fit:contain" alt="">` : ''}<p><button onclick="window.print()">${t('Print / Save as PDF')}</button></p>`;
    return page(c, title, `<div class="card">${brand}${body}${foot}</div>`, nav(req));
  };
  app.get('/app/billing/:id', needAdmin, (req, res) => {
    const inv = getInv(req, req.params.id), t = L(req); if (!inv) return res.status(404).send('Not found');
    const co = q1('SELECT * FROM companies WHERE id=?', inv.company_id), cu = q1('SELECT * FROM customers WHERE id=?', inv.customer_id);
    const pays = q('SELECT * FROM cust_payments WHERE invoice_id=? ORDER BY id', inv.id);
    res.send(docPage(req, inv.status === 'paid' ? t('Receipt') : t('Invoice'), `${infoGrid([[t('Invoice'), esc(invNo(inv))], [t('Date'), esc(String(inv.created_at).slice(0, 10))], [t('Customer ID'), esc(cu.code)], [t('Full name'), esc(cu.full_name)], [t('Status'), badge(inv.status, t)]])}
<table><tr><th>${t('Package name')}</th><th>${t('Period')}</th><th>${t('Amount')}</th></tr><tr><td>${esc(inv.package_name)}</td><td>${esc(inv.period_start)} - ${esc(inv.period_end)}</td><td>${esc(money(inv.amount, inv.currency))}</td></tr>
<tr><td colspan="2">${t('Discount')}</td><td>- ${esc(money(inv.discount, inv.currency))}</td></tr>${pays.map((p) => `<tr><td colspan="2">${t('Paid')} ${esc(String(p.created_at).slice(0, 10))} (${esc(p.method)})</td><td>- ${esc(money(p.amount, inv.currency))}</td></tr>`).join('')}
<tr><th colspan="2">${t('Balance due')}</th><th>${esc(money(inv.status === 'void' ? 0 : dueOf(inv), inv.currency))}</th></tr></table>`, co));
  });
  app.get('/app/customers/:id/statement', needAdmin, (req, res) => {
    const cid = req.user.company_id, t = L(req);
    const cu = q1('SELECT * FROM customers WHERE id=? AND company_id=?', req.params.id, cid); if (!cu) return res.status(404).send('Not found');
    const co = q1('SELECT * FROM companies WHERE id=?', cid), invs = q("SELECT * FROM cust_invoices WHERE customer_id=? AND status<>'void' ORDER BY id", cu.id);
    const pays = q('SELECT * FROM cust_payments WHERE customer_id=? ORDER BY id', cu.id);
    const bal = invs.reduce((s, i) => s + (i.amount - i.discount), 0) - pays.reduce((s, p) => s + p.amount, 0);
    res.send(docPage(req, t('Account statement'), `${infoGrid([[t('Customer ID'), esc(cu.code)], [t('Full name'), esc(cu.full_name)], [t('Phone'), esc(cu.phone)], [t('Balance due'), esc(money(Math.max(0, bal), co.currency))]])}
<table><tr><th>${t('Date')}</th><th></th><th>${t('Amount')}</th></tr>${invs.map((i) => `<tr><td>${esc(String(i.created_at).slice(0, 10))}</td><td>${t('Invoice')} ${esc(invNo(i))} ${esc(i.package_name)}</td><td>${esc(money(i.amount - i.discount, i.currency))}</td></tr>`).join('')}${pays.map((p) => `<tr><td>${esc(String(p.created_at).slice(0, 10))}</td><td>${t('Paid')} (${esc(p.method)})</td><td>- ${esc(money(p.amount, co.currency))}</td></tr>`).join('')}</table>`, co));
  });

  // ---------- customer detail section (called by app.js)
  function custSection(req, cu) {
    const t = L(req), c = ctx(req), co = cur(cu.company_id);
    const pk = q('SELECT * FROM packages WHERE company_id=? AND active=1 ORDER BY name', cu.company_id);
    const invs = q('SELECT * FROM cust_invoices WHERE customer_id=? ORDER BY id DESC LIMIT 30', cu.id);
    return `<div class="card"><h3>${t('Renewal & Billing')}</h3>${infoGrid([[t('Package name'), esc(cu.package || '-')], [t('Subscription Expiration Date'), esc(cu.sub_end || '-')], [t('Payment status'), badge(cu.payment_status, t)]])}
${pk.length ? `<form method="post" action="/app/customers/${cu.id}/renew" class="row">${csrfField(c)}${select(t('Package name'), 'package_id', cu.package_id, pk.map((p) => [String(p.id), `${p.name} - ${money(p.price, co)} / ${p.validity_days}d`]))}${field(t('Discount'), 'discount', '0', { type: 'number' })}<div style="padding-top:22px"><button>${t('Renew')}</button></div></form>` : `<p class="mut">${t('Create a package first')}: <a href="/app/packages">${t('Packages')}</a></p>`}
<p><a href="/app/customers/${cu.id}/statement">${t('Account statement')}</a></p></div>
<div class="card tbl"><h3>${t('Invoices')}</h3><table><tr><th>${t('Invoice')}</th><th>${t('Package name')}</th><th>${t('Amount')}</th><th>${t('Balance due')}</th><th>${t('Status')}</th><th></th></tr>${invs.map((i) => { const due = i.status === 'void' ? 0 : dueOf(i); return `<tr><td><a href="/app/billing/${i.id}">${esc(invNo(i))}</a></td><td>${esc(i.package_name)}</td><td>${esc(money(i.amount - i.discount, i.currency))}</td><td>${esc(money(due, i.currency))}</td><td>${badge(i.status, t)}</td><td>${i.status === 'unpaid' ? `<form class="inline" method="post" action="/app/billing/${i.id}/collect">${csrfField(c)}<input type="number" step="0.01" name="amount" value="${due}" style="width:90px"><select name="method" style="width:auto">${METHODS.map((m) => `<option value="${m}">${t(m)}</option>`).join('')}</select><button>${t('Collect payment')}</button></form><form class="inline" method="post" action="/app/billing/${i.id}/void">${csrfField(c)}<button class="sec">${t('Void')}</button></form>` : ''}</td></tr>`; }).join('') || `<tr><td colspan="6" class="mut">${t('No results')}</td></tr>`}</table></div>`;
  }

  // ---------- finance dashboard + expenses
  app.get('/app/finance', needAdmin, (req, res) => {
    const t = L(req), c = ctx(req), cid = req.user.company_id, co = cur(cid), d = today(), m = d.slice(0, 7);
    const sum = (sql, ...a) => q1(sql, ...a).s;
    const day = sum("SELECT COALESCE(SUM(amount),0) s FROM cust_payments WHERE company_id=? AND substr(created_at,1,10)=?", cid, d);
    const mon = sum("SELECT COALESCE(SUM(amount),0) s FROM cust_payments WHERE company_id=? AND substr(created_at,1,7)=?", cid, m);
    const exp = sum("SELECT COALESCE(SUM(amount),0) s FROM expenses WHERE company_id=? AND substr(spent_on,1,7)=?", cid, m);
    const open = q("SELECT i.*, cu.code, cu.full_name FROM cust_invoices i JOIN customers cu ON cu.id=i.customer_id WHERE i.company_id=? AND i.status='unpaid' ORDER BY i.id DESC LIMIT 100", cid).map((i) => ({ ...i, due: dueOf(i) }));
    const outstanding = open.reduce((s, i) => s + i.due, 0);
    const exps = q('SELECT * FROM expenses WHERE company_id=? ORDER BY spent_on DESC, id DESC LIMIT 50', cid);
    res.send(page(c, 'Finance', `<div class="grid"><div class="stat"><span>${t('Collected today')}</span><b>${esc(money(day, co))}</b></div><div class="stat"><span>${t('Collected this month')}</span><b>${esc(money(mon, co))}</b></div><div class="stat"><span>${t('Expenses this month')}</span><b>${esc(money(exp, co))}</b></div><div class="stat"><span>${t('Net this month')}</span><b>${esc(money(mon - exp, co))}</b></div><div class="stat"><span>${t('Outstanding balances')}</span><b>${esc(money(outstanding, co))}</b></div></div>
<div class="card tbl"><h3>${t('Outstanding balances')}</h3><table><tr><th>${t('Customer ID')}</th><th>${t('Full name')}</th><th>${t('Invoice')}</th><th>${t('Balance due')}</th></tr>${open.map((i) => `<tr><td>${esc(i.code)}</td><td><a href="/app/customers/${i.customer_id}">${esc(i.full_name)}</a></td><td><a href="/app/billing/${i.id}">${esc(invNo(i))}</a></td><td>${esc(money(i.due, i.currency))}</td></tr>`).join('') || `<tr><td colspan="4" class="mut">${t('No results')}</td></tr>`}</table></div>
<div class="card tbl"><h3>${t('Expenses')}</h3><form method="post" action="/app/expenses" class="row">${csrfField(c)}${field(t('Title'), 'title', '', { req: true })}${field(t('Amount'), 'amount', '', { type: 'number', req: true })}${field(t('Category'), 'category', '')}${field(t('Date'), 'spent_on', d, { type: 'date' })}<div style="padding-top:22px"><button>${t('Add')}</button></div></form>
<table><tr><th>${t('Date')}</th><th>${t('Title')}</th><th>${t('Category')}</th><th>${t('Amount')}</th><th></th></tr>${exps.map((e) => `<tr><td>${esc(e.spent_on)}</td><td>${esc(e.title)}</td><td>${esc(e.category)}</td><td>${esc(money(e.amount, co))}</td><td><form class="inline" method="post" action="/app/expenses/${e.id}/delete">${csrfField(c)}<button class="bad">${t('Delete')}</button></form></td></tr>`).join('') || `<tr><td colspan="5" class="mut">${t('No results')}</td></tr>`}</table></div>`, nav(req)));
  });
  app.post('/app/expenses', needAdmin, (req, res) => {
    const t = L(req), b = req.body, amount = num(b.amount, 0, 0.01, 1e9), title = clean(b.title, 150), d = /^\d{4}-\d{2}-\d{2}$/.test(b.spent_on || '') ? b.spent_on : today();
    if (!title || !amount) return go(res, '/app/finance', 'err', t('required'));
    run('INSERT INTO expenses(company_id,title,amount,category,spent_on) VALUES(?,?,?,?,?)', req.user.company_id, title, amount, clean(b.category, 60), d);
    audit(req, 'expense_added', title); go(res, '/app/finance', 'ok', t('Saved'));
  });
  app.post('/app/expenses/:id/delete', needAdmin, (req, res) => {
    run('DELETE FROM expenses WHERE id=? AND company_id=?', req.params.id, req.user.company_id); audit(req, 'expense_deleted', req.params.id); go(res, '/app/finance', 'ok', L(req)('Deleted'));
  });
  return { custSection };
}
module.exports = { init };
