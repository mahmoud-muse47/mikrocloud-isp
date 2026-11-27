const { esc, page, csrfField, badge, field, select } = require('./views');

const TYPES = [['bank_transfer', 'Bank transfer'], ['cash', 'Cash payment'], ['manual', 'Manual payment confirmation'], ['mobile_wallet', 'Mobile wallet'], ['egypt_provider', 'Egyptian payment provider'], ['gateway', 'Online payment gateway (needs merchant account, not active yet)']];
const clean = (v, max = 300) => String(v ?? '').trim().slice(0, max);
const num = (v, def = 0, min = 0, max = 1e9) => { const n = Number(v); return Number.isFinite(n) && n >= min && n <= max ? n : def; };
const money = (n, cur) => `${Number(n).toFixed(2).replace(/\.00$/, '')} ${cur || 'EGP'}`;
const validImg = (s) => s === '' || (/^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$/.test(s) && s.length <= 300000);

function init(h) {
  const { q, q1, run, audit, ctx, go, deny, needSuper, needAdmin, nav } = h;
  const mName = (m, i) => (i.lang === 'ar' ? (m.name_ar || m.name_en) : (m.name_en || m.name_ar));
  const mDesc = (m, i) => (i.lang === 'ar' ? (m.desc_ar || m.desc_en) : (m.desc_en || m.desc_ar)) || '';
  const mInstr = (m, i) => (i.lang === 'ar' ? (m.instr_ar || m.instr_en) : (m.instr_en || m.instr_ar)) || '';
  const feeOf = (m, amount) => Math.round((amount * (m.fee_pct || 0) / 100 + (m.fee_fixed || 0)) * 100) / 100;
  const invNo = (inv) => `INV-${String(inv.created_at || '').slice(0, 4)}-${String(inv.id).padStart(6, '0')}`;
  const pstatus = (s, t) => `<span class="badge ${s === 'approved' ? 'active' : s === 'rejected' ? 'expired' : 'trial'}">${t(s === 'pending' ? 'Pending Verification' : s[0].toUpperCase() + s.slice(1))}</span>`;
  const methodAllowed = (m, inv) => m.enabled && m.type !== 'gateway' && m.currency === inv.currency
    && (!m.min_amount || inv.amount - inv.credit >= m.min_amount) && (!m.max_amount || inv.amount - inv.credit <= m.max_amount);
  const payable = (inv) => Math.max(0, Number(inv.amount) - Number(inv.credit || 0));

  // ============ SUPER ADMIN: payment methods
  const M_COLS = ['type', 'name_en', 'name_ar', 'desc_en', 'desc_ar', 'instr_en', 'instr_ar', 'account_info', 'currency', 'min_amount', 'max_amount', 'fee_pct', 'fee_fixed', 'require_ref', 'require_proof', 'sort_order', 'logo'];
  function parseMethod(b) {
    const o = {
      type: TYPES.some((x) => x[0] === b.type) ? b.type : null, name_en: clean(b.name_en, 80), name_ar: clean(b.name_ar, 80), desc_en: clean(b.desc_en, 500), desc_ar: clean(b.desc_ar, 500),
      instr_en: clean(b.instr_en, 2000), instr_ar: clean(b.instr_ar, 2000), account_info: clean(b.account_info, 1000), currency: clean(b.currency || 'EGP', 3).toUpperCase(),
      min_amount: num(b.min_amount), max_amount: num(b.max_amount), fee_pct: num(b.fee_pct, 0, 0, 100), fee_fixed: num(b.fee_fixed), require_ref: b.require_ref ? 1 : 0, require_proof: b.require_proof ? 1 : 0,
      sort_order: Math.round(num(b.sort_order, 0, -9999, 9999)), logo: clean(b.logo, 300000),
    };
    if (!o.type || (!o.name_en && !o.name_ar) || !/^[A-Z]{3}$/.test(o.currency) || !validImg(o.logo)) return null;
    if (o.max_amount && o.max_amount < o.min_amount) return null;
    return o;
  }
  function methodForm(c, t, m, action) {
    const chk = (n, v, l) => `<label style="display:flex;gap:6px;align-items:center"><input type="checkbox" name="${n}" value="1" ${v ? 'checked' : ''}> ${esc(l)}</label>`;
    return `<form method="post" action="${action}">${csrfField(c)}<div class="card"><div class="row2">
${select(t('Payment method type'), 'type', m.type || 'bank_transfer', TYPES.map(([v, l]) => [v, t(l)]))}${field(t('Currency'), 'currency', m.currency || 'EGP', { req: true })}
${field(t('Name (English)'), 'name_en', m.name_en || '')}${field(t('Name (Arabic)'), 'name_ar', m.name_ar || '')}
${field(t('Description (English)'), 'desc_en', m.desc_en || '')}${field(t('Description (Arabic)'), 'desc_ar', m.desc_ar || '')}
${field(t('Payment instructions (English)'), 'instr_en', m.instr_en || '', { ta: true })}${field(t('Payment instructions (Arabic)'), 'instr_ar', m.instr_ar || '', { ta: true })}
${field(t('Account information'), 'account_info', m.account_info || '', { ta: true })}${field(t('Display order'), 'sort_order', m.sort_order || 0, { type: 'number' })}
${field(t('Minimum amount'), 'min_amount', m.min_amount || 0, { type: 'number' })}${field(t('Maximum amount (0 = none)'), 'max_amount', m.max_amount || 0, { type: 'number' })}
${field(t('Fee percent'), 'fee_pct', m.fee_pct || 0, { type: 'number' })}${field(t('Fixed fee'), 'fee_fixed', m.fee_fixed || 0, { type: 'number' })}
</div><p>${chk('require_ref', m.require_ref !== 0, t('Require transaction reference'))} ${chk('require_proof', m.require_proof, t('Require proof of payment'))}</p>
<p><label>${t('Logo')}</label><input type="file" accept="image/png,image/jpeg,image/webp,image/gif" onchange="mcImg(this,'logo')"><input type="hidden" name="logo" id="logo" value="${esc(m.logo || '')}"> ${m.logo ? `<img src="${esc(m.logo)}" style="height:32px;vertical-align:middle" alt="">` : ''}</p>
<button>${t('Save')}</button> <a href="/admin/payment-methods">${t('Cancel')}</a></div></form>
<script>function mcImg(i,id){var f=i.files[0];if(!f)return;if(f.size>200000){alert('Max 200KB');i.value='';return}var r=new FileReader();r.onload=function(){document.getElementById(id).value=r.result};r.readAsDataURL(f)}</script>`;
  }
  h.app.get('/admin/payment-methods', needSuper, (req, res) => {
    const t = req.i.t, c = ctx(req);
    const rows = q('SELECT * FROM payment_methods ORDER BY sort_order, id');
    res.send(page(c, 'Payment Methods Management', `<div class="card"><h3>${t('Payment Methods Management')}</h3><p class="mut">${t('Methods you enable appear on the client payment page. Disabling a method hides it from new payments; old payments and invoices are not changed.')}</p><a class="btn" href="/admin/payment-methods/new">${t('Add payment method')}</a> <a href="/admin/payments">${t('Payment requests')}</a></div>
<div class="card tbl"><table><tr><th></th><th>${t('Name')}</th><th>${t('Type')}</th><th>${t('Currency')}</th><th>${t('Limits')}</th><th>${t('Fees')}</th><th>${t('Status')}</th><th></th></tr>
${rows.map((m) => `<tr><td>${m.logo ? `<img src="${esc(m.logo)}" style="height:28px" alt="">` : ''}</td><td>${esc(mName(m, req.i))}</td><td>${esc(t((TYPES.find((x) => x[0] === m.type) || [0, m.type])[1]))}</td><td>${esc(m.currency)}</td><td>${esc(m.min_amount)} - ${m.max_amount ? esc(m.max_amount) : '∞'}</td><td>${esc(m.fee_pct)}% + ${esc(m.fee_fixed)}</td>
<td>${m.enabled ? `<span class="badge active">${t('Enabled')}</span>` : `<span class="badge">${t('Disabled')}</span>`}</td><td><a href="/admin/payment-methods/${m.id}">${t('Edit')}</a>
<form class="inline" method="post" action="/admin/payment-methods/${m.id}/toggle">${csrfField(c)}<button class="sec">${m.enabled ? t('Disable') : t('Enable')}</button></form></td></tr>`).join('') || `<tr><td colspan="8" class="mut">${t('No payment methods yet')}</td></tr>`}</table></div>`, nav(req)));
  });
  h.app.get('/admin/payment-methods/new', needSuper, (req, res) => { const c = ctx(req); res.send(page(c, 'Add payment method', methodForm(c, req.i.t, {}, '/admin/payment-methods'), nav(req))); });
  h.app.post('/admin/payment-methods', needSuper, (req, res) => {
    const t = req.i.t, o = parseMethod(req.body);
    if (!o) return go(res, '/admin/payment-methods/new', 'err', t('required'));
    const id = run(`INSERT INTO payment_methods(${M_COLS.join(',')},enabled) VALUES(${M_COLS.map(() => '?').join(',')},0)`, ...M_COLS.map((k) => o[k])).lastInsertRowid;
    audit(req, 'payment_method_created', o.name_en || o.name_ar, null);
    go(res, `/admin/payment-methods/${id}`, 'ok', t('Created. It is disabled until you enable it.'));
  });
  const m404 = (req, res) => { const m = q1('SELECT * FROM payment_methods WHERE id=?', Number(req.params.id)); if (!m) { res.status(404).send('Not found'); return null; } return m; };
  h.app.get('/admin/payment-methods/:id', needSuper, (req, res) => {
    const m = m404(req, res); if (!m) return; const c = ctx(req), t = req.i.t;
    const used = q1('SELECT count(*) n FROM payments WHERE method_id=?', m.id).n;
    res.send(page(c, 'Payment method', methodForm(c, t, m, `/admin/payment-methods/${m.id}`) + `<div class="card"><form method="post" action="/admin/payment-methods/${m.id}/delete" onsubmit="return confirm('${t('Delete?')}')">${csrfField(c)}<button class="danger">${t('Delete')}</button> <span class="mut">${used ? t('This method has payments, so it will be disabled instead of deleted.') : ''}</span></form></div>`, nav(req)));
  });
  h.app.post('/admin/payment-methods/:id', needSuper, (req, res) => {
    const m = m404(req, res); if (!m) return; const t = req.i.t, o = parseMethod(req.body);
    if (!o) return go(res, `/admin/payment-methods/${m.id}`, 'err', t('required'));
    run(`UPDATE payment_methods SET ${M_COLS.map((k) => `${k}=?`).join(',')} WHERE id=?`, ...M_COLS.map((k) => o[k]), m.id);
    audit(req, 'payment_method_updated', o.name_en || o.name_ar, null);
    go(res, `/admin/payment-methods/${m.id}`, 'ok', t('Saved'));
  });
  h.app.post('/admin/payment-methods/:id/toggle', needSuper, (req, res) => {
    const m = m404(req, res); if (!m) return;
    if (!m.enabled && m.type === 'gateway') return go(res, '/admin/payment-methods', 'err', req.i.t('Online gateways need a merchant account and are not available yet'));
    run('UPDATE payment_methods SET enabled=? WHERE id=?', m.enabled ? 0 : 1, m.id);
    audit(req, m.enabled ? 'payment_method_disabled' : 'payment_method_enabled', m.name_en || m.name_ar, null);
    go(res, '/admin/payment-methods', 'ok', req.i.t('Saved'));
  });
  h.app.post('/admin/payment-methods/:id/delete', needSuper, (req, res) => {
    const m = m404(req, res); if (!m) return; const t = req.i.t;
    if (q1('SELECT count(*) n FROM payments WHERE method_id=?', m.id).n > 0) { run('UPDATE payment_methods SET enabled=0 WHERE id=?', m.id); audit(req, 'payment_method_disabled_instead_of_delete', m.name_en, null); return go(res, '/admin/payment-methods', 'ok', t('Method has payments, so it was disabled instead of deleted')); }
    run('DELETE FROM payment_methods WHERE id=?', m.id); audit(req, 'payment_method_deleted', m.name_en, null);
    go(res, '/admin/payment-methods', 'ok', t('Deleted'));
  });

  // ============ SUPER ADMIN: review payments
  h.app.get('/admin/payments', needSuper, (req, res) => {
    const t = req.i.t, c = ctx(req);
    const rows = q(`SELECT p.*, co.name company, i.created_at inv_date, i.id inv_id FROM payments p JOIN companies co ON co.id=p.company_id JOIN invoices i ON i.id=p.invoice_id ORDER BY (p.status='pending') DESC, p.id DESC LIMIT 200`);
    res.send(page(c, 'Payment requests', `<div class="card"><h3>${t('Payment requests')}</h3></div><div class="card tbl"><table><tr><th>${t('Date')}</th><th>${t('Client')}</th><th>${t('Invoice')}</th><th>${t('Method')}</th><th>${t('Amount')}</th><th>${t('Reference')}</th><th>${t('Proof')}</th><th>${t('Status')}</th><th></th></tr>
${rows.map((p) => `<tr><td>${esc(p.created_at)}</td><td>${esc(p.company)}</td><td><a href="/admin/invoices/${p.invoice_id}">${esc(invNo({ id: p.inv_id, created_at: p.inv_date }))}</a></td><td>${esc(p.method_name)}</td><td>${esc(money(p.amount, p.currency))}${p.fee ? ` (+${esc(money(p.fee, p.currency))})` : ''}</td><td>${esc(p.reference)}</td>
<td>${p.proof ? `<a href="/admin/payments/${p.id}/proof" target="_blank">${t('View')}</a>` : '-'}</td><td>${pstatus(p.status, t)}${p.decided_at ? `<br><span class="mut">${esc(p.decided_at)} ${esc(p.note)}</span>` : ''}</td>
<td>${p.status === 'pending' ? `<form class="inline" method="post" action="/admin/payments/${p.id}/approve">${csrfField(c)}<button class="ok">${t('Approve')}</button></form> <form class="inline" method="post" action="/admin/payments/${p.id}/reject">${csrfField(c)}<input name="note" placeholder="${t('Reason')}" style="width:120px"><button class="danger">${t('Reject')}</button></form>` : ''}</td></tr>`).join('') || `<tr><td colspan="9" class="mut">${t('No payment requests')}</td></tr>`}</table></div>`, nav(req)));
  });
  h.app.get('/admin/payments/:id/proof', needSuper, (req, res) => {
    const p = q1('SELECT proof FROM payments WHERE id=?', Number(req.params.id));
    if (!p || !p.proof) return res.status(404).send('Not found');
    res.send(`<!doctype html><meta charset="utf-8"><img src="${esc(p.proof)}" style="max-width:100%">`);
  });
  h.app.post('/admin/payments/:id/approve', needSuper, (req, res) => {
    const t = req.i.t, p = q1('SELECT * FROM payments WHERE id=?', Number(req.params.id));
    if (!p) return res.status(404).send('Not found');
    // atomic: only a pending payment can be approved, once
    const r = run("UPDATE payments SET status='approved', decided_at=datetime('now'), decided_by=? WHERE id=? AND status='pending'", req.user.id, p.id);
    if (!r.changes) return go(res, '/admin/payments', 'err', t('Already decided'));
    run("UPDATE invoices SET status='paid', paid_at=datetime('now') WHERE id=? AND company_id=? AND status<>'paid'", p.invoice_id, p.company_id);
    audit(req, 'payment_approved', `payment ${p.id} invoice ${p.invoice_id}`, p.company_id);
    go(res, '/admin/payments', 'ok', t('Payment approved and invoice marked paid'));
  });
  h.app.post('/admin/payments/:id/reject', needSuper, (req, res) => {
    const t = req.i.t, p = q1('SELECT * FROM payments WHERE id=?', Number(req.params.id));
    if (!p) return res.status(404).send('Not found');
    const r = run("UPDATE payments SET status='rejected', decided_at=datetime('now'), decided_by=?, note=? WHERE id=? AND status='pending'", req.user.id, clean(req.body.note, 300), p.id);
    if (!r.changes) return go(res, '/admin/payments', 'err', t('Already decided'));
    audit(req, 'payment_rejected', `payment ${p.id} invoice ${p.invoice_id}`, p.company_id);
    go(res, '/admin/payments', 'ok', t('Payment rejected'));
  });

  // ============ CLIENT: pay an invoice
  const myInv = (req, res) => {
    const inv = q1('SELECT * FROM invoices WHERE id=? AND company_id=?', Number(req.params.id), req.user.company_id);
    if (!inv) { res.status(404).send('Not found'); return null; } return inv;
  };
  h.app.get('/app/invoices/:id/pay', needAdmin, (req, res) => {
    const inv = myInv(req, res); if (!inv) return; const t = req.i.t, c = ctx(req);
    const due = payable(inv);
    if (inv.status === 'paid' || due <= 0) return go(res, '/app/subscription', 'ok', t('This invoice is already paid'));
    const pend = q1("SELECT 1 x FROM payments WHERE invoice_id=? AND status='pending'", inv.id);
    const ms = q('SELECT * FROM payment_methods ORDER BY sort_order,id').filter((m) => methodAllowed(m, inv));
    const body = pend ? `<div class="card"><p>${t('You already have a payment waiting for verification for this invoice.')}</p><a href="/app/payments">${t('My payments')}</a></div>`
      : !ms.length ? `<div class="card"><p>${t('No payment method is available for this invoice right now. Please contact the platform administrator.')}</p></div>`
        : `<form method="post" action="/app/invoices/${inv.id}/pay">${csrfField(c)}<div class="card"><h3>${t('Pay invoice')} ${esc(invNo(inv))}: ${esc(money(due, inv.currency))}</h3>
${ms.map((m, k) => `<div class="card" style="border:1px solid #dde"><label style="display:flex;gap:10px;align-items:flex-start"><input type="radio" name="method_id" value="${m.id}" ${k === 0 ? 'checked' : ''}> ${m.logo ? `<img src="${esc(m.logo)}" style="height:32px" alt="">` : ''}<span><b>${esc(mName(m, req.i))}</b><br><span class="mut">${esc(mDesc(m, req.i))}</span>
${m.account_info ? `<br><b>${t('Account information')}:</b> <span style="white-space:pre-wrap">${esc(m.account_info)}</span>` : ''}${mInstr(m, req.i) ? `<br><span style="white-space:pre-wrap">${esc(mInstr(m, req.i))}</span>` : ''}${feeOf(m, due) ? `<br>${t('Fee')}: ${esc(money(feeOf(m, due), m.currency))}` : ''}${m.require_proof ? `<br><i>${t('Proof of payment is required')}</i>` : ''}</span></label></div>`).join('')}
${field(t('Transaction reference'), 'reference', '')}<p><label>${t('Proof of payment (image, max 250KB)')}</label><input type="file" accept="image/png,image/jpeg,image/webp" onchange="var f=this.files[0];if(!f)return;if(f.size>250000){alert('Max 250KB');this.value='';return}var r=new FileReader();r.onload=function(){document.getElementById('proof').value=r.result};r.readAsDataURL(f)"><input type="hidden" name="proof" id="proof"></p>
<button>${t('Submit payment for verification')}</button></div></form>`;
    res.send(page(c, 'Pay invoice', body, nav(req)));
  });
  h.app.post('/app/invoices/:id/pay', needAdmin, (req, res) => {
    const inv = myInv(req, res); if (!inv) return; const t = req.i.t, back = `/app/invoices/${inv.id}/pay`;
    const due = payable(inv), m = q1('SELECT * FROM payment_methods WHERE id=?', Number(req.body.method_id));
    if (inv.status === 'paid' || due <= 0) return go(res, '/app/subscription', 'ok', t('This invoice is already paid'));
    if (!m || !methodAllowed(m, inv)) return go(res, back, 'err', t('This payment method is not available'));
    const reference = clean(req.body.reference, 120), proof = clean(req.body.proof, 400000);
    if (m.require_ref && !reference) return go(res, back, 'err', t('Transaction reference is required'));
    if (m.require_proof && !proof) return go(res, back, 'err', t('Proof of payment is required'));
    if (proof && !validImg(proof)) return go(res, back, 'err', t('Invalid proof image'));
    if (q1("SELECT 1 x FROM payments WHERE invoice_id=? AND status='pending'", inv.id)) return go(res, '/app/payments', 'err', t('You already have a payment waiting for verification for this invoice.'));
    if (reference && q1("SELECT 1 x FROM payments WHERE method_id=? AND reference=? AND status<>'rejected'", m.id, reference)) return go(res, back, 'err', t('This transaction reference was already used'));
    const nm = (m.name_en || m.name_ar);
    run('INSERT INTO payments(invoice_id,company_id,method_id,method_name,amount,fee,currency,reference,proof,status) VALUES(?,?,?,?,?,?,?,?,?,?)', inv.id, inv.company_id, m.id, nm, due, feeOf(m, due), inv.currency, reference, proof, 'pending');
    audit(req, 'payment_submitted', `invoice ${inv.id} via ${nm}`, inv.company_id);
    go(res, '/app/payments', 'ok', t('Payment submitted. It is pending verification.'));
  });
  h.app.get('/app/payments', needAdmin, (req, res) => {
    const t = req.i.t, c = ctx(req);
    const rows = q('SELECT * FROM payments WHERE company_id=? ORDER BY id DESC LIMIT 100', req.user.company_id);
    res.send(page(c, 'My payments', `<div class="card"><h3>${t('My payments')}</h3><a href="/app/subscription">${t('My Subscription')}</a></div><div class="card tbl"><table><tr><th>${t('Date')}</th><th>${t('Invoice')}</th><th>${t('Method')}</th><th>${t('Amount')}</th><th>${t('Reference')}</th><th>${t('Status')}</th></tr>
${rows.map((p) => `<tr><td>${esc(p.created_at)}</td><td><a href="/app/invoices/${p.invoice_id}">#${p.invoice_id}</a></td><td>${esc(p.method_name)}</td><td>${esc(money(p.amount, p.currency))}</td><td>${esc(p.reference)}</td><td>${pstatus(p.status, t)} ${p.status === 'rejected' && p.note ? `<span class="mut">${esc(p.note)}</span>` : ''}</td></tr>`).join('') || `<tr><td colspan="6" class="mut">${t('No payments yet')}</td></tr>`}</table></div>`, nav(req)));
  });

  // ============ Printable invoice / receipt (use the browser's Print > Save as PDF)
  function invoiceHtml(req, inv) {
    const t = req.i.t, co = q1('SELECT * FROM companies WHERE id=?', inv.company_id);
    const pays = q("SELECT * FROM payments WHERE invoice_id=? AND status='approved' ORDER BY id", inv.id);
    const planName = req.i.lang === 'ar' ? (inv.plan_name_ar || inv.plan_name_en) : (inv.plan_name_en || inv.plan_name_ar);
    return `<!doctype html><html lang="${req.i.lang}" dir="${req.i.rtl ? 'rtl' : 'ltr'}"><head><meta charset="utf-8"><title>${esc(invNo(inv))}</title><style>body{font-family:system-ui,Arial;margin:30px;color:#111}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #ddd;text-align:start}h1{margin:0}.r{float:inline-end}@media print{.np{display:none}}</style></head><body>
<p class="np"><button onclick="print()">${t('Print / Save as PDF')}</button></p>
<h1>MikroCloud <span class="r">${inv.status === 'paid' ? t('Receipt') : t('Invoice')}</span></h1><p>${esc(invNo(inv))}<br>${t('Date')}: ${esc(String(inv.created_at).slice(0, 10))}<br>${t('Status')}: ${esc(t(inv.status === 'paid' ? 'Paid' : 'Unpaid'))}${inv.paid_at ? ` (${esc(inv.paid_at)})` : ''}</p>
<p><b>${t('Client')}:</b> ${esc(co.name)}${co.email ? `<br>${esc(co.email)}` : ''}</p>
<table><tr><th>${t('Description')}</th><th>${t('Period')}</th><th>${t('Amount')}</th></tr><tr><td>${esc(planName)} (${esc(inv.kind)})</td><td>${esc(inv.period)}</td><td>${esc(money(inv.amount, inv.currency))}</td></tr>
${inv.credit ? `<tr><td>${t('Credit')}</td><td></td><td>-${esc(money(inv.credit, inv.currency))}</td></tr>` : ''}<tr><th colspan="2">${t('Total due')}</th><th>${esc(money(payable(inv), inv.currency))}</th></tr></table>
${pays.map((p) => `<p>${t('Paid via')} ${esc(p.method_name)} ${p.reference ? `(${esc(p.reference)})` : ''} - ${esc(p.decided_at)}</p>`).join('')}</body></html>`;
  }
  h.app.get('/app/invoices/:id', needAdmin, (req, res) => { const inv = myInv(req, res); if (inv) res.send(invoiceHtml(req, inv)); });
  h.app.get('/admin/invoices/:id', needSuper, (req, res) => {
    const inv = q1('SELECT * FROM invoices WHERE id=?', Number(req.params.id));
    if (!inv) return res.status(404).send('Not found'); res.send(invoiceHtml(req, inv));
  });
  return { invNo };
}
module.exports = { init, TYPES };
