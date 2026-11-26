const { esc, page, csrfField, badge, field, select } = require('./views');

const LIMITS = [
  ['max_admins', 'Maximum Client Admin accounts'], ['max_employees', 'Maximum employee accounts'], ['max_subscribers', 'Maximum managed subscribers'],
  ['max_hotspot', 'Maximum Hotspot subscribers'], ['max_pppoe', 'Maximum PPPoE subscribers'], ['max_routers', 'Maximum MikroTik routers'],
  ['max_aps', 'Maximum Access Points'], ['max_devices', 'Maximum network devices'], ['max_vouchers_batch', 'Maximum vouchers per batch'],
  ['max_vouchers_month', 'Maximum monthly generated vouchers'], ['max_storage_mb', 'Maximum storage (MB)'], ['max_api_ops', 'Maximum API operations per month'],
];
const LIMIT_KEYS = LIMITS.map((l) => l[0]);
const PERIODS = [['monthly', 30, 'price_monthly', 'Monthly'], ['quarterly', 90, 'price_quarterly', 'Quarterly'], ['semiannual', 180, 'price_semiannual', 'Semi-annual'], ['annual', 365, 'price_annual', 'Annual'], ['custom', 0, 'price_custom', 'Custom duration']];
const MODULES = [['customers', 'Subscribers module'], ['network', 'Network Management'], ['vouchers', 'Vouchers'], ['reports', 'Reports'], ['api', 'API access']];
const ROUTER_CATS = ['main_router', 'secondary_router', 'core_router', 'edge_router'];
const AP_CATS = ['ap', 'outdoor_ap', 'indoor_ap'];

const today = () => new Date().toISOString().slice(0, 10);
const addDays = (d, n) => new Date(new Date(d).getTime() + n * 864e5).toISOString().slice(0, 10);
const daysBetween = (a, b) => Math.round((new Date(b) - new Date(a)) / 864e5);
const clean = (v, max = 300) => String(v ?? '').trim().slice(0, max);
const num = (v, def = 0, min = 0, max = 1e9) => { const n = Number(v); return Number.isFinite(n) && n >= min && n <= max ? n : def; };
const money = (n, cur) => `${Number(n).toFixed(2).replace(/\.00$/, '')} ${cur || 'EGP'}`;
const validDate = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(new Date(s).getTime());
const validIcon = (s) => s === '' || (/^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$/.test(s) && s.length <= 90000);

function init(h) {
  const { db, q, q1, run, audit, ctx, go, deny, needSuper, needAdmin, nav } = h;

  const getPlan = (idOrCode) => (typeof idOrCode === 'number' || /^\d+$/.test(String(idOrCode))
    ? q1('SELECT * FROM plans WHERE id=?', Number(idOrCode)) : q1('SELECT * FROM plans WHERE code=?', String(idOrCode)));
  const planName = (p, i) => (!p ? '-' : i.lang === 'ar' ? (p.name_ar || p.name_en) : (p.name_en || p.name_ar));
  const planDesc = (p, i) => (i.lang === 'ar' ? (p.desc_ar || p.desc_en) : (p.desc_en || p.desc_ar)) || '';
  const periodLabel = (code, t) => t((PERIODS.find((p) => p[0] === code) || [0, 0, 0, code === 'trial' ? 'Trial' : code])[3]);
  const periodDays = (p, period) => (period === 'trial' ? p.trial_days : period === 'custom' ? p.custom_days : (PERIODS.find((x) => x[0] === period) || [0, 30])[1]);
  function effPrice(p, period) {
    if (period === 'trial') return 0;
    const col = (PERIODS.find((x) => x[0] === period) || PERIODS[0])[2];
    const base = Number(p[col]) || 0;
    let v = base;
    if (p.promo_price > 0 && p.promo_price < base) v = p.promo_price;
    else if (p.discount_pct > 0) v = base * (1 - Math.min(p.discount_pct, 100) / 100);
    return Math.round(v * 100) / 100;
  }
  const basePrice = (p, period) => (period === 'trial' ? 0 : Number(p[(PERIODS.find((x) => x[0] === period) || PERIODS[0])[2]]) || 0);
  const availablePeriods = (p) => {
    const out = [];
    if (p.trial_eligible && p.trial_days > 0) out.push('trial');
    for (const [code, , col] of PERIODS) {
      if (code === 'custom' ? (p.custom_days > 0 && p.price_custom > 0) : p[col] > 0) out.push(code);
    }
    if (!out.length) out.push('monthly');
    return out;
  };
  const lim = (v) => (v < 0 ? '∞' : String(v));

  function overridesOf(co) {
    let o = {}; try { o = JSON.parse(co.limit_overrides || '{}'); } catch { o = {}; }
    const out = {};
    for (const [k, v] of Object.entries(o)) if (LIMIT_KEYS.includes(k) && v && (!v.until || v.until >= today())) out[k] = v;
    return out;
  }
  function limitsOf(co) {
    const p = getPlan(co.plan) || {};
    const ov = overridesOf(co), res = {};
    for (const k of LIMIT_KEYS) res[k] = ov[k] ? ov[k].v : (p[k] ?? -1);
    return res;
  }
  function usageOf(cid) {
    const n = (sql, ...a) => q1(sql, cid, ...a).n;
    const marks = (arr) => arr.map(() => '?').join(',');
    return {
      max_admins: n("SELECT count(*) n FROM users WHERE company_id=? AND role='company_admin'"),
      max_employees: n("SELECT count(*) n FROM users WHERE company_id=? AND role='employee'"),
      max_subscribers: n('SELECT count(*) n FROM customers WHERE company_id=?'),
      max_hotspot: n("SELECT count(*) n FROM customers WHERE company_id=? AND service_type='hotspot'"),
      max_pppoe: n("SELECT count(*) n FROM customers WHERE company_id=? AND service_type='pppoe'"),
      max_routers: n(`SELECT count(*) n FROM devices WHERE company_id=? AND category IN (${marks(ROUTER_CATS)})`, ...ROUTER_CATS),
      max_aps: n(`SELECT count(*) n FROM devices WHERE company_id=? AND category IN (${marks(AP_CATS)})`, ...AP_CATS),
      max_devices: n('SELECT count(*) n FROM devices WHERE company_id=?'),
      max_vouchers_batch: 0, max_vouchers_month: 0, max_storage_mb: 0, max_api_ops: 0,
    };
  }
  // returns null if allowed, or {key,limit,used} when adding `add` more would exceed the effective limit (backend check)
  function checkLimit(cid, key, add = 1) {
    const co = q1('SELECT * FROM companies WHERE id=?', cid); if (!co) return { key, limit: 0, used: 0 };
    const limit = limitsOf(co)[key];
    if (limit < 0) return null;
    const used = usageOf(cid)[key];
    return used + add > limit ? { key, limit, used } : null;
  }
  const limitMsg = (t, r) => `${t('Plan limit reached')}: ${t((LIMITS.find((l) => l[0] === r.key) || [0, r.key])[1])} (${r.used}/${r.limit}). ${t('Open My Subscription to request an upgrade.')}`;
  const hasModule = (co, m) => { const p = getPlan(co.plan); return !!p && String(p.modules).split(',').includes(m); };

  function addInvoice(co, plan, kind, period, amount, credit, note, status = 'unpaid') {
    return run(`INSERT INTO invoices(company_id,kind,plan_code,plan_name_en,plan_name_ar,period,amount,credit,currency,status,note) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
      co.id, kind, plan.code, plan.name_en, plan.name_ar, period, amount, credit, plan.currency, status, note || '').lastInsertRowid;
  }
  // apply a plan change; existing customers/devices/users are never touched
  function applyPlanChange(co, plan, period, opts = {}) {
    const days = periodDays(plan, period);
    const price = effPrice(plan, period);
    let credit = 0;
    const end = co.subscription_ends || co.trial_ends;
    if (opts.prorate && co.price_paid > 0 && end && end > today()) {
      const oldDays = Math.max(1, periodDays(getPlan(co.plan) || plan, co.billing_period) || 30);
      credit = Math.round(co.price_paid * Math.min(1, daysBetween(today(), end) / oldDays) * 100) / 100;
    }
    const kind = price > co.price_paid ? 'upgrade' : price < co.price_paid ? 'downgrade' : 'plan_change';
    const amount = Math.max(0, Math.round((price - credit) * 100) / 100);
    const start = today(), expiry = addDays(start, days || 30);
    const isTrial = period === 'trial';
    run(`UPDATE companies SET plan=?,billing_period=?,price_paid=?,currency=?,sub_start=?,trial_ends=?,subscription_ends=?,limit_overrides='{}',status=CASE WHEN status='suspended' THEN 'suspended' WHEN ?=1 THEN 'trial' ELSE 'active' END WHERE id=?`,
      plan.code, period, price, plan.currency, start, isTrial ? expiry : null, isTrial ? null : expiry, isTrial ? 1 : 0, co.id);
    const inv = addInvoice(co, plan, kind, period, amount, credit, opts.note || '', amount === 0 ? 'paid' : 'unpaid');
    return { kind, amount, credit, invoice: inv, expiry };
  }

  // ---------- plan form
  function planFormHtml(c, t, p = {}, isNew = true) {
    const chk = (name, v, label) => `<label style="display:flex;gap:6px;align-items:center;color:var(--tx)"><input type="checkbox" name="${name}" value="1" style="width:auto" ${v ? 'checked' : ''}> ${label}</label>`;
    const mods = String(p.modules ?? 'customers,network').split(',');
    return `<form method="post" action="${isNew ? '/admin/plans' : `/admin/plans/${p.id}`}">${csrfField(c)}
<div class="card"><h3>${t('Plan names and descriptions')}</h3><div class="row">
${isNew ? field(t('Internal code'), 'code', p.code || '', { req: true }) : ''}${field(t('English name'), 'name_en', p.name_en, { req: true })}${field(t('Arabic name'), 'name_ar', p.name_ar, { req: true })}
${field(t('English description'), 'desc_en', p.desc_en, { ta: true })}${field(t('Arabic description'), 'desc_ar', p.desc_ar, { ta: true })}
${field(t('Display order'), 'sort_order', p.sort_order ?? 0, { type: 'number' })}
<div><label>${t('Plan icon or image')} (PNG/JPG, 60KB)</label><input type="file" accept="image/png,image/jpeg,image/gif,image/webp" onchange="var f=this.files[0];if(!f)return;if(f.size>60000){alert('Max 60KB');this.value='';return}var r=new FileReader();r.onload=function(){document.getElementById('icon').value=r.result;document.getElementById('iconp').src=r.result};r.readAsDataURL(f)">
<input type="hidden" id="icon" name="icon" value="${esc(p.icon || '')}"><img id="iconp" src="${esc(p.icon || '')}" style="max-height:48px;margin-top:6px" alt=""></div></div>
<p>${chk('active', p.active ?? 1, t('Active'))}${chk('recommended', p.recommended, t('Recommended / Popular'))}</p></div>
<div class="card"><h3>${t('Pricing')}</h3><div class="row">
${field(t('Currency'), 'currency', p.currency || 'EGP')}${field(t('Monthly price'), 'price_monthly', p.price_monthly ?? 0, { type: 'number' })}${field(t('Quarterly price'), 'price_quarterly', p.price_quarterly ?? 0, { type: 'number' })}
${field(t('Semi-annual price'), 'price_semiannual', p.price_semiannual ?? 0, { type: 'number' })}${field(t('Annual price'), 'price_annual', p.price_annual ?? 0, { type: 'number' })}
${field(t('Custom duration (days)'), 'custom_days', p.custom_days ?? 0, { type: 'number' })}${field(t('Custom duration price'), 'price_custom', p.price_custom ?? 0, { type: 'number' })}
${field(t('Promotional price'), 'promo_price', p.promo_price ?? 0, { type: 'number' })}${field(t('Discount percentage'), 'discount_pct', p.discount_pct ?? 0, { type: 'number' })}
${field(t('Setup fee'), 'setup_fee', p.setup_fee ?? 0, { type: 'number' })}${field(t('Trial duration (days)'), 'trial_days', p.trial_days ?? 0, { type: 'number' })}</div>
<p>${chk('trial_eligible', p.trial_eligible, t('Trial eligible'))}</p><p class="mut">${t('Changing a plan price never changes issued invoices or paid transactions. Existing subscriptions keep their price until renewal, and renewal uses the current plan price.')}</p></div>
<div class="card"><h3>${t('Plan limits')}</h3><p class="mut">${t('Tick Unlimited to remove a limit.')}</p><div class="row">
${LIMITS.map(([k, l]) => { const v = p[k] ?? (k === 'max_admins' ? 1 : 10); return `<div><label>${t(l)}</label><input type="number" min="0" name="lim_${k}" value="${v < 0 ? '' : v}"><label style="display:flex;gap:6px;align-items:center;color:var(--tx);margin:2px 0"><input type="checkbox" style="width:auto" name="unl_${k}" value="1" ${v < 0 ? 'checked' : ''}> ${t('Unlimited')}</label></div>`; }).join('')}</div></div>
<div class="card"><h3>${t('Available modules')}</h3>${MODULES.map(([k, l]) => `<label style="display:inline-flex;gap:6px;align-items:center;margin-inline-end:14px;color:var(--tx)"><input type="checkbox" name="mod_${k}" value="1" style="width:auto" ${mods.includes(k) ? 'checked' : ''}> ${t(l)}</label>`).join('')}</div>
<p><button>${t('Save')}<span class="spin"></span></button> <a class="btn sec" href="/admin/plans">${t('Cancel')}</a></p></form>`;
  }
  function parsePlan(b) {
    const o = {
      name_en: clean(b.name_en, 80), name_ar: clean(b.name_ar, 80), desc_en: clean(b.desc_en, 400), desc_ar: clean(b.desc_ar, 400), icon: clean(b.icon, 100000),
      sort_order: Math.round(num(b.sort_order, 0, -1000, 1000)), active: b.active ? 1 : 0, recommended: b.recommended ? 1 : 0,
      currency: clean(b.currency, 5).toUpperCase() || 'EGP', price_monthly: num(b.price_monthly), price_quarterly: num(b.price_quarterly), price_semiannual: num(b.price_semiannual),
      price_annual: num(b.price_annual), price_custom: num(b.price_custom), custom_days: Math.round(num(b.custom_days, 0, 0, 3650)), promo_price: num(b.promo_price),
      discount_pct: num(b.discount_pct, 0, 0, 100), trial_eligible: b.trial_eligible ? 1 : 0, trial_days: Math.round(num(b.trial_days, 0, 0, 365)), setup_fee: num(b.setup_fee),
      modules: MODULES.filter(([k]) => b['mod_' + k]).map((m) => m[0]).join(','),
    };
    if (!o.name_en || !o.name_ar || !validIcon(o.icon) || !/^[A-Z]{2,5}$/.test(o.currency)) return null;
    for (const k of LIMIT_KEYS) o[k] = b['unl_' + k] ? -1 : Math.round(num(b['lim_' + k], 0, 0, 1e9));
    return o;
  }
  const PCOLS = ['name_en', 'name_ar', 'desc_en', 'desc_ar', 'icon', 'sort_order', 'active', 'recommended', 'currency', 'price_monthly', 'price_quarterly', 'price_semiannual', 'price_annual', 'price_custom', 'custom_days', 'promo_price', 'discount_pct', 'trial_eligible', 'trial_days', 'setup_fee', ...LIMIT_KEYS, 'modules'];

  // ---------- super admin: plans
  h.app.get('/admin/plans', needSuper, (req, res) => {
    const t = req.i.t, c = ctx(req);
    const rows = q('SELECT * FROM plans ORDER BY archived, sort_order, id');
    const uses = (p) => q1("SELECT count(*) n FROM companies WHERE plan=? AND status<>'suspended'", p.code).n;
    res.send(page(c, 'Subscription Plans & Pricing', `<div class="card"><h3>${t('Subscription Plans & Pricing')}</h3><p class="mut">${t('Changing a plan price never changes issued invoices or paid transactions. Existing subscriptions keep their price until renewal, and renewal uses the current plan price.')}</p><a class="btn" href="/admin/plans/new">${t('New plan')}</a></div>
<div class="card tbl"><table><tr><th></th><th>${t('Name')}</th><th>${t('Monthly price')}</th><th>${t('Annual price')}</th><th>${t('Maximum Client Admin accounts')}</th><th>${t('Maximum employee accounts')}</th><th>${t('Maximum managed subscribers')}</th><th>${t('Maximum MikroTik routers')}</th><th>${t('Maximum Access Points')}</th><th>${t('Clients')}</th><th>${t('Status')}</th><th></th></tr>
${rows.map((p) => `<tr><td>${p.icon ? `<img src="${esc(p.icon)}" style="height:28px" alt="">` : ''}</td><td>${esc(planName(p, req.i))} ${p.recommended ? `<span class="badge trial">${t('Recommended')}</span>` : ''}<br><span class="mut">${esc(i18nOther(p, req.i))}</span></td>
<td>${esc(money(p.price_monthly, p.currency))}</td><td>${esc(money(p.price_annual, p.currency))}</td><td>${lim(p.max_admins)}</td><td>${lim(p.max_employees)}</td><td>${lim(p.max_subscribers)}</td><td>${lim(p.max_routers)}</td><td>${lim(p.max_aps)}</td><td>${uses(p)}</td>
<td>${p.archived ? `<span class="badge expired">${t('Archived')}</span>` : p.active ? `<span class="badge active">${t('Active')}</span>` : `<span class="badge">${t('Inactive')}</span>`}</td><td><a href="/admin/plans/${p.id}">${t('Edit')}</a></td></tr>`).join('')}</table></div>`, nav(req)));
  });
  const i18nOther = (p, i) => (i.lang === 'ar' ? p.name_en : p.name_ar);
  h.app.get('/admin/plans/new', needSuper, (req, res) => {
    const t = req.i.t, c = ctx(req);
    res.send(page(c, 'New plan', planFormHtml(c, t, {}, true), nav(req)));
  });
  h.app.post('/admin/plans', needSuper, (req, res) => {
    const t = req.i.t, b = req.body, code = clean(b.code, 40).toLowerCase();
    const o = parsePlan(b);
    if (!o || !/^[a-z0-9_-]{2,40}$/.test(code)) return go(res, '/admin/plans/new', 'err', t('required'));
    if (q1('SELECT 1 x FROM plans WHERE code=?', code)) return go(res, '/admin/plans/new', 'err', t('duplicate'));
    const id = run(`INSERT INTO plans(code,${PCOLS.join(',')}) VALUES(?,${PCOLS.map(() => '?').join(',')})`, code, ...PCOLS.map((k) => o[k])).lastInsertRowid;
    audit(req, 'plan_created', o.name_en, null);
    go(res, `/admin/plans/${id}`, 'ok', t('Created'));
  });
  const planOr404 = (req, res) => { const p = getPlan(Number(req.params.id)); if (!p) { deny(req, res, 404); return null; } return p; };
  h.app.get('/admin/plans/:id', needSuper, (req, res) => {
    const p = planOr404(req, res); if (!p) return;
    const t = req.i.t, c = ctx(req);
    const n = q1('SELECT count(*) n FROM companies WHERE plan=?', p.code).n;
    const act = (path, label, cls = 'sec') => `<form class="inline" method="post" action="/admin/plans/${p.id}/${path}">${csrfField(c)}<button class="${cls}">${label}</button></form>`;
    res.send(page(c, planName(p, req.i), `<div class="card"><h3>${esc(planName(p, req.i))}</h3><p>${p.archived ? act('archive', t('Restore'), 'ok') : act('archive', t('Archive'))} ${p.active ? act('toggle', t('Deactivate'), 'bad') : act('toggle', t('Activate'), 'ok')}
${act('delete', t('Delete'), 'bad')}</p><p class="mut">${t('Clients')}: ${n}. ${t('A plan with clients cannot be deleted. It is archived instead.')}</p></div>${planFormHtml(c, t, p, false)}`, nav(req)));
  });
  h.app.post('/admin/plans/:id', needSuper, (req, res) => {
    const p = planOr404(req, res); if (!p) return;
    const t = req.i.t, o = parsePlan(req.body);
    if (!o) return go(res, `/admin/plans/${p.id}`, 'err', t('required'));
    run(`UPDATE plans SET ${PCOLS.map((k) => `${k}=?`).join(',')} WHERE id=?`, ...PCOLS.map((k) => o[k]), p.id);
    audit(req, 'plan_updated', p.code, null);
    go(res, `/admin/plans/${p.id}`, 'ok', t('Saved'));
  });
  h.app.post('/admin/plans/:id/toggle', needSuper, (req, res) => {
    const p = planOr404(req, res); if (!p) return;
    run('UPDATE plans SET active=? WHERE id=?', p.active ? 0 : 1, p.id);
    audit(req, p.active ? 'plan_deactivated' : 'plan_activated', p.code, null);
    go(res, `/admin/plans/${p.id}`, 'ok', req.i.t('Updated'));
  });
  h.app.post('/admin/plans/:id/archive', needSuper, (req, res) => {
    const p = planOr404(req, res); if (!p) return;
    run('UPDATE plans SET archived=?, active=CASE WHEN ?=1 THEN 0 ELSE active END WHERE id=?', p.archived ? 0 : 1, p.archived ? 0 : 1, p.id);
    audit(req, 'plan_archive_toggled', p.code, null);
    go(res, `/admin/plans/${p.id}`, 'ok', req.i.t('Updated'));
  });
  h.app.post('/admin/plans/:id/delete', needSuper, (req, res) => {
    const p = planOr404(req, res); if (!p) return;
    const t = req.i.t;
    if (q1('SELECT count(*) n FROM companies WHERE plan=?', p.code).n > 0 || q1('SELECT count(*) n FROM invoices WHERE plan_code=?', p.code).n > 0) {
      run('UPDATE plans SET archived=1, active=0 WHERE id=?', p.id);
      audit(req, 'plan_archived_instead_of_delete', p.code, null);
      return go(res, `/admin/plans/${p.id}`, 'ok', t('Plan is in use, so it was archived instead of deleted'));
    }
    run('DELETE FROM plans WHERE id=?', p.id);
    audit(req, 'plan_deleted', p.code, null);
    go(res, '/admin/plans', 'ok', t('Deleted'));
  });

  // ---------- super admin: per-client subscription controls (rendered inside the client page)
  function adminSubscriptionCard(req, c, co) {
    const t = req.i.t, p = getPlan(co.plan);
    const plans = q('SELECT * FROM plans WHERE active=1 AND archived=0 ORDER BY sort_order,id');
    const invs = q('SELECT * FROM invoices WHERE company_id=? ORDER BY id DESC LIMIT 20', co.id);
    const reqs = q("SELECT r.*, p.name_en, p.name_ar, p.code FROM plan_requests r JOIN plans p ON p.id=r.plan_id WHERE r.company_id=? AND r.status='pending' ORDER BY r.id", co.id);
    const ov = overridesOf(co), L = limitsOf(co), U = usageOf(co.id);
    const f = (path) => `method="post" action="/admin/companies/${co.id}/${path}"`;
    return `<div class="card"><h3>${t('Subscription')}</h3>
<p>${t('Plan')}: <b>${esc(planName(p, req.i))}</b> | ${t('Billing Period')}: ${esc(periodLabel(co.billing_period, t))} | ${t('Plan Price')}: ${esc(money(co.price_paid, co.currency))} | ${t('Subscription Start Date')}: ${esc(co.sub_start || '-')} | ${t('Subscription Expiration Date')}: ${esc(co.subscription_ends || co.trial_ends || '-')}</p>
${reqs.length ? `<h4>${t('Pending plan requests')}</h4>${reqs.map((r) => `<form class="inline" ${f(`requests/${r.id}`)}>${csrfField(c)}${esc(req.i.lang === 'ar' ? r.name_ar : r.name_en)} / ${esc(periodLabel(r.period, t))}
 <label style="display:inline-flex;gap:4px;color:var(--tx)"><input type="checkbox" name="prorate" value="1" style="width:auto"> ${t('Prorate')}</label> <button name="decision" value="approve" class="ok">${t('Approve')}</button> <button name="decision" value="reject" class="bad">${t('Reject')}</button></form><br>`).join('')}` : ''}
<form ${f('plan')} class="row">${csrfField(c)}${select(t('Plan'), 'plan_id', '', plans.map((x) => [x.id, planName(x, req.i)]))}${select(t('Billing Period'), 'period', 'monthly', ['trial', 'monthly', 'quarterly', 'semiannual', 'annual', 'custom'].map((x) => [x, periodLabel(x, t)]))}
<div><label>${t('Prorate')}</label><select name="prorate"><option value="">${t('No')}</option><option value="1">${t('Yes')}</option></select></div><div style="padding-top:22px"><button>${t('Change plan')}</button></div></form>
<form ${f('renew')} class="row">${csrfField(c)}<div style="padding-top:22px"><button class="sec">${t('Renew subscription')}</button> <span class="mut">${t('Renewal uses the current plan price and extends from the later of today and the expiry date.')}</span></div></form>
<h4>${t('Limits')}</h4><div class="tbl"><table><tr><th></th><th>${t('Used')}</th><th>${t('Allowed')}</th><th></th></tr>${LIMITS.map(([k, l]) => `<tr><td>${t(l)}</td><td>${U[k]}</td><td>${lim(L[k])}</td><td>${ov[k] ? `${t('Exception')}${ov[k].until ? ' → ' + esc(ov[k].until) : ''}` : ''}</td></tr>`).join('')}</table></div>
<form ${f('exception')} class="row">${csrfField(c)}${select(t('Limit'), 'key', '', LIMITS.map(([k, l]) => [k, t(l)]))}${field(t('New value (empty = unlimited)'), 'value', '', { type: 'number' })}${field(t('Days (empty = permanent)'), 'days', '', { type: 'number' })}<div style="padding-top:22px"><button>${t('Grant limit increase')}</button></div></form>
<h4>${t('Invoices')}</h4><div class="tbl"><table><tr><th>#</th><th>${t('Created')}</th><th>${t('Type')}</th><th>${t('Plan')}</th><th>${t('Amount')}</th><th>${t('Status')}</th><th></th></tr>${invs.map((v) => `<tr><td>${v.id}</td><td>${esc(v.created_at)}</td><td>${t(v.kind)}</td><td>${esc(req.i.lang === 'ar' ? v.plan_name_ar : v.plan_name_en)}</td><td>${esc(money(v.amount, v.currency))}${v.credit ? ` (-${esc(money(v.credit, v.currency))})` : ''}</td><td>${badge(v.status, t)}</td>
<td>${v.status === 'unpaid' ? `<form class="inline" ${f(`invoices/${v.id}/paid`)}>${csrfField(c)}<button class="ok">${t('Mark paid')}</button></form>` : ''}</td></tr>`).join('') || `<tr><td colspan="7">${t('No results')}</td></tr>`}</table></div></div>`;
  }
  const coOr404 = (req, res) => { const co = q1('SELECT * FROM companies WHERE id=?', Number(req.params.id)); if (!co) { deny(req, res, 404); return null; } return co; };
  const back = (co) => `/admin/companies/${co.id}`;
  h.app.post('/admin/companies/:id/plan', needSuper, (req, res) => {
    const co = coOr404(req, res); if (!co) return; const t = req.i.t;
    const p = getPlan(Number(req.body.plan_id));
    if (!p || !p.active || p.archived || !availablePeriods(p).includes(req.body.period)) return go(res, back(co), 'err', t('Plan is not available'));
    const r = applyPlanChange(co, p, req.body.period, { prorate: !!req.body.prorate, note: 'admin' });
    audit(req, 'plan_changed', `${p.code} ${req.body.period} ${r.kind}`, co.id);
    go(res, back(co), 'ok', t('Updated'));
  });
  h.app.post('/admin/companies/:id/renew', needSuper, (req, res) => {
    const co = coOr404(req, res); if (!co) return; const t = req.i.t;
    const p = getPlan(co.plan); const period = co.billing_period === 'trial' ? 'monthly' : co.billing_period;
    if (!p || co.billing_period === 'trial' && !(p.price_monthly > 0)) return go(res, back(co), 'err', t('Choose a paid plan first'));
    const price = effPrice(p, period), days = periodDays(p, period) || 30;
    const base = new Date(Math.max(Date.now(), new Date(co.subscription_ends || co.trial_ends || 0).getTime())).toISOString().slice(0, 10);
    run("UPDATE companies SET billing_period=?, price_paid=?, subscription_ends=?, trial_ends=NULL, status=CASE WHEN status='suspended' THEN 'suspended' ELSE 'active' END WHERE id=?", period, price, addDays(base, days), co.id);
    addInvoice(co, p, 'renewal', period, price, 0, '', price === 0 ? 'paid' : 'unpaid');
    audit(req, 'subscription_renewed', `${p.code} ${period}`, co.id);
    go(res, back(co), 'ok', t('Updated'));
  });
  h.app.post('/admin/companies/:id/exception', needSuper, (req, res) => {
    const co = coOr404(req, res); if (!co) return; const t = req.i.t, b = req.body;
    if (!LIMIT_KEYS.includes(b.key)) return go(res, back(co), 'err', t('required'));
    const ov = JSON.parse(co.limit_overrides || '{}');
    const days = b.days === '' || b.days === undefined ? 0 : Math.round(num(b.days, 0, 0, 3650));
    ov[b.key] = { v: b.value === '' || b.value === undefined ? -1 : Math.round(num(b.value, 0, 0, 1e9)), until: days ? addDays(today(), days) : null };
    run('UPDATE companies SET limit_overrides=? WHERE id=?', JSON.stringify(ov), co.id);
    audit(req, 'limit_exception_granted', `${b.key}=${ov[b.key].v} until ${ov[b.key].until || 'permanent'}`, co.id);
    go(res, back(co), 'ok', t('Updated'));
  });
  h.app.post('/admin/companies/:id/invoices/:iid/paid', needSuper, (req, res) => {
    const co = coOr404(req, res); if (!co) return;
    run("UPDATE invoices SET status='paid', paid_at=datetime('now') WHERE id=? AND company_id=?", Number(req.params.iid), co.id);
    audit(req, 'invoice_paid', String(req.params.iid), co.id);
    go(res, back(co), 'ok', req.i.t('Updated'));
  });
  h.app.post('/admin/companies/:id/requests/:rid', needSuper, (req, res) => {
    const co = coOr404(req, res); if (!co) return; const t = req.i.t;
    const r = q1("SELECT * FROM plan_requests WHERE id=? AND company_id=? AND status='pending'", Number(req.params.rid), co.id);
    if (!r) return deny(req, res, 404);
    if (req.body.decision === 'approve') {
      const p = getPlan(r.plan_id);
      if (!p || !p.active || p.archived || !availablePeriods(p).includes(r.period)) return go(res, back(co), 'err', t('Plan is not available'));
      applyPlanChange(co, p, r.period, { prorate: !!req.body.prorate, note: 'request' });
      run("UPDATE plan_requests SET status='approved', decided_at=datetime('now') WHERE id=?", r.id);
      audit(req, 'plan_request_approved', p.code, co.id);
    } else {
      run("UPDATE plan_requests SET status='rejected', decided_at=datetime('now') WHERE id=?", r.id);
      audit(req, 'plan_request_rejected', String(r.id), co.id);
    }
    go(res, back(co), 'ok', t('Updated'));
  });

  // ---------- client admin: My Subscription
  h.app.get('/app/subscription', needAdmin, (req, res) => {
    const t = req.i.t, c = ctx(req), cid = req.user.company_id;
    const co = q1('SELECT * FROM companies WHERE id=?', cid), p = getPlan(co.plan);
    const L = limitsOf(co), U = usageOf(cid), end = co.subscription_ends || co.trial_ends;
    const remaining = end ? daysBetween(today(), end) : null;
    const lastInv = q1('SELECT * FROM invoices WHERE company_id=? ORDER BY id DESC LIMIT 1', cid);
    const pending = q1("SELECT 1 x FROM plan_requests WHERE company_id=? AND status='pending'", cid);
    const plans = q('SELECT * FROM plans WHERE active=1 AND archived=0 ORDER BY sort_order,id');
    const row = (k, l) => { const over = L[k] >= 0 && U[k] > L[k]; const full = L[k] >= 0 && U[k] >= L[k]; return `<tr><td>${t(l)}</td><td>${U[k]} / ${lim(L[k])}</td><td>${over ? `<span class="badge expired">${t('Over limit: existing records are kept, new additions are blocked')}</span>` : full ? `<span class="badge trial">${t('Limit reached')}</span>` : ''}</td></tr>`; };
    const feats = String(p?.modules || '').split(',').filter(Boolean).map((m) => t((MODULES.find((x) => x[0] === m) || [0, m])[1])).join(', ');
    res.send(page(c, 'My Subscription', `<div class="card"><h3>${t('My Subscription')}</h3><div class="row">
<div class="stat"><span>${t('Current plan')}</span><b>${esc(planName(p, req.i))}</b></div><div class="stat"><span>${t('Plan Price')}</span><b>${esc(money(co.price_paid, co.currency))}</b><span>${esc(periodLabel(co.billing_period, t))}</span></div>
<div class="stat"><span>${t('Subscription Start Date')}</span><b style="font-size:20px">${esc(co.sub_start || '-')}</b></div><div class="stat"><span>${t('Subscription Expiration Date')}</span><b style="font-size:20px">${esc(end || '-')}</b></div>
<div class="stat"><span>${t('Remaining days')}</span><b>${remaining === null ? '-' : Math.max(0, remaining)}</b></div><div class="stat"><span>${t('Payment status')}</span><b style="font-size:20px">${lastInv ? t(lastInv.status[0].toUpperCase() + lastInv.status.slice(1)) : '-'}</b></div></div>
<p>${t('Available features')}: ${esc(feats || '-')}</p></div>
<div class="card tbl"><h3>${t('Usage')}</h3><table><tr><th></th><th>${t('Used')} / ${t('Allowed')}</th><th></th></tr>${LIMITS.filter(([k]) => ['max_subscribers', 'max_admins', 'max_employees', 'max_hotspot', 'max_pppoe', 'max_routers', 'max_aps', 'max_devices', 'max_vouchers_month'].includes(k)).map(([k, l]) => row(k, l)).join('')}</table></div>
<div class="card tbl"><h3>${t('Plan comparison')}</h3>${pending ? `<p class="flash ok">${t('You have a pending plan request')}</p>` : ''}<table><tr><th></th>${plans.map((x) => `<th>${esc(planName(x, req.i))}${x.recommended ? ` <span class="badge trial">${t('Recommended')}</span>` : ''}${x.code === co.plan ? ` <span class="badge active">${t('Current plan')}</span>` : ''}</th>`).join('')}</tr>
<tr><td>${t('Monthly price')}</td>${plans.map((x) => `<td>${esc(money(effPrice(x, 'monthly'), x.currency))}</td>`).join('')}</tr><tr><td>${t('Annual price')}</td>${plans.map((x) => `<td>${esc(money(effPrice(x, 'annual'), x.currency))}</td>`).join('')}</tr>
${LIMITS.filter(([k]) => ['max_admins', 'max_employees', 'max_subscribers', 'max_routers', 'max_aps'].includes(k)).map(([k, l]) => `<tr><td>${t(l)}</td>${plans.map((x) => `<td>${lim(x[k])}</td>`).join('')}</tr>`).join('')}
<tr><td></td>${plans.map((x) => `<td>${x.code === co.plan ? '' : `<form method="post" action="/app/subscription/request">${csrfField(c)}<input type="hidden" name="plan_id" value="${x.id}"><select name="period">${availablePeriods(x).filter((z) => z !== 'trial').map((z) => `<option value="${z}">${esc(periodLabel(z, t))}</option>`).join('')}</select><button style="margin-top:6px">${t('Upgrade Plan')}</button></form>`}</td>`).join('')}</tr></table>
<p class="mut">${t('Downgrading never deletes your data. If you use more than the new plan allows, existing records stay and new additions are blocked until you are within limits or an exception is approved.')}</p></div>`, nav(req)));
  });
  h.app.post('/app/subscription/request', needAdmin, (req, res) => {
    const t = req.i.t, cid = req.user.company_id, p = getPlan(Number(req.body.plan_id));
    if (!p || !p.active || p.archived || req.body.period === 'trial' || !availablePeriods(p).includes(req.body.period)) return go(res, '/app/subscription', 'err', t('Plan is not available'));
    if (q1("SELECT 1 x FROM plan_requests WHERE company_id=? AND status='pending'", cid)) return go(res, '/app/subscription', 'err', t('You have a pending plan request'));
    run('INSERT INTO plan_requests(company_id,plan_id,period,requested_by) VALUES(?,?,?,?)', cid, p.id, req.body.period, req.user.id);
    audit(req, 'plan_requested', `${p.code} ${req.body.period}`);
    go(res, '/app/subscription', 'ok', t('Request sent. The platform owner will review it.'));
  });

  // ---------- create-client form data (used by app.js)
  function planOptions(i, includeTrial = true) {
    return q('SELECT * FROM plans WHERE active=1 AND archived=0 ORDER BY sort_order,id').map((p) => ({
      id: p.id, name: planName(p, i), cur: p.currency, setup: p.setup_fee, trial_days: p.trial_days, trial: !!p.trial_eligible && p.trial_days > 0,
      periods: availablePeriods(p).map((per) => ({ code: per, days: periodDays(p, per), price: effPrice(p, per), base: basePrice(p, per) })),
      limits: Object.fromEntries(LIMIT_KEYS.map((k) => [k, p[k]])), desc: planDesc(p, i),
    }));
  }
  function limitsFromForm(b, p) {
    const out = {}, over = {};
    for (const k of LIMIT_KEYS) {
      let v = p[k];
      if (b['unl_' + k]) v = -1;
      else if (b['lim_' + k] !== undefined && String(b['lim_' + k]).trim() !== '') v = Math.round(num(b['lim_' + k], p[k], 0, 1e9));
      out[k] = v;
      if (v !== p[k]) over[k] = { v, until: null };
    }
    return { out, over };
  }

  return { LIMITS, LIMIT_KEYS, PERIODS, getPlan, planName, periodLabel, periodDays, effPrice, availablePeriods, limitsOf, usageOf, checkLimit, limitMsg, hasModule, applyPlanChange, addInvoice, adminSubscriptionCard, planOptions, limitsFromForm, lim, validIcon, validDate, today, addDays, money };
}
module.exports = { init, LIMITS, PERIODS, ROUTER_CATS, AP_CATS };
