const express = require('express');
const crypto = require('node:crypto');
const { hashPassword, verifyPassword, passwordProblem, sha } = require('./db');
const { make } = require('./i18n');
const V = require('./views');
const { init: plansInit } = require('./plans');
const { init: devicesInit, PAGES: DEV_PAGES } = require('./devices');
const { init: paymentsInit } = require('./payments');
const { init: financeInit } = require('./finance');
const { init: vouchersInit } = require('./vouchers');
const { init: reportsInit } = require('./reports');
const makePortal = require('./portal');
const makeBackup = require('./autobackup');
const TF = require('./twofa');
const secureInit = require('./secure');
const { infoGrid, esc, page, csrfField, badge, field, select } = V;

const SESSION_TTL = 8 * 3600e3, REMEMBER_TTL = 30 * 24 * 3600e3;
const MAX_FAILS = 5, LOCK_MS = 15 * 60e3;
const CUSTOMER_PERMS = ['customers.view', 'customers.add', 'customers.edit', 'customers.delete', 'customers.export', 'audit.view'];
const ROLE_PRESETS = {
  'Company Manager': CUSTOMER_PERMS,
  'Network Administrator': ['customers.view', 'customers.edit'],
  'Technical Support': ['customers.view', 'customers.edit'],
  'Sales Employee': ['customers.view', 'customers.add'],
  'Cashier': ['customers.view'],
  'Read-only Employee': ['customers.view'],
};
const PLANS = ['trial', 'basic', 'pro', 'enterprise'];
const nowIso = () => new Date().toISOString().slice(0, 19).replace('T', ' ');
const addDays = (d, n) => new Date(d.getTime() + n * 864e5).toISOString().slice(0, 10);
const clean = (v, max = 300) => String(v ?? '').trim().slice(0, max);

function createApp(db, opts = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', opts.trustProxy ? 1 : false);
  app.use((req, res, next) => { const h = opts.trustProxy && req.headers['cf-connecting-ip']; if (h && /^[0-9a-fA-F:.]{3,45}$/.test(h)) Object.defineProperty(req, 'ip', { value: h }); next(); });
  const PT = makePortal({ secureCookies: opts.secureCookies });
  PT.bind(db);
  app.use(PT.hostGuard);
  app.use(express.urlencoded({ extended: false, limit: '400kb' }));
  app.use(['/api/enroll', '/api/router'], express.text({ type: '*/*', limit: '32kb' }));
  try { run('DELETE FROM login_history WHERE ts<?', new Date(Date.now() - 90 * 864e5).toISOString().slice(0, 19).replace('T', ' ')); } catch { }
  const sqlTs = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
  // persistent per-IP throttle: counts attempts recorded in login_history (survives restarts)
  const tooMany = (ip) => q1('SELECT count(*) n FROM login_history WHERE ip=? AND ts>?', ip || '', sqlTs(Date.now() - 10 * 60e3)).n >= 30;

  const q = (sql, ...a) => db.prepare(sql).all(...a);
  const q1 = (sql, ...a) => db.prepare(sql).get(...a);
  const run = (sql, ...a) => db.prepare(sql).run(...a);
  const audit = (req, action, detail = '', companyId = undefined) =>
    run('INSERT INTO audit_log(company_id,user_id,action,detail,ip) VALUES(?,?,?,?,?)',
      companyId !== undefined ? companyId : (req.user ? req.user.company_id : null), req.user ? req.user.id : null, action, detail, req.ip);

  // ---- context: language, session, csrf
  let lastReact = 0;
  const reactivate = () => {
    const today = new Date().toISOString().slice(0, 10);
    for (const co of q("SELECT id,name,plan FROM companies WHERE status='suspended' AND suspended_until IS NOT NULL AND suspended_until<=?", today)) {
      run("UPDATE companies SET status=?, suspended_until=NULL WHERE id=? AND status='suspended'", co.plan === 'trial' ? 'trial' : 'active', co.id);
      run("INSERT INTO audit_log(company_id,user_id,action,detail) VALUES(?,?,?,?)", co.id, null, 'company_auto_reactivated', co.name);
    }
  };
  setInterval(() => { try { reactivate(); } catch (e) { /* retried on next request */ } }, 10 * 60 * 1000).unref();
  app.use((req, res, next) => {
    if (Date.now() - lastReact > 30000) { lastReact = Date.now(); try { reactivate(); } catch (e) { /* ignore */ } }
    const cookies = Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split('=')).filter((p) => p[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));
    req.cookies = cookies;
    req.i = make(cookies.lang === 'en' ? 'en' : 'ar');
    req.user = null; req.session = null;
    if (cookies.sid) {
      const s = q1('SELECT * FROM sessions WHERE token_hash=?', sha(cookies.sid));
      if (s && s.expires_at > Date.now()) {
        const u = q1('SELECT * FROM users WHERE id=?', s.user_id);
        const c = u && u.company_id ? q1('SELECT status FROM companies WHERE id=?', u.company_id) : null;
        if (u && u.status === 'active' && !(c && c.status === 'suspended')) {
          req.user = u; req.session = s;
          u.perms = u.role === 'employee' ? JSON.parse(u.permissions) : null;
          run('UPDATE sessions SET last_seen=? WHERE token_hash=?', Date.now(), s.token_hash);
        } else run('DELETE FROM sessions WHERE token_hash=?', s.token_hash);
      } else if (s) run('DELETE FROM sessions WHERE token_hash=?', s.token_hash);
    }
    req.csrf = req.session ? req.session.csrf : (cookies.pre || '');
    if (!req.session && !cookies.pre) {
      req.csrf = crypto.randomBytes(16).toString('hex');
      res.append('Set-Cookie', `pre=${req.csrf}; HttpOnly; SameSite=Lax; Path=/${opts.secureCookies ? '; Secure' : ''}`);
    }
    const f = cookies.flash;
    if (f) { try { req.flash = JSON.parse(f); } catch { } res.append('Set-Cookie', 'flash=; Max-Age=0; Path=/'); }
    res.setHeader('X-Frame-Options', 'DENY');
    const nonce = crypto.randomBytes(16).toString('base64'); req.nonce = nonce;
    res.setHeader('Content-Security-Policy', `default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-${nonce}'; script-src-attr 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'${opts.secureCookies ? '; upgrade-insecure-requests' : ''}`);
    const send = res.send.bind(res);
    res.send = (b) => send(typeof b === 'string' && b.includes('<script>') ? b.split('<script>').join(`<script nonce="${nonce}">`) : b);
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    if (opts.secureCookies) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Cache-Control', 'no-store');
    next();
  });
  app.use(PT.portalSession);
  app.use((req, res, next) => {
    if (req.method === 'POST' && req.path !== '/api/enroll' && !req.path.startsWith('/api/router/')) {
      const tok = req.body && req.body._csrf;
      if (!tok || !req.csrf || tok.length !== req.csrf.length || !crypto.timingSafeEqual(Buffer.from(tok), Buffer.from(req.csrf)))
        return res.status(403).send('Invalid CSRF token');
    }
    next();
  });
  for (const pn of ['id', 'iid', 'rid', 'uid']) app.param(pn, (req, res, next, v) => (/^\d{1,9}$/.test(v) ? next() : res.status(404).send('Not found')));
  const ctx = (req) => ({ i: req.i, user: req.user, csrf: req.csrf, flash: req.flash, path: req.originalUrl });
  const setFlash = (res, type, msg) => res.append('Set-Cookie', `flash=${encodeURIComponent(JSON.stringify({ type, msg }))}; Path=/; HttpOnly; SameSite=Lax; Max-Age=30`);
  const go = (res, url, type, msg) => { if (type) setFlash(res, type, msg); res.redirect(303, url); };
  const noModule = (req, res) => res.status(403).send(page(ctx(req), 'Error', `<div class="card"><h3>${req.i.t('Not included in your plan')}</h3><p>${req.i.t('This section is not part of your current plan. Open My Subscription to upgrade.')}</p><a class="btn" href="/app/subscription">${req.i.t('My Subscription')}</a></div>`));
  const deny = (req, res, code = 403) => code === 'module' ? noModule(req, res) : res.status(code).send(page(ctx(req), 'Error', `<div class="card"><h3>${req.i.t(code === 404 ? 'Not found' : 'Forbidden')}</h3></div>`));

  // ---- guards
  // Two-factor is required for the super admin when REQUIRE_SUPER_2FA=1. A super admin without 2FA can still sign in with the
  // password, but can only reach the 2FA setup page (and logout) until it is enabled, so nobody gets locked out.
  const requireSuper2fa = opts.requireSuper2fa !== undefined ? opts.requireSuper2fa : process.env.REQUIRE_SUPER_2FA === '1';
  app.use((req, res, next) => {
    const u = req.user;
    if (!requireSuper2fa || !u || u.role !== 'super_admin' || u.totp_on) return next();
    const p = req.path;
    if (p.startsWith('/account/2fa') || p === '/logout' || p.startsWith('/lang/') || p === '/health') return next();
    if (req.method !== 'GET') return res.status(403).send('Two-factor authentication required');
    return go(res, '/account/2fa', 'warn', req.i.t('Two-factor authentication is required for the super admin. Set it up below to continue.'));
  });
  const needLogin = (req, res, next) => (req.user ? next() : res.redirect(303, '/login'));
  const needSuper = (req, res, next) => (req.user && req.user.role === 'super_admin' ? next() : req.user ? deny(req, res) : res.redirect(303, '/admin/login'));
  const needCompany = (req, res, next) => (req.user && req.user.company_id ? next() : req.user ? deny(req, res) : res.redirect(303, '/login'));
  const can = (u, perm) => u.role === 'company_admin' || (u.role === 'employee' && u.perms.includes(perm));
  const need = (perm) => (req, res, next) => (can(req.user, perm) ? next() : deny(req, res));
  const needAdmin = (req, res, next) => (req.user && req.user.role === 'company_admin' ? next() : req.user ? deny(req, res) : res.redirect(303, '/login'));
  const home = (u) => (u.role === 'super_admin' ? '/admin' : '/app');
  const P = plansInit({ app, db, q, q1, run, audit, ctx, go, deny, needSuper, needAdmin, nav: (req) => nav(req) });
  paymentsInit({ app, db, q, q1, run, audit, ctx, go, deny, needSuper, needAdmin, nav: (req) => nav(req) });
  const FIN = financeInit({ app, db, q, q1, run, audit, ctx, go, deny, needAdmin, nav: (req) => nav(req) });
  vouchersInit({ app, db, q, q1, run, audit, ctx, go, deny, needAdmin, nav: (req) => nav(req), P });
  const S = secureInit(q1, run); S.setQ(q); try { S.migrate(); } catch (e) { console.error('secure migrate', e.message); }
  TF.init({ requireSuper2fa, S, app, q1, run, audit, ctx, go, needLogin, verifyPassword, nav: (req) => nav(req) });
  const RPT = reportsInit({ app, q, q1, ctx, needAdmin, deny, nav: (req) => nav(req), P });
  const D = devicesInit({ S, app, db, q, q1, run, audit, ctx, go, deny, needAdmin, nav: (req) => nav(req) }, P);

  // ---- language / root
  app.get('/lang/:l', (req, res) => {
    res.append('Set-Cookie', `lang=${req.params.l === 'en' ? 'en' : 'ar'}; Path=/; Max-Age=31536000; SameSite=Lax`);
    const back = String(req.query.back || '/');
    res.redirect(303, /^\/(?![\/\\])[^\r\n\\]*$/.test(back) ? back : '/');
  });
  app.get('/', (req, res) => res.redirect(303, req.user ? home(req.user) : '/login'));
  app.get('/health', (req, res) => res.json({ ok: true }));

  // ---- auth
  app.get('/login', (req, res) => (req.user ? res.redirect(303, home(req.user)) : res.send(V.login(ctx(req), req.flash && req.flash.msg))));
  app.get('/admin/login', (req, res) => (req.user ? res.redirect(303, home(req.user)) : res.send(V.login({ ...ctx(req), admin: true }, req.flash && req.flash.msg))));
  app.post('/login', (req, res) => {
    const t = req.i.t;
    const fail = (msg, status = 401) => res.status(status).send(V.login(ctx(req), t(msg)));
    const ident = clean(req.body.identifier, 200).toLowerCase(), pw = String(req.body.password || '');
    if (tooMany(req.ip)) return fail('Too many attempts', 429);
    const u = q1('SELECT * FROM users WHERE lower(username)=? OR lower(email)=?', ident, ident);
    const log = (ok, reason) => run('INSERT INTO login_history(user_id,identifier,success,reason,ip) VALUES(?,?,?,?,?)', u ? u.id : null, ident, ok ? 1 : 0, reason, req.ip);
    if (!u) { verifyPassword(pw, 'scrypt$00$00'); log(0, 'unknown'); return fail('Invalid credentials'); }
    if (u.locked_until > Date.now()) { log(0, 'locked'); return fail('Account locked, try later', 423); }
    if (!verifyPassword(pw, u.password_hash)) {
      const n = u.failed_attempts + 1;
      if (n >= MAX_FAILS) run('UPDATE users SET failed_attempts=0, locked_until=? WHERE id=?', Date.now() + LOCK_MS, u.id);
      else run('UPDATE users SET failed_attempts=? WHERE id=?', n, u.id);
      log(0, 'bad_password'); return fail('Invalid credentials');
    }
    if (u.status !== 'active') { log(0, 'disabled'); return fail('Invalid credentials'); }
    if (!PT.loginAllowed(req, u)) { log(0, 'wrong_portal'); return fail('Invalid credentials'); }
    if (u.company_id) {
      const c = q1('SELECT status FROM companies WHERE id=?', u.company_id);
      if (!c || c.status === 'suspended') { log(0, 'company_suspended'); return fail('Company is suspended', 403); }
    }
    if (u.totp_on) {
      const pt = crypto.randomBytes(24).toString('hex');
      pend2fa.set(pt, { uid: u.id, remember: !!req.body.remember, exp: Date.now() + 5 * 60e3, tries: 0 });
      res.append('Set-Cookie', `p2=${pt}; HttpOnly; SameSite=Lax; Path=/; Max-Age=300${opts.secureCookies ? '; Secure' : ''}`);
      log(1, 'password_ok_2fa_pending');
      return res.send(V.login2fa(ctx(req), ''));
    }
    run('UPDATE users SET failed_attempts=0, locked_until=0, last_login_at=?, last_login_ip=? WHERE id=?', nowIso(), req.ip, u.id);
    log(1, 'ok');
    finishLogin(req, res, u, req.body.remember);
  });
  const pend2fa = new Map();
  app.post('/login/2fa', (req, res) => {
    const t = req.i.t, m = /(?:^|;\s*)p2=([0-9a-f]+)/.exec(req.headers.cookie || ''), p = m && pend2fa.get(m[1]);
    if (!p || p.exp < Date.now()) { if (m) pend2fa.delete(m[1]); return res.status(401).send(V.login(ctx(req), t('Session expired, sign in again'))); }
    const u = q1('SELECT * FROM users WHERE id=?', p.uid);
    const ok = u && u.status === 'active' && (TF.verifyTotp(S.dec(u.totp_secret), req.body.code) || TF.useRecovery(q1, run, u, req.body.code));
    if (!ok) {
      if (++p.tries >= 5) { pend2fa.delete(m[1]); run('INSERT INTO login_history(user_id,identifier,success,reason,ip) VALUES(?,?,?,?,?)', p.uid, u ? u.username : '', 0, '2fa_locked', req.ip); return res.status(401).send(V.login(ctx(req), t('Too many attempts'))); }
      return res.status(401).send(V.login2fa(ctx(req), t('Invalid code')));
    }
    pend2fa.delete(m[1]);
    run('UPDATE users SET failed_attempts=0, locked_until=0, last_login_at=?, last_login_ip=? WHERE id=?', nowIso(), req.ip, u.id);
    run('INSERT INTO login_history(user_id,identifier,success,reason,ip) VALUES(?,?,?,?,?)', u.id, u.username, 1, 'ok_2fa', req.ip);
    finishLogin(req, res, u, p.remember);
  });
  function finishLogin(req, res, u, remember) {
    const token = crypto.randomBytes(32).toString('hex'), csrf = crypto.randomBytes(16).toString('hex');
    const ttl = remember ? REMEMBER_TTL : SESSION_TTL;
    run('INSERT INTO sessions(token_hash,user_id,csrf,ip,ua,created_at,last_seen,expires_at) VALUES(?,?,?,?,?,?,?,?)',
      sha(token), u.id, csrf, req.ip, clean(req.headers['user-agent'], 200), Date.now(), Date.now(), Date.now() + ttl);
    res.append('Set-Cookie', `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.floor(ttl / 1000)}${opts.secureCookies ? '; Secure' : ''}`);
    req.user = u;
    audit(req, 'login', '', u.company_id);
    res.redirect(303, home(u));
  }
  app.post('/logout', needLogin, (req, res) => {
    audit(req, 'logout');
    run('DELETE FROM sessions WHERE token_hash=?', req.session.token_hash);
    res.append('Set-Cookie', 'sid=; Max-Age=0; Path=/');
    res.redirect(303, '/login');
  });

  // ---- password reset via one-time link (issued by super admin)
  app.get('/forgot', (req, res) => {
    const t = req.i.t, c = ctx(req);
    res.send(page(c, 'Forgot password', `<div class="card" style="max-width:420px;margin:auto"><h3>${t('Forgot password?')}</h3><p class="mut">${t('Enter your username or email. A request is sent to your administrator, who will give you a one-time reset link.')}</p>
<form method="post" action="/forgot">${csrfField(c)}${field(t('Email or username'), 'identifier', '', { req: true })}<p><button>${t('Send request')}</button> <a class="btn sec" href="/login">${t('Back')}</a></p></form></div>`));
  });
  app.post('/forgot', (req, res) => {
    const t = req.i.t, c = ctx(req), ident = clean(req.body.identifier, 200).toLowerCase();
    const done = () => res.send(page(c, 'Forgot password', `<div class="card" style="max-width:420px;margin:auto"><h3>${t('Request sent')}</h3><p>${t('If the account exists, your administrator has been notified and will send you a reset link.')}</p><p><a class="btn" href="/login">${t('Back')}</a></p></div>`));
    if (tooMany(req.ip)) return res.status(429).send(page(c, 'Forgot password', `<div class="card"><h3>${t('Too many attempts')}</h3></div>`));
    const u = ident ? q1('SELECT * FROM users WHERE lower(username)=? OR lower(email)=?', ident, ident) : null;
    run('INSERT INTO login_history(user_id,identifier,success,reason,ip) VALUES(?,?,?,?,?)', u ? u.id : null, ident, 0, 'forgot_request', req.ip);
    if (u && u.status === 'active' && (u.role === 'company_admin' || u.role === 'employee') && !q1("SELECT 1 x FROM reset_requests WHERE user_id=? AND status='open'", u.id)) {
      run('INSERT INTO reset_requests(user_id) VALUES(?)', u.id); audit(req, 'password_reset_requested', u.username, u.company_id);
    }
    done();
  });
  const issueLink = (req, u, by) => { const token = crypto.randomBytes(24).toString('hex'); run('INSERT INTO reset_tokens(token_hash,user_id,expires_at,created_by) VALUES(?,?,?,?)', sha(token), u.id, Date.now() + 24 * 3600e3, by); run("UPDATE reset_requests SET status='done' WHERE user_id=?", u.id); return `${opts.baseUrl || `${req.protocol}://${req.get('host')}`}/reset/${token}`; };
  app.post('/app/employees/:id/reset-link', needAdmin, (req, res) => {
    const u = q1("SELECT * FROM users WHERE id=? AND company_id=? AND role='employee'", Number(req.params.id), req.user.company_id);
    if (!u) return deny(req, res, 404);
    const url = issueLink(req, u, req.user.id); audit(req, 'password_reset_link_issued', u.username);
    const c = ctx(req), t = req.i.t;
    res.send(page(c, 'Reset', `<div class="card"><h3>${t('Reset password link')}</h3><p>${t('Link valid for 24 hours. Give it to the employee. It can be used once.')}</p><p><input readonly value="${esc(url)}" onfocus="this.select()"></p><p><a class="btn" href="/app/employees">${t('Back')}</a></p></div>`, nav(req)));
  });
  app.get('/reset/:token', (req, res) => {
    const r = q1('SELECT * FROM reset_tokens WHERE token_hash=? AND used=0 AND expires_at>?', sha(req.params.token), Date.now());
    const c = ctx(req), t = req.i.t;
    if (!r) return res.status(400).send(page(c, 'Reset', `<div class="card"><h3>${t('Invalid or expired link')}</h3></div>`));
    res.send(page(c, 'Reset', `<div class="card" style="max-width:420px;margin:auto"><h3>${t('Set new password')}</h3>
<form method="post">${csrfField(c)}${field(t('New password'), 'password', '', { type: 'password', req: true })}${field(t('Confirm new password'), 'confirm', '', { type: 'password', req: true })}<p><button>${t('Save')}</button></p></form></div>`));
  });
  app.post('/reset/:token', (req, res) => {
    const t = req.i.t, c = ctx(req);
    const r = q1('SELECT * FROM reset_tokens WHERE token_hash=? AND used=0 AND expires_at>?', sha(req.params.token), Date.now());
    if (!r) return res.status(400).send(page(c, 'Reset', `<div class="card"><h3>${t('Invalid or expired link')}</h3></div>`));
    const pw = String(req.body.password || ''), prob = passwordProblem(pw);
    if (prob || pw !== req.body.confirm) return go(res, req.originalUrl, 'err', t(prob || 'pw_mismatch'));
    run('UPDATE users SET password_hash=?, failed_attempts=0, locked_until=0 WHERE id=?', hashPassword(pw), r.user_id);
    run('UPDATE reset_tokens SET used=1 WHERE token_hash=?', r.token_hash);
    run('DELETE FROM sessions WHERE user_id=?', r.user_id);
    const u = q1('SELECT company_id FROM users WHERE id=?', r.user_id);
    audit(req, 'password_reset_completed', `user ${r.user_id}`, u.company_id);
    go(res, '/login', 'ok', t('Password updated, you can sign in'));
  });

  // ---- account (any logged-in user)
  app.get('/account', needLogin, (req, res) => {
    const c = ctx(req), t = req.i.t;
    const sessions = q('SELECT * FROM sessions WHERE user_id=? ORDER BY last_seen DESC', req.user.id);
    const hist = q('SELECT * FROM login_history WHERE user_id=? ORDER BY id DESC LIMIT 15', req.user.id);
    res.send(page(c, 'Account', `<div class="card"><h3>${t('Change password')}</h3><form method="post" action="/account/password">${csrfField(c)}<div class="row">
${field(t('Current password'), 'current', '', { type: 'password', req: true })}${field(t('New password'), 'password', '', { type: 'password', req: true })}${field(t('Confirm new password'), 'confirm', '', { type: 'password', req: true })}</div><p><button>${t('Save')}</button></p></form></div>
<div class="card"><h3>${t('Active sessions')}</h3><div class="tbl"><table><tr><th>IP</th><th>Device</th><th>Last</th><th></th></tr>${sessions.map((s) => `<tr><td>${esc(s.ip)}</td><td>${esc(s.ua)}</td><td>${new Date(s.last_seen).toISOString().slice(0, 19).replace('T', ' ')}</td><td>${s.token_hash === req.session.token_hash ? '&#9679;' : ''}</td></tr>`).join('')}</table></div>
<p><a class="btn sec" href="/account/2fa">${t('Two-factor authentication')}</a></p><form method="post" action="/account/logout-others">${csrfField(c)}<p><button class="sec">${t('Logout other sessions')}</button></p></form></div>
<div class="card"><h3>${t('Login history')}</h3><div class="tbl"><table><tr><th>Time</th><th>IP</th><th>Result</th></tr>${hist.map((h) => `<tr><td>${esc(h.ts)}</td><td>${esc(h.ip)}</td><td>${h.success ? 'OK' : esc(h.reason)}</td></tr>`).join('')}</table></div></div>`, nav(req)));
  });
  app.post('/account/password', needLogin, (req, res) => {
    const t = req.i.t, pw = String(req.body.password || '');
    if (!verifyPassword(String(req.body.current || ''), req.user.password_hash)) { audit(req, 'password_change_failed'); return go(res, '/account', 'err', t('pw_wrong')); }
    const prob = passwordProblem(pw);
    if (prob) return go(res, '/account', 'err', t(prob));
    if (pw !== req.body.confirm) return go(res, '/account', 'err', t('pw_mismatch'));
    run('UPDATE users SET password_hash=? WHERE id=?', hashPassword(pw), req.user.id);
    run('DELETE FROM sessions WHERE user_id=? AND token_hash<>?', req.user.id, req.session.token_hash);
    audit(req, 'password_changed');
    go(res, '/account', 'ok', t('Saved'));
  });
  app.post('/account/logout-others', needLogin, (req, res) => {
    run('DELETE FROM sessions WHERE user_id=? AND token_hash<>?', req.user.id, req.session.token_hash);
    audit(req, 'logout_other_sessions');
    go(res, '/account', 'ok', req.i.t('Saved'));
  });

  const NOMAIL = '@noemail.invalid';
  const userMail = (email, username) => email || `${username}${NOMAIL}`;
  function nav(req) {
    const t = req.i.t, u = req.user;
    if (!u) return '';
    if (u.role === 'super_admin') return `<a href="/admin">${t('Dashboard')}</a><a href="/admin/companies">${t('Companies')}</a><a href="/admin/plans">${t('Subscription Plans & Pricing')}</a><a href="/admin/payment-methods">${t('Payment Methods')}</a><a href="/admin/payments">${t('Payments')}</a><a href="/admin/audit">${t('Audit log')}</a><a href="/admin/security">${t('Security')}</a><a href="/admin/backups">${t('Backups')}</a><a href="/admin/system">${t('System')}</a>`;
    const P0 = req.path || '';
    const grp = (label, items) => `<details class="grp"${items.some(([, u]) => P0 === u || (u.length > 5 && P0.startsWith(u + '/')) || P0 === u) ? ' open' : ''}><summary>${t(label)}</summary>${items.map(([l, u]) => `<a href="${u}">${t(l)}</a>`).join('')}</details>`;
    const co0 = u.company_id ? q1('SELECT plan FROM companies WHERE id=?', u.company_id) : null, hm = (m) => !co0 || P.hasModule(co0, m);
    let h = `<a href="/app">${t('Dashboard')}</a>`;
    if (can(u, 'customers.view')) h += can(u, 'customers.add') ? grp('Customers', [['Customers', '/app/customers'], ['Add', '/app/customers/new']]) : `<a href="/app/customers">${t('Customers')}</a>`;
    if (u.role === 'company_admin') h += `<a href="/app/packages">${t('Packages')}</a>` + (hm('vouchers') ? grp('Vouchers', [['Voucher batches', '/app/vouchers'], ['Card templates', '/app/vouchers/templates']]) : '') + (hm('reports') ? `<a href="/app/reports">${t('Reports')}</a>` : '') + `<a href="/app/notifications">${t('Notifications')}</a><a href="/app/finance">${t('Finance')}</a>` + (hm('network') ? grp('Network Management', DEV_PAGES.map(([k, l, u2]) => [l, u2])) : '') + grp('My Subscription', [['My Subscription', '/app/subscription'], ['My payments', '/app/payments']]);
    if (can(u, 'audit.view')) h += `<a href="/app/audit">${t('Audit log')}</a>`;
    return h;
  }

  // =============== SUPER ADMIN ===============
  const statusOf = (c) => {
    if (c.status === 'suspended') return 'suspended';
    const end = c.subscription_ends || c.trial_ends;
    if (end && end < new Date().toISOString().slice(0, 10)) return 'expired';
    return c.status;
  };
  app.get('/admin', needSuper, (req, res) => {
    const t = req.i.t, c = ctx(req);
    const comps = q('SELECT * FROM companies');
    const cnt = (s) => comps.filter((x) => statusOf(x) === s).length;
    const customers = q1('SELECT count(*) n FROM customers').n;
    const recent = q('SELECT a.*, c.name cname FROM audit_log a LEFT JOIN companies c ON c.id=a.company_id ORDER BY a.id DESC LIMIT 10');
    const stat = (n, l) => `<div class="stat"><b>${n}</b><span>${t(l)}</span></div>`;
    const rr = q("SELECT r.id, u.id uid, u.username, c.id cid, c.name cname FROM reset_requests r JOIN users u ON u.id=r.user_id JOIN companies c ON c.id=u.company_id WHERE r.status='open' AND u.role='company_admin' ORDER BY r.id");
    const rrCard = rr.length ? `<div class="card tbl"><h3>${t('Password reset requests')}</h3><table>${rr.map((r) => `<tr><td>${esc(r.cname)}</td><td>${esc(r.username)}</td><td><form class="inline" method="post" action="/admin/companies/${r.cid}/reset/${r.uid}">${csrfField(c)}<button>${t('Issue reset link')}</button></form></td></tr>`).join('')}</table></div>` : '';
    res.send(page(c, 'Dashboard', `${rrCard}<div class="grid">${stat(comps.length, 'Total companies')}${stat(cnt('active'), 'Active companies')}${stat(cnt('trial'), 'Trial companies')}${stat(cnt('suspended'), 'Suspended companies')}${stat(cnt('expired'), 'Expired subscriptions')}${stat(customers, 'Total customers')}</div>
<div class="card" style="margin-top:16px"><h3>${t('Recent activity')}</h3><div class="tbl"><table>${recent.map((a) => `<tr><td>${esc(a.ts)}</td><td>${esc(a.cname || '-')}</td><td>${esc(a.action)}</td><td>${esc(a.detail)}</td></tr>`).join('') || `<tr><td>${t('No results')}</td></tr>`}</table></div></div>`, nav(req)));
  });
  const AB = makeBackup({ db, S, audit });
  if (!opts.noBackupTimer) AB.start();
  PT.init({ app, db, audit, ctx, go, needSuper, nav: (req) => nav(req), AB, requireSuper2fa });
  app.get('/admin/audit', needSuper, (req, res) => {
    const rows = q('SELECT a.*, c.name cname, u.username FROM audit_log a LEFT JOIN companies c ON c.id=a.company_id LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 200');
    res.send(page(ctx(req), 'Audit', `<div class="card tbl"><table><tr><th>Time</th><th>Company</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr>${rows.map((a) => `<tr><td>${esc(a.ts)}</td><td>${esc(a.cname || '-')}</td><td>${esc(a.username || '-')}</td><td>${esc(a.action)}</td><td>${esc(a.detail)}</td><td>${esc(a.ip)}</td></tr>`).join('')}</table></div>`, nav(req)));
  });
  app.get('/admin/companies', needSuper, (req, res) => {
    const t = req.i.t, c = ctx(req);
    const s = clean(req.query.q, 100), st = clean(req.query.status, 20);
    let rows = q('SELECT c.*, (SELECT count(*) FROM customers WHERE company_id=c.id) cust FROM companies c WHERE (c.name LIKE ? OR c.owner_name LIKE ? OR c.email LIKE ?) ORDER BY c.id DESC', `%${s}%`, `%${s}%`, `%${s}%`);
    if (st) rows = rows.filter((r) => statusOf(r) === st);
    res.send(page(c, 'Companies', `<div class="card"><form method="get" class="row"><div><input name="q" value="${esc(s)}" placeholder="${t('Search')}"></div>
${select(t('Status'), 'status', st, [['', t('All')], ['active', t('Active')], ['trial', t('Trial')], ['suspended', t('Suspended')], ['expired', t('Expired')]])}<div style="padding-top:22px"><button>${t('Search')}</button> <a class="btn sec" href="/admin/companies/new">${t('New company')}</a></div></form></div>
<div class="card tbl"><table><tr><th>#</th><th>${t('Company name')}</th><th>${t('Owner name')}</th><th>${t('Plan')}</th><th>${t('Status')}</th><th>${t('Customers')}</th><th></th></tr>
${rows.map((r) => `<tr><td>${r.id}</td><td>${esc(r.name)}</td><td>${esc(r.owner_name)}</td><td>${esc(P.planName(P.getPlan(r.plan), req.i))}</td><td>${badge(statusOf(r), t)}</td><td>${r.cust}</td><td><a href="/admin/companies/${r.id}">${t('View')}</a></td></tr>`).join('') || `<tr><td colspan="7">${t('No results')}</td></tr>`}</table></div>`, nav(req)));
  });
  const companyForm = (c, t, co = {}) => `<div class="row">${field(t('Company name'), 'name', co.name, { req: true })}${field(t('Network name'), 'network_name', co.network_name)}${field(t('Owner name'), 'owner_name', co.owner_name)}
${field(t('Email'), 'email', co.email, { type: 'email' })}${field(t('Phone'), 'phone', co.phone)}${field(t('WhatsApp'), 'whatsapp', co.whatsapp)}${field(t('Country'), 'country', co.country || 'EG')}${field(t('City'), 'city', co.city)}${field(t('Address'), 'address', co.address)}</div>${field(t('Notes'), 'notes', co.notes, { ta: true })}`;
  const createForm = (req, c, v = {}) => {
    const t = req.i.t, opts = P.planOptions(req.i);
    const data = JSON.stringify({ plans: opts, lbl: { trial: t('Trial'), monthly: t('Monthly'), quarterly: t('Quarterly'), semiannual: t('Semi-annual'), annual: t('Annual'), custom: t('Custom duration'), days: t('days'), unl: t('Unlimited'), setup: t('Setup fee'), price: t('Plan Price'), admins: t('Maximum Dashboard Users'), subs: t('Maximum Managed Subscribers'), routers: t('Maximum Routers'), aps: t('Maximum Access Points'), trialdur: t('Trial Duration') } }).replace(/</g, '\\u003c');
    const sec = (title, body) => `<div class="card"><h3>${t(title)}</h3><div class="row2">${body}</div></div>`;
    const limInput = (k, label) => `<div><label>${t(label)}</label><input type="number" min="0" name="lim_${k}" id="lim_${k}"><label style="display:flex;gap:6px;align-items:center;color:var(--tx);margin:2px 0"><input type="checkbox" style="width:auto" name="unl_${k}" id="unl_${k}" value="1"> ${t('Unlimited')}</label></div>`;
    return `<div class="card"><h3>${t('New company')}</h3></div><form method="post" action="/admin/companies">${csrfField(c)}
${sec('Company Information', `${field(t('Company name'), 'name', v.name, { req: true })}${field(t('Network name'), 'network_name', v.network_name)}${field(t('Owner name'), 'owner_name', v.owner_name)}${field(t('Email'), 'email', v.email, { type: 'email' })}${field(t('Phone'), 'phone', v.phone)}${field(t('WhatsApp'), 'whatsapp', v.whatsapp)}${field(t('Country'), 'country', v.country || 'EG')}${field(t('City'), 'city', v.city)}${field(t('Address'), 'address', v.address)}`)}
${sec('Account Information', `${field(t('Admin username'), 'admin_username', v.admin_username, { req: true })}${field(t('Admin password'), 'admin_password', '', { type: 'password', req: true })}${field(t('Confirm Password'), 'admin_confirm', '', { type: 'password', req: true })}`)}
${sec('Subscription Configuration', `${select(t('Select Plan'), 'plan_id', '', opts.map((o) => [o.id, o.name]))}${select(t('Billing Period'), 'period', '', [['monthly', t('Monthly')]])}
<div><label>${t('Plan Price')}</label><input id="priceShow" readonly></div><div><label>${t('Trial Duration')}</label><input id="trialShow" readonly></div>
${limInput('max_admins', 'Maximum Dashboard Users')}${limInput('max_subscribers', 'Maximum Managed Subscribers')}${limInput('max_routers', 'Maximum Routers')}${limInput('max_aps', 'Maximum Access Points')}
${field(t('Subscription Start Date'), 'sub_start', P.today(), { type: 'date' })}${field(t('Subscription Expiration Date'), 'sub_end', '', { type: 'date' })}
<div style="grid-column:1/-1"><div id="planPreview" class="stat"></div></div>`)}
${sec('Additional Settings', `${select(t('Account Status'), 'status', 'auto', [['auto', t('Automatic (from plan)')], ['active', t('Active')], ['trial', t('Trial')], ['suspended', t('Suspended')]])}
<div><label>${t('Company Logo')} (PNG/JPG, 60KB)</label><input type="file" accept="image/png,image/jpeg,image/gif,image/webp" onchange="var f=this.files[0];if(!f)return;if(f.size>60000){alert('Max 60KB');this.value='';return}var r=new FileReader();r.onload=function(){document.getElementById('logo').value=r.result};r.readAsDataURL(f)"><input type="hidden" id="logo" name="logo"></div>
<div style="grid-column:1/-1">${field(t('Administrative Notes'), 'notes', v.notes, { ta: true })}</div>`)}
<p><button>${t('Save')}<span class="spin"></span></button> <a class="btn sec" href="/admin/companies">${t('Cancel')}</a></p></form>
<script>(function(){var D=${data},$=function(i){return document.getElementById(i)};var ps=$('planPreview');
function cur(){return D.plans.filter(function(p){return String(p.id)===$('plan_id').value})[0]}
function fill(){var p=cur();if(!p)return;var per=$('period');var old=per.value;per.innerHTML='';p.periods.forEach(function(x){var o=document.createElement('option');o.value=x.code;o.textContent=D.lbl[x.code]||x.code;per.appendChild(o)});if(old&&p.periods.some(function(x){return x.code===old}))per.value=old;
['max_admins','max_subscribers','max_routers','max_aps'].forEach(function(k){var v=p.limits[k];$('lim_'+k).value=v<0?'':v;$('unl_'+k).checked=v<0});upd()}
function upd(){var p=cur();if(!p)return;var x=p.periods.filter(function(q){return q.code===$('period').value})[0];if(!x)return;
$('priceShow').value=x.price+' '+p.cur+' / '+(D.lbl[x.code]||x.code);$('trialShow').value=x.code==='trial'?p.trial_days+' '+D.lbl.days:'-';
var s=new Date($('sub_start').value||new Date());if(!isNaN(s)){s.setDate(s.getDate()+(x.days||30));$('sub_end').value=s.toISOString().slice(0,10)}
var L=function(k){var v=p.limits[k];return v<0?D.lbl.unl:v};
ps.innerHTML='<b>'+p.name+'</b><br><span class="mut">'+(p.desc||'')+'</span><br>'+D.lbl.price+': '+x.price+' '+p.cur+(p.setup>0?' (+'+D.lbl.setup+' '+p.setup+')':'')+(x.code==='trial'?'<br>'+D.lbl.trialdur+': '+p.trial_days+' '+D.lbl.days:'')+'<br>'+D.lbl.admins+': '+L('max_admins')+' | '+D.lbl.subs+': '+L('max_subscribers')+' | '+D.lbl.routers+': '+L('max_routers')+' | '+D.lbl.aps+': '+L('max_aps')}
$('plan_id').onchange=fill;$('period').onchange=upd;$('sub_start').onchange=upd;fill()})()</script>`;
  };
  app.get('/admin/companies/new', needSuper, (req, res) => {
    const c = ctx(req);
    res.send(page(c, 'New company', createForm(req, c), nav(req)));
  });
  app.post('/admin/companies', needSuper, (req, res) => {
    const t = req.i.t, b = req.body;
    const name = clean(b.name), email = clean(b.email, 200).toLowerCase(), au = clean(b.admin_username, 60).toLowerCase(), ap = String(b.admin_password || '');
    const bad = (m) => go(res, '/admin/companies/new', 'err', t(m));
    if (!name || !au) return bad('required');
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return bad('required');
    const prob = passwordProblem(ap);
    if (prob) return bad(prob);
    if (b.admin_confirm !== undefined && b.admin_confirm !== ap) return bad('pw_mismatch');
    if (q1('SELECT 1 x FROM users WHERE lower(username)=? OR lower(email)=?', au, userMail(email, au))) return bad('duplicate');
    const plan = b.plan_id !== undefined ? P.getPlan(Number(b.plan_id)) : P.getPlan(String(b.plan || 'trial'));
    if (!plan || !plan.active || plan.archived) return bad('Plan is not available');
    const periods = P.availablePeriods(plan);
    const period = b.period && periods.includes(b.period) ? b.period : periods[0];
    if (b.period && !periods.includes(b.period) && periods.length > 1) return bad('Plan is not available');
    const logo = clean(b.logo, 100000);
    if (!P.validIcon(logo)) return bad('required');
    const start = b.sub_start ? clean(b.sub_start, 10) : P.today();
    const days = P.periodDays(plan, period) || 30;
    const end = b.sub_end ? clean(b.sub_end, 10) : P.addDays(start, days);
    if (!P.validDate(start) || !P.validDate(end) || end < start) return bad('Invalid dates');
    const { over } = P.limitsFromForm(b, plan);
    const isTrial = period === 'trial';
    const status = ['active', 'trial', 'suspended'].includes(b.status) ? b.status : (isTrial ? 'trial' : 'active');
    const price = P.effPrice(plan, period);
    let cid;
    db.exec('BEGIN');
    try {
      cid = run(`INSERT INTO companies(name,network_name,owner_name,email,phone,whatsapp,country,city,address,plan,status,trial_ends,subscription_ends,notes,billing_period,price_paid,currency,sub_start,limit_overrides,logo) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        name, clean(b.network_name), clean(b.owner_name), email, clean(b.phone, 40), clean(b.whatsapp, 40), clean(b.country, 40), clean(b.city, 80), clean(b.address, 300), plan.code,
        status, isTrial ? end : null, isTrial ? null : end, clean(b.notes, 1000), period, price, plan.currency, start, JSON.stringify(over), logo).lastInsertRowid;
      run(`INSERT INTO users(company_id,name,username,email,phone,password_hash,role) VALUES(?,?,?,?,?,?, 'company_admin')`, cid, clean(b.owner_name) || name, au, userMail(email, au), clean(b.phone, 40), hashPassword(ap));
      const amount = price + (plan.setup_fee || 0);
      P.addInvoice({ id: cid }, plan, 'subscription', period, amount, 0, plan.setup_fee > 0 ? `setup fee ${plan.setup_fee}` : '', amount === 0 ? 'paid' : 'unpaid');
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); return bad('duplicate'); }
    audit(req, 'company_created', `${name} (${plan.code}/${period})`, cid);
    go(res, `/admin/companies/${cid}`, 'ok', t('Created'));
  });
  const getCompany = (req, res) => { const c = q1('SELECT * FROM companies WHERE id=?', Number(req.params.id)); if (!c) { deny(req, res, 404); return null; } return c; };
  app.get('/admin/companies/:id', needSuper, (req, res) => {
    const co = getCompany(req, res); if (!co) return;
    const t = req.i.t, c = ctx(req);
    const emps = q('SELECT * FROM users WHERE company_id=? ORDER BY id', co.id);
    const cust = q1('SELECT count(*) n FROM customers WHERE company_id=?', co.id).n;
    const acts = q('SELECT * FROM audit_log WHERE company_id=? ORDER BY id DESC LIMIT 15', co.id);
    const act = (path, label, cls = '') => `<form class="inline" method="post" action="/admin/companies/${co.id}/${path}">${csrfField(c)}<button class="${cls}">${label}</button></form>`;
    const link = req.flash && req.flash.link ? '' : '';
    res.send(page(c, co.name, `<div class="card"><div class="head"><h3>${esc(co.name)} ${badge(statusOf(co), t)}</h3><div class="acts"><a class="btn sec" href="/admin/companies/${co.id}/domains">${t('Custom domains')}</a> <a class="btn sec" href="/admin/companies/${co.id}/export">${t('Export')}</a></div></div>
${infoGrid([[t('Plan'), esc(P.planName(P.getPlan(co.plan), req.i))], [t('Status'), badge(statusOf(co), t)], [t('Trial ends'), esc(co.trial_ends || '-')], [t('Subscription ends'), esc(co.subscription_ends || '-')], [t('Registered'), esc(String(co.created_at).slice(0, 10))], [t('Customers'), cust], [t('Owner name'), esc(co.owner_name || '-')], [t('Email'), esc(co.email)]])}
${co.status === 'suspended' ? `<p class="flash err">${t('Suspended')}${co.suspended_until ? ` - ${t('Auto-reactivates on')} ${esc(co.suspended_until)}` : ` - ${t('Until reactivated manually')}`}</p><p>${act('status', t('Activate'), 'ok')}</p>` : `<form method="post" action="/admin/companies/${co.id}/status" class="row" style="border:1px solid var(--bd);border-radius:12px;padding:12px;margin:12px 0">${csrfField(c)}${field(t('Suspend until (leave empty for indefinite)'), 'until', '', { type: 'date' })}${field(t('Or suspend for N days'), 'days', '', { type: 'number' })}<div style="padding-top:22px"><button class="bad">${t('Suspend')}</button></div></form>`}
<form method="post" action="/admin/companies/${co.id}/delete" class="card" style="border:1px solid var(--bad)" onsubmit="return confirm('${t('Delete this client and all its data? A full archive copy is kept.')}')">${csrfField(c)}<h3 style="color:var(--bad)">${t('Delete client')}</h3><p class="mut">${t('Removes the client, its users, customers, invoices and devices. A full archive copy is kept in the database. Type the exact client name to confirm.')}</p>${field(t('Client name'), 'confirm_name', '')}<p><button class="bad">${t('Delete client')}</button></p></form>
<form method="post" action="/admin/companies/${co.id}/extend" class="row">${csrfField(c)}${field(t('Days'), 'days', '30', { type: 'number' })}<div style="padding-top:22px"><button>${t('Extend')}</button></div></form></div>
<div class="card"><h3>${t('Company profile')}</h3><form method="post" action="/admin/companies/${co.id}/edit">${csrfField(c)}${companyForm(c, t, co)}<p><button>${t('Save')}</button></p></form></div>
${P.adminSubscriptionCard(req, c, co)}
<div class="card"><h3>${t('Employees')}</h3><div class="tbl"><table><tr><th>${t('Name')}</th><th>${t('Username')}</th><th>${t('Role')}</th><th>${t('Status')}</th><th></th></tr>${emps.map((u) => `<tr><td>${esc(u.name)}</td><td>${esc(u.username)}</td><td>${esc(u.role === 'company_admin' ? t('Company admin') : u.emp_role)}</td><td>${badge(u.status, t)}</td><td>${u.role === 'company_admin' ? act(`reset/${u.id}`, t('Reset password link'), 'sec') + ' ' : ''}<form class="inline" method="post" action="/admin/companies/${co.id}/newpass/${u.id}" onsubmit="return confirm('${t('Create a new password for this user? The old one stops working.')}')">${csrfField(c)}<button class="sec">${t('New password')}</button></form></td></tr>`).join('')}</table></div></div>
<div class="card"><h3>${t('Recent activity')}</h3><div class="tbl"><table>${acts.map((a) => `<tr><td>${esc(a.ts)}</td><td>${esc(a.action)}</td><td>${esc(a.detail)}</td></tr>`).join('')}</table></div></div>`, nav(req)));
  });
  app.post('/admin/companies/:id/edit', needSuper, (req, res) => {
    const co = getCompany(req, res); if (!co) return;
    const t = req.i.t, b = req.body, name = clean(b.name), email = clean(b.email, 200).toLowerCase();
    if (!name) return go(res, `/admin/companies/${co.id}`, 'err', t('required'));
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return go(res, `/admin/companies/${co.id}`, 'err', t('required'));
    run(`UPDATE companies SET name=?,network_name=?,owner_name=?,email=?,phone=?,whatsapp=?,country=?,city=?,address=?,notes=?,logo=? WHERE id=?`,
      name, clean(b.network_name), clean(b.owner_name), email, clean(b.phone, 40), clean(b.whatsapp, 40), clean(b.country, 40), clean(b.city, 80), clean(b.address, 300), clean(b.notes, 1000), P.validIcon(clean(b.logo, 100000)) ? (b.logo === undefined ? co.logo : clean(b.logo, 100000)) : co.logo, co.id);
    audit(req, 'company_updated', name, co.id);
    go(res, `/admin/companies/${co.id}`, 'ok', t('Updated'));
  });
  app.post('/admin/companies/:id/status', needSuper, (req, res) => {
    const co = getCompany(req, res); if (!co) return;
    const t = req.i.t, back = `/admin/companies/${co.id}`;
    if (co.status === 'suspended') {
      run('UPDATE companies SET status=?, suspended_until=NULL WHERE id=?', co.plan === 'trial' ? 'trial' : 'active', co.id);
      audit(req, 'company_activated', co.name, co.id);
      return go(res, back, 'ok', t('Updated'));
    }
    let until = null; const today = new Date().toISOString().slice(0, 10);
    const days = String(req.body.days || '').trim(), u = String(req.body.until || '').trim();
    if (days) {
      const n = Number(days); if (!Number.isInteger(n) || n < 1 || n > 3650) return go(res, back, 'err', t('Invalid date'));
      until = new Date(Date.now() + n * 86400000).toISOString().slice(0, 10);
    } else if (u) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(u) || isNaN(Date.parse(u)) || u <= today) return go(res, back, 'err', t('Invalid date'));
      until = u;
    }
    run("UPDATE companies SET status='suspended', suspended_until=? WHERE id=?", until, co.id);
    run('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE company_id=?)', co.id);
    audit(req, 'company_suspended', `${co.name}${until ? ' until ' + until : ''}`, co.id);
    go(res, back, 'ok', t('Updated'));
  });
  app.post('/admin/companies/:id/delete', needSuper, (req, res) => {
    const co = getCompany(req, res); if (!co) return;
    const t = req.i.t;
    if (String(req.body.confirm_name || '').trim() !== co.name) return go(res, `/admin/companies/${co.id}`, 'err', t('Type the exact client name to confirm deletion'));
    const users = q('SELECT id,name,username,email,role,emp_role,status FROM users WHERE company_id=?', co.id);
    const snap = { company: co, users };
    for (const tb of ['customers', 'invoices', 'payments', 'plan_requests', 'devices', 'device_groups', 'device_alerts']) snap[tb] = q(`SELECT * FROM ${tb} WHERE company_id=?`, co.id);
    try {
      run('INSERT INTO deleted_companies(company_id,name,deleted_by,snapshot) VALUES(?,?,?,?)', co.id, co.name, req.user.username, JSON.stringify(snap));
      for (const tb of ['vouchers', 'voucher_batches', 'voucher_templates', 'cust_payments', 'cust_invoices', 'expenses', 'packages', 'payments', 'router_cmds', 'router_items', 'device_alerts', 'device_groups', 'devices', 'plan_requests', 'invoices', 'customers']) run(`DELETE FROM ${tb} WHERE company_id=?`, co.id);
      run('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE company_id=?)', co.id);
      run('DELETE FROM tenant_domains WHERE company_id=?', co.id);
      run('DELETE FROM reset_requests WHERE user_id IN (SELECT id FROM users WHERE company_id=?)', co.id);
      run('DELETE FROM reset_tokens WHERE user_id IN (SELECT id FROM users WHERE company_id=?)', co.id);
      run('DELETE FROM users WHERE company_id=?', co.id);
      run('DELETE FROM companies WHERE id=?', co.id);
    } catch (e) { return go(res, '/admin/companies', 'err', t('Could not save')); }
    audit(req, 'company_deleted', co.name, null);
    go(res, '/admin/companies', 'ok', t('Client deleted. A full archive copy was kept.'));
  });
  app.post('/admin/companies/:id/extend', needSuper, (req, res) => {
    const co = getCompany(req, res); if (!co) return;
    const days = parseInt(req.body.days, 10);
    if (!(days >= 1 && days <= 3650)) return go(res, `/admin/companies/${co.id}`, 'err', req.i.t('required'));
    const base = new Date(Math.max(Date.now(), new Date(co.subscription_ends || co.trial_ends || 0).getTime()));
    const col = co.plan === 'trial' && !co.subscription_ends ? 'trial_ends' : 'subscription_ends';
    run(`UPDATE companies SET ${col}=? WHERE id=?`, addDays(base, days), co.id);
    audit(req, 'subscription_extended', `${days} days`, co.id);
    go(res, `/admin/companies/${co.id}`, 'ok', req.i.t('Updated'));
  });
  // Super admin sets a new random password for a client user. It is shown once; only the hash is stored, so nobody can read it later.
  const genPassword = () => { const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ', a = 'abcdefghijkmnpqrstuvwxyz', D = '23456789', all = A + a + D; const pick = (s) => s[crypto.randomInt(s.length)]; const ch = [pick(A), pick(a), pick(D)]; while (ch.length < 14) ch.push(pick(all)); for (let i = ch.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [ch[i], ch[j]] = [ch[j], ch[i]]; } return ch.join(''); };
  app.post('/admin/companies/:id/newpass/:uid', needSuper, (req, res) => {
    const co = getCompany(req, res); if (!co) return;
    const u = q1("SELECT * FROM users WHERE id=? AND company_id=? AND role IN ('company_admin','employee')", Number(req.params.uid), co.id);
    if (!u) return deny(req, res, 404);
    const pw = genPassword();
    run('UPDATE users SET password_hash=?, failed_attempts=0, locked_until=0 WHERE id=?', hashPassword(pw), u.id);
    run('DELETE FROM sessions WHERE user_id=?', u.id);
    run("UPDATE reset_requests SET status='done' WHERE user_id=? AND status='open'", u.id);
    audit(req, 'password_set_by_admin', u.username, co.id);
    const c = ctx(req), t = req.i.t;
    res.setHeader('Cache-Control', 'no-store');
    res.send(page(c, 'Password', `<div class="card"><h3>${t('New password')}: ${esc(u.username)}</h3><p>${t('Shown once. Copy it now and give it to the user. It cannot be shown again, only replaced with another new one. All sessions of this user were signed out.')}</p><p><input readonly dir="ltr" style="font-size:20px;letter-spacing:1px" value="${esc(pw)}" onfocus="this.select()"></p><p><a class="btn" href="/admin/companies/${co.id}">${t('Company profile')}</a></p></div>`, nav(req)));
  });
  app.post('/admin/companies/:id/reset/:uid', needSuper, (req, res) => {
    const co = getCompany(req, res); if (!co) return;
    const u = q1("SELECT * FROM users WHERE id=? AND company_id=? AND role='company_admin'", Number(req.params.uid), co.id);
    if (!u) return deny(req, res, 404);
    const url = issueLink(req, u, req.user.id);
    audit(req, 'password_reset_link_issued', u.username, co.id);
    const c = ctx(req), t = req.i.t;
    res.send(page(c, 'Reset', `<div class="card"><h3>${t('Reset password link')}</h3><p>${t('Link valid for 24 hours. Give it to the client admin. It can be used once.')}</p><p><input readonly value="${esc(url)}" onfocus="this.select()"></p><p><a class="btn" href="/admin/companies/${co.id}">${t('Company profile')}</a></p></div>`, nav(req)));
  });
  app.get('/admin/companies/:id/export', needSuper, (req, res) => {
    const co = getCompany(req, res); if (!co) return;
    audit(req, 'company_exported', co.name, co.id);
    const users = q('SELECT id,name,username,email,role,emp_role,status,last_login_at FROM users WHERE company_id=?', co.id);
    res.setHeader('Content-Disposition', `attachment; filename="company-${co.id}.json"`);
    res.json({ company: co, users, customers: q('SELECT * FROM customers WHERE company_id=?', co.id) });
  });

  // =============== COMPANY AREA (tenant scoped: company_id ALWAYS from session) ===============
  const u_isAdmin = (req) => req.user.role === 'company_admin';
  app.get('/app', needCompany, (req, res) => {
    const t = req.i.t, c = ctx(req), cid = req.user.company_id;
    const co = q1('SELECT * FROM companies WHERE id=?', cid);
    const n = (sql, ...a) => q1(sql, cid, ...a).n;
    const stat = (v, l) => `<div class="stat"><b>${v}</b><span>${t(l)}</span></div>`;
    res.send(page(c, 'Dashboard', `<h3>${t('Welcome')}, ${esc(req.user.name)} - ${esc(co.name)} ${badge(statusOf(co), t)}</h3><div class="grid">
${stat(n('SELECT count(*) n FROM customers WHERE company_id=?'), 'Total customers')}${stat(n("SELECT count(*) n FROM customers WHERE company_id=? AND status='active'"), 'Active')}${stat(n("SELECT count(*) n FROM customers WHERE company_id=? AND payment_status='unpaid'"), 'Unpaid')}${stat(n("SELECT count(*) n FROM users WHERE company_id=? AND role='employee'"), 'Employees')}</div>${u_isAdmin(req) ? RPT.dashboard(req) : ''}`, nav(req)));
  });
  const custFields = (t, v = {}) => `<div class="row">${field(t('Full name'), 'full_name', v.full_name, { req: true })}${field(t('Phone'), 'phone', v.phone)}${field(t('WhatsApp'), 'whatsapp', v.whatsapp)}${field(t('Email'), 'email', v.email, { type: 'email' })}${field(t('Address'), 'address', v.address)}${field(t('Location'), 'location', v.location)}
${select(t('Account type'), 'account_type', v.account_type, [['individual', 'Individual'], ['business', 'Business']])}${select(t('Service type'), 'service_type', v.service_type, [['pppoe', 'PPPoE'], ['hotspot', 'Hotspot'], ['static', 'Static']])}${field(t('Package'), 'package', v.package)}${field(t('Username'), 'username', v.username)}
${field(t('Subscription start'), 'sub_start', v.sub_start, { type: 'date' })}${field(t('Subscription ends'), 'sub_end', v.sub_end, { type: 'date' })}${select(t('Payment status'), 'payment_status', v.payment_status, [['unpaid', t('Unpaid')], ['paid', t('Paid')]])}${select(t('Status'), 'status', v.status, [['active', t('Active')], ['suspended', t('Suspended')]])}</div>${field(t('Notes'), 'notes', v.notes, { ta: true })}`;
  const custValues = (b) => {
    const d = (x) => (/^\d{4}-\d{2}-\d{2}$/.test(x || '') ? x : null);
    return [clean(b.full_name), clean(b.phone, 40), clean(b.whatsapp, 40), clean(b.email, 200), clean(b.address), clean(b.location),
      ['individual', 'business'].includes(b.account_type) ? b.account_type : 'individual', ['pppoe', 'hotspot', 'static'].includes(b.service_type) ? b.service_type : 'pppoe',
      clean(b.package, 80), clean(b.username, 80), d(b.sub_start), d(b.sub_end), b.payment_status === 'paid' ? 'paid' : 'unpaid', b.status === 'suspended' ? 'suspended' : 'active', clean(b.notes, 1000)];
  };
  app.get('/app/customers', needCompany, need('customers.view'), (req, res) => {
    const t = req.i.t, c = ctx(req), cid = req.user.company_id;
    const s = clean(req.query.q, 100), st = clean(req.query.status, 20), pay = clean(req.query.pay, 20);
    const page_ = Math.max(1, parseInt(req.query.page, 10) || 1), per = 20;
    let where = 'company_id=? AND (full_name LIKE ? OR phone LIKE ? OR username LIKE ? OR code LIKE ?)';
    const args = [cid, `%${s}%`, `%${s}%`, `%${s}%`, `%${s}%`];
    if (['active', 'suspended'].includes(st)) { where += ' AND status=?'; args.push(st); }
    if (['paid', 'unpaid'].includes(pay)) { where += ' AND payment_status=?'; args.push(pay); }
    const total = q1(`SELECT count(*) n FROM customers WHERE ${where}`, ...args).n;
    const rows = q(`SELECT * FROM customers WHERE ${where} ORDER BY id DESC LIMIT ? OFFSET ?`, ...args, per, (page_ - 1) * per);
    const qs = (p) => `?q=${encodeURIComponent(s)}&status=${st}&pay=${pay}&page=${p}`;
    res.send(page(c, 'Customers', `<div class="card"><form method="get" class="row"><div><input name="q" value="${esc(s)}" placeholder="${t('Search')}"></div>
${select(t('Status'), 'status', st, [['', t('All')], ['active', t('Active')], ['suspended', t('Suspended')]])}${select(t('Payment status'), 'pay', pay, [['', t('All')], ['paid', t('Paid')], ['unpaid', t('Unpaid')]])}
<div style="padding-top:22px"><button>${t('Search')}</button> ${can(req.user, 'customers.add') ? `<a class="btn sec" href="/app/customers/new">${t('Add')}</a>` : ''} ${can(req.user, 'customers.export') ? `<a class="btn sec" href="/app/customers.csv">${t('Export')}</a>` : ''}</div></form></div>
<div class="card tbl"><table><tr><th>${t('Customer ID')}</th><th>${t('Full name')}</th><th>${t('Phone')}</th><th>${t('Package')}</th><th>${t('Status')}</th><th>${t('Payment status')}</th><th></th></tr>
${rows.map((r) => `<tr><td>${esc(r.code)}</td><td>${esc(r.full_name)}</td><td>${esc(r.phone)}</td><td>${esc(r.package)}</td><td>${badge(r.status, t)}</td><td>${badge(r.payment_status, t)}</td><td><a href="/app/customers/${r.id}">${t('View')}</a></td></tr>`).join('') || `<tr><td colspan="7">${t('No results')}</td></tr>`}</table>
<div class="pager">${page_ > 1 ? `<a href="${qs(page_ - 1)}">${t('Previous')}</a>` : ''}<span class="mut">${total} | ${page_}/${Math.max(1, Math.ceil(total / per))}</span>${page_ * per < total ? `<a href="${qs(page_ + 1)}">${t('Next')}</a>` : ''}</div></div>`, nav(req)));
  });
  app.get('/app/customers.csv', needCompany, need('customers.export'), (req, res) => {
    const rows = q('SELECT code,full_name,phone,whatsapp,email,address,package,username,sub_start,sub_end,payment_status,status FROM customers WHERE company_id=? ORDER BY id', req.user.company_id);
    const cell = (v) => { v = String(v ?? ''); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return `"${v.replace(/"/g, '""')}"`; };
    audit(req, 'customers_exported', `${rows.length} rows`);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="customers.csv"');
    res.send('\ufeff' + ['code,full_name,phone,whatsapp,email,address,package,username,sub_start,sub_end,payment_status,status', ...rows.map((r) => Object.values(r).map(cell).join(','))].join('\n'));
  });
  app.get('/app/customers/new', needCompany, need('customers.add'), (req, res) => {
    const t = req.i.t, c = ctx(req);
    res.send(page(c, 'New customer', `<div class="card"><form method="post" action="/app/customers">${csrfField(c)}${custFields(t)}<p><button>${t('Save')}</button></p></form></div>`, nav(req)));
  });
  app.post('/app/customers', needCompany, need('customers.add'), (req, res) => {
    const t = req.i.t, cid = req.user.company_id, v = custValues(req.body);
    if (!v[0]) return go(res, '/app/customers/new', 'err', t('required'));
    for (const k of ['max_subscribers', req.body.service_type === 'hotspot' ? 'max_hotspot' : req.body.service_type === 'pppoe' ? 'max_pppoe' : null]) {
      const r = k && P.checkLimit(cid, k); if (r) { audit(req, 'limit_blocked', k); return go(res, '/app/customers/new', 'err', P.limitMsg(t, r)); }
    }
    const last = q1('SELECT max(id) m FROM customers WHERE company_id=?', cid).m || 0;
    let code = `C${String(last + 1).padStart(5, '0')}`;
    while (q1('SELECT 1 x FROM customers WHERE company_id=? AND code=?', cid, code)) code += 'x';
    const id = run(`INSERT INTO customers(company_id,code,full_name,phone,whatsapp,email,address,location,account_type,service_type,package,username,sub_start,sub_end,payment_status,status,notes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, cid, code, ...v).lastInsertRowid;
    audit(req, 'customer_created', `${code} ${v[0]}`);
    go(res, `/app/customers/${id}`, 'ok', t('Created'));
  });
  const getCust = (req, res) => { const r = q1('SELECT * FROM customers WHERE id=? AND company_id=?', Number(req.params.id), req.user.company_id); if (!r) { deny(req, res, 404); return null; } return r; };
  app.get('/app/customers/:id', needCompany, need('customers.view'), (req, res) => {
    const r = getCust(req, res); if (!r) return;
    const t = req.i.t, c = ctx(req);
    const hist = q("SELECT * FROM audit_log WHERE company_id=? AND detail LIKE ? ORDER BY id DESC LIMIT 15", req.user.company_id, `${r.code} %`);
    const editable = can(req.user, 'customers.edit');
    res.send(page(c, r.full_name, `<div class="card"><h3>${esc(r.code)} - ${esc(r.full_name)} ${badge(r.status, t)}</h3>
${editable ? `<form method="post" action="/app/customers/${r.id}/edit">${csrfField(c)}${custFields(t, r)}<p><button>${t('Save')}</button></p></form>` : `<table>${Object.entries(r).filter(([k]) => !['id', 'company_id'].includes(k)).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join('')}</table>`}
${can(req.user, 'customers.delete') ? `<form method="post" action="/app/customers/${r.id}/delete" onsubmit="return confirm('${t('Delete')}?')">${csrfField(c)}<button class="bad">${t('Delete')}</button></form>` : ''}</div>
${can(req.user, 'customers.edit') && req.user.role === 'company_admin' ? FIN.custSection(req, r) : ''}
<div class="card"><h3>${t('Recent activity')}</h3><table>${hist.map((a) => `<tr><td>${esc(a.ts)}</td><td>${esc(a.action)}</td></tr>`).join('') || `<tr><td>${t('No results')}</td></tr>`}</table></div>`, nav(req)));
  });
  app.post('/app/customers/:id/edit', needCompany, need('customers.edit'), (req, res) => {
    const r = getCust(req, res); if (!r) return;
    const v = custValues(req.body);
    if (!v[0]) return go(res, `/app/customers/${r.id}`, 'err', req.i.t('required'));
    if (v[7] !== r.service_type && (v[7] === 'hotspot' || v[7] === 'pppoe')) {
      const k = v[7] === 'hotspot' ? 'max_hotspot' : 'max_pppoe', lr = P.checkLimit(req.user.company_id, k);
      if (lr) { audit(req, 'limit_blocked', k); return go(res, `/app/customers/${r.id}`, 'err', P.limitMsg(req.i.t, lr)); }
    }
    run(`UPDATE customers SET full_name=?,phone=?,whatsapp=?,email=?,address=?,location=?,account_type=?,service_type=?,package=?,username=?,sub_start=?,sub_end=?,payment_status=?,status=?,notes=? WHERE id=? AND company_id=?`, ...v, r.id, req.user.company_id);
    audit(req, 'customer_updated', `${r.code} ${v[0]}`);
    go(res, `/app/customers/${r.id}`, 'ok', req.i.t('Saved'));
  });
  app.post('/app/customers/:id/delete', needCompany, need('customers.delete'), (req, res) => {
    const r = getCust(req, res); if (!r) return;
    run('DELETE FROM customers WHERE id=? AND company_id=?', r.id, req.user.company_id);
    audit(req, 'customer_deleted', `${r.code} ${r.full_name}`);
    go(res, '/app/customers', 'ok', req.i.t('Deleted'));
  });

  // ---- employees (company admin only)
  const permChecks = (t, sel = []) => `<div class="checks">${CUSTOMER_PERMS.map((p) => `<label><input type="checkbox" name="perm" value="${p}" ${sel.includes(p) ? 'checked' : ''}> ${t(p)}</label>`).join('')}</div>`;
  const parsePerms = (b) => [].concat(b.perm || []).filter((p) => CUSTOMER_PERMS.includes(p));
  app.get('/app/employees', needAdmin, (req, res) => {
    const t = req.i.t, c = ctx(req);
    const rows = q("SELECT * FROM users WHERE company_id=? AND role='employee' ORDER BY id", req.user.company_id);
    const rq = q("SELECT u.id, u.name, u.username FROM reset_requests r JOIN users u ON u.id=r.user_id WHERE r.status='open' AND u.company_id=? AND u.role='employee'", req.user.company_id);
    const rqCard = rq.length ? `<div class="card tbl"><h3>${t('Password reset requests')}</h3><table>${rq.map((r) => `<tr><td>${esc(r.name)}</td><td>${esc(r.username)}</td><td><form class="inline" method="post" action="/app/employees/${r.id}/reset-link">${csrfField(c)}<button>${t('Issue reset link')}</button></form></td></tr>`).join('')}</table></div>` : '';
    res.send(page(c, 'Employees', `${rqCard}<div class="card"><a class="btn" href="/app/employees/new">${t('Add')}</a></div><div class="card tbl"><table><tr><th>${t('Name')}</th><th>${t('Username')}</th><th>${t('Role')}</th><th>${t('Status')}</th><th></th></tr>
${rows.map((u) => `<tr><td>${esc(u.name)}</td><td>${esc(u.username)}</td><td>${esc(t(u.emp_role))}</td><td>${badge(u.status, t)}</td><td><a href="/app/employees/${u.id}">${t('Edit')}</a></td></tr>`).join('') || `<tr><td colspan="5">${t('No results')}</td></tr>`}</table></div>`, nav(req)));
  });
  app.get('/app/employees/new', needAdmin, (req, res) => {
    const t = req.i.t, c = ctx(req);
    res.send(page(c, 'New employee', `<div class="card"><form method="post" action="/app/employees">${csrfField(c)}<div class="row">${field(t('Name'), 'name', '', { req: true })}${field(t('Username'), 'username', '', { req: true })}${field(t('Email'), 'email', '', { type: 'email' })}${field(t('Password'), 'password', '', { type: 'password', req: true })}
${select(t('Role'), 'emp_role', 'Cashier', Object.keys(ROLE_PRESETS).map((r) => [r, t(r)]))}</div><label>${t('Permissions')} (${t('Role')} preset applies if none ticked)</label>${permChecks(t)}<p><button>${t('Save')}</button></p></form></div>`, nav(req)));
  });
  app.post('/app/employees', needAdmin, (req, res) => {
    const t = req.i.t, b = req.body, cid = req.user.company_id;
    const un = clean(b.username, 60).toLowerCase(), em = clean(b.email, 200).toLowerCase(), name = clean(b.name);
    const role = ROLE_PRESETS[b.emp_role] ? b.emp_role : 'Read-only Employee';
    if (!un || !name) return go(res, '/app/employees/new', 'err', t('required'));
    { const r = P.checkLimit(cid, 'max_employees'); if (r) { audit(req, 'limit_blocked', 'max_employees'); return go(res, '/app/employees/new', 'err', P.limitMsg(t, r)); } }
    const prob = passwordProblem(String(b.password || ''));
    if (prob) return go(res, '/app/employees/new', 'err', t(prob));
    if (q1('SELECT 1 x FROM users WHERE lower(username)=? OR lower(email)=?', un, userMail(em, un))) return go(res, '/app/employees/new', 'err', t('duplicate'));
    const perms = parsePerms(b), final = perms.length ? perms : ROLE_PRESETS[role];
    const id = run(`INSERT INTO users(company_id,name,username,email,password_hash,role,emp_role,permissions) VALUES(?,?,?,?,?, 'employee',?,?)`, cid, name, un, userMail(em, un), hashPassword(b.password), role, JSON.stringify(final)).lastInsertRowid;
    audit(req, 'employee_created', un);
    go(res, `/app/employees/${id}`, 'ok', t('Created'));
  });
  const getEmp = (req, res) => { const u = q1("SELECT * FROM users WHERE id=? AND company_id=? AND role='employee'", Number(req.params.id), req.user.company_id); if (!u) { deny(req, res, 404); return null; } return u; };
  app.get('/app/employees/:id', needAdmin, (req, res) => {
    const u = getEmp(req, res); if (!u) return;
    const t = req.i.t, c = ctx(req);
    res.send(page(c, u.name, `<div class="card"><form method="post" action="/app/employees/${u.id}/edit">${csrfField(c)}<div class="row">${field(t('Name'), 'name', u.name, { req: true })}${select(t('Status'), 'status', u.status, [['active', t('Active')], ['suspended', t('Suspended')]])}
${field(t('New password'), 'password', '', { type: 'password' })}${select(t('Role'), 'emp_role', u.emp_role, Object.keys(ROLE_PRESETS).map((r) => [r, t(r)]))}</div><label>${t('Permissions')}</label>${permChecks(t, JSON.parse(u.permissions))}<p><button>${t('Save')}</button></p></form>
<form method="post" action="/app/employees/${u.id}/delete" onsubmit="return confirm('${t('Delete')}?')">${csrfField(c)}<button class="bad">${t('Delete')}</button></form></div>`, nav(req)));
  });
  app.post('/app/employees/:id/edit', needAdmin, (req, res) => {
    const u = getEmp(req, res); if (!u) return;
    const t = req.i.t, b = req.body, name = clean(b.name);
    if (!name) return go(res, `/app/employees/${u.id}`, 'err', t('required'));
    let hash = u.password_hash;
    if (b.password) { const p = passwordProblem(String(b.password)); if (p) return go(res, `/app/employees/${u.id}`, 'err', t(p)); hash = hashPassword(b.password); }
    const role = ROLE_PRESETS[b.emp_role] ? b.emp_role : u.emp_role;
    run('UPDATE users SET name=?,status=?,password_hash=?,emp_role=?,permissions=? WHERE id=? AND company_id=?', name, b.status === 'suspended' ? 'suspended' : 'active', hash, role, JSON.stringify(parsePerms(b)), u.id, req.user.company_id);
    if (b.status === 'suspended' || b.password) run('DELETE FROM sessions WHERE user_id=?', u.id);
    audit(req, 'employee_updated', u.username);
    go(res, `/app/employees/${u.id}`, 'ok', t('Saved'));
  });
  app.post('/app/employees/:id/delete', needAdmin, (req, res) => {
    const u = getEmp(req, res); if (!u) return;
    run('DELETE FROM users WHERE id=? AND company_id=?', u.id, req.user.company_id);
    audit(req, 'employee_deleted', u.username);
    go(res, '/app/employees', 'ok', req.i.t('Deleted'));
  });

  // ---- company settings & audit
  const okImg = (s) => {
    if (s === '') return true;
    const m = /^data:image\/(png|jpeg|gif|webp);base64,([A-Za-z0-9+/=]+)$/.exec(s); if (!m || s.length > 300000) return false;
    const h = Buffer.from(m[2].slice(0, 40), 'base64'), type = m[1];
    return (type === 'png' && h.slice(0, 4).toString('hex') === '89504e47') || (type === 'jpeg' && h.slice(0, 3).toString('hex') === 'ffd8ff') || (type === 'gif' && /^GIF8/.test(h.slice(0, 4).toString('latin1'))) || (type === 'webp' && h.slice(0, 4).toString('latin1') === 'RIFF' && h.slice(8, 12).toString('latin1') === 'WEBP');
  };
  const okColor = (s) => /^#[0-9a-fA-F]{6}$/.test(s);
  app.get('/app/settings', needAdmin, (req, res) => {
    const t = req.i.t, c = ctx(req), co = q1('SELECT * FROM companies WHERE id=?', req.user.company_id);
    const img = (id, label, v, h) => `<div><label>${t(label)}</label><input type="file" accept="image/png,image/jpeg,image/webp,image/gif" onchange="mcImg(this,'${id}')"><input type="hidden" name="${id}" id="${id}" value="${esc(v || '')}">${v ? `<p><img src="${esc(v)}" style="max-height:${h}px;max-width:240px;object-fit:contain" alt=""></p><label style="display:flex;gap:6px;align-items:center;color:var(--tx)"><input type="checkbox" style="width:auto" name="rm_${id}" value="1"> ${t('Remove')}</label>` : ''}</div>`;
    res.send(page(c, 'Settings', `<div class="card"><h3>${t('Company Profile & Network Identity')}</h3><form method="post" action="/app/settings">${csrfField(c)}<div class="row">${field(t('Company name'), 'name', co.name, { req: true })}${field(t('Company legal name'), 'legal_name', co.legal_name)}${field(t('Network name'), 'network_name', co.network_name)}${field(t('Owner name'), 'owner_name', co.owner_name)}${field(t('Phone'), 'phone', co.phone)}${field(t('Secondary phone'), 'phone2', co.phone2)}${field(t('WhatsApp'), 'whatsapp', co.whatsapp)}${field(t('Country'), 'country', co.country)}${field(t('City'), 'city', co.city)}${field(t('Address'), 'address', co.address)}${field(t('Website'), 'website', co.website)}${field(t('Tax registration number'), 'tax_no', co.tax_no)}${field(t('Brand primary color'), 'brand_color', co.brand_color || '#2563eb', { type: 'color' })}${field(t('Brand secondary color'), 'brand_color2', co.brand_color2 || '#0f172a', { type: 'color' })}${field(t('Logo height (px)'), 'logo_h', co.logo_h || 48, { type: 'number' })}</div>
<div class="row">${img('logo', 'Logo', co.logo, 120)}${img('stamp', 'Company stamp (optional)', co.stamp, 120)}</div>
<p><label>${t('Description')}</label><textarea name="description" rows="2">${esc(co.description)}</textarea></p><p><label>${t('Customer support information')}</label><textarea name="support_info" rows="2">${esc(co.support_info)}</textarea></p><p><label>${t('Invoice footer text')}</label><textarea name="invoice_footer" rows="2">${esc(co.invoice_footer)}</textarea></p>
<p class="mut">${t('Logos keep their aspect ratio. Allowed: PNG, JPG, WEBP, GIF up to 200KB.')}</p><p><button>${t('Save')}</button></p></form></div>
<script>function mcImg(i,id){var f=i.files[0];if(!f)return;if(f.size>200000){alert('Max 200KB');i.value='';return}var r=new FileReader();r.onload=function(){document.getElementById(id).value=r.result};r.readAsDataURL(f)}</script>`, nav(req)));
  });
  app.post('/app/settings', needAdmin, (req, res) => {
    const b = req.body, t = req.i.t, name = clean(b.name);
    const old = q1('SELECT logo,stamp FROM companies WHERE id=?', req.user.company_id);
    if (!name) return go(res, '/app/settings', 'err', t('required'));
    const pick = (k) => (b['rm_' + k] ? '' : (b[k] === undefined ? old[k] : String(b[k])));
    const logo = pick('logo'), stamp = pick('stamp');
    if (!okImg(logo) || !okImg(stamp)) return go(res, '/app/settings', 'err', t('Invalid image'));
    const c1 = clean(b.brand_color, 7), c2 = clean(b.brand_color2, 7);
    if (!okColor(c1) || !okColor(c2)) return go(res, '/app/settings', 'err', t('Invalid color'));
    const lh = Math.round(Number(b.logo_h));
    if (!(lh >= 16 && lh <= 200)) return go(res, '/app/settings', 'err', t('Invalid logo size'));
    const web = clean(b.website, 200);
    if (web && !/^https?:\/\/[^\s<>"']+$/i.test(web)) return go(res, '/app/settings', 'err', t('Invalid website'));
    try {
      run('UPDATE companies SET name=?,legal_name=?,network_name=?,owner_name=?,phone=?,phone2=?,whatsapp=?,country=?,city=?,address=?,website=?,tax_no=?,description=?,support_info=?,invoice_footer=?,brand_color=?,brand_color2=?,logo_h=?,logo=?,stamp=? WHERE id=?', name, clean(b.legal_name, 200), clean(b.network_name, 120), clean(b.owner_name), clean(b.phone, 40), clean(b.phone2, 40), clean(b.whatsapp, 40), clean(b.country, 40), clean(b.city, 80), clean(b.address, 300), web, clean(b.tax_no, 60), clean(b.description, 1000), clean(b.support_info, 600), clean(b.invoice_footer, 600), c1, c2, lh, logo, stamp, req.user.company_id);
    } catch (e) { return go(res, '/app/settings', 'err', t('Could not save')); }
    audit(req, 'company_settings_updated', name);
    go(res, '/app/settings', 'ok', t('Saved'));
  });
  app.get('/app/audit', needCompany, need('audit.view'), (req, res) => {
    const rows = q('SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON u.id=a.user_id WHERE a.company_id=? ORDER BY a.id DESC LIMIT 200', req.user.company_id);
    res.send(page(ctx(req), 'Audit', `<div class="card tbl"><table><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr>${rows.map((a) => `<tr><td>${esc(a.ts)}</td><td>${esc(a.username || '-')}</td><td>${esc(a.action)}</td><td>${esc(a.detail)}</td><td>${esc(a.ip)}</td></tr>`).join('')}</table></div>`, nav(req)));
  });

  app.use((req, res) => (req.user ? deny(req, res, 404) : res.status(404).send('Not found')));
  app.use((err, req, res, next) => { const code = err && err.status >= 400 && err.status < 500 ? err.status : 500; if (code === 500) console.error(err); res.status(code).send(code === 413 ? 'Request too large' : code === 500 ? 'Server error' : 'Bad request'); });
  return app;
}
module.exports = { createApp, ROLE_PRESETS };
