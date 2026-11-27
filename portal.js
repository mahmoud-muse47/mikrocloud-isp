'use strict';
// Portal separation by hostname, tenant custom domains (verified by DNS TXT), brand settings, security monitoring page.
const crypto = require('node:crypto');
const dns = require('node:dns').promises;
const V = require('./views');
const { esc, page, csrfField, field } = V;
const makeConfig = require('./config');

const FQDN = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const sqlTs = (ms) => new Date(ms).toISOString().slice(0, 19).replace('T', ' ');

module.exports = function portal(opts = {}) {
  const cfg = opts.config || makeConfig();
  let q1 = () => null, q = () => [], run = () => { };
  const bind = (db) => { q1 = (s, ...a) => db.prepare(s).get(...a); q = (s, ...a) => db.prepare(s).all(...a); run = (s, ...a) => db.prepare(s).run(...a); };
  const loadBrand = () => { const r = q1("SELECT v FROM app_settings WHERE k='brand_name'"); V.setBrand((r && r.v) || cfg.appName); };

  // Early middleware: HTTPS redirect, host validation, portal + tenant resolution. Never trusts an unknown Host header.
  const hostGuard = (req, res, next) => {
    const h = (req.headers.host || '').toLowerCase().replace(/:\d+$/, '');
    if (cfg.forceHttps && req.headers['x-forwarded-proto'] === 'http' && req.path !== '/health') {
      return res.redirect(301, 'https://' + h + req.originalUrl);
    }
    req.portal = 'any'; req.tenantId = null;
    const configured = !!(cfg.adminDomain || cfg.clientDomain);
    if (cfg.adminDomain && h === cfg.adminDomain) req.portal = 'admin';
    else if (cfg.clientDomain && h === cfg.clientDomain) req.portal = 'client';
    else if (cfg.allowedHosts.includes(h)) req.portal = 'any';
    else {
      const d = FQDN.test(h) ? q1('SELECT company_id FROM tenant_domains WHERE domain=? AND verified=1', h) : null;
      if (d) { req.portal = 'client'; req.tenantId = d.company_id; }
      else if (configured || cfg.allowedHosts.length) { if (req.path === '/health') return next(); return res.status(421).type('text').send('Unknown host'); }
    }
    const p = req.path;
    if (req.portal === 'admin') {
      if (p === '/' ) return res.redirect(303, '/admin');
      if (p === '/login' && req.method === 'GET') return res.redirect(303, '/admin/login');
      if (!(p.startsWith('/admin') || p === '/logout' || p === '/login' || p === '/login/2fa' || p.startsWith('/lang/') || p === '/health')) return res.status(404).type('text').send('Not found');
    } else if (req.portal === 'client') {
      if (p.startsWith('/admin')) return res.status(404).type('text').send('Not found');
    }
    next();
  };
  // after the session is loaded: a session from one portal is never valid on another
  const portalSession = (req, res, next) => {
    const u = req.user;
    if (u && ((req.portal === 'admin' && u.role !== 'super_admin') || (req.portal === 'client' && u.role === 'super_admin') || (req.tenantId && u.company_id !== req.tenantId))) { req.user = null; req.session = null; }
    next();
  };
  const loginAllowed = (req, u) => !((req.portal === 'admin' && u.role !== 'super_admin') || (req.portal === 'client' && u.role === 'super_admin') || (req.tenantId && u.company_id !== req.tenantId));

  const init = ({ app, db, audit, ctx, go, needSuper, nav }) => {
    bind(db); loadBrand();
    const dom = (req) => req.i.t;
    // ---- System: brand + domain configuration status
    app.get('/admin/system', needSuper, (req, res) => {
      const t = req.i.t, c = ctx(req);
      const row = (k, v) => `<tr><td>${esc(k)}</td><td>${v ? esc(v) : '<span style="color:var(--mut)">' + t('Not set') + '</span>'}</td></tr>`;
      res.send(page(c, 'System', `<div class="card"><h3>${t('Branding')}</h3><form method="post" action="/admin/system/brand" class="row">${csrfField(c)}${field(t('Product name'), 'brand_name', V.getBrand())}<div style="padding-top:22px"><button>${t('Save')}</button></div></form></div>
<div class="card tbl"><h3>${t('Domain configuration (environment)')}</h3><table>${row('APP_NAME', cfg.appName)}${row('APP_URL', cfg.appUrl)}${row('ADMIN_DOMAIN', cfg.adminDomain)}${row('CLIENT_DOMAIN', cfg.clientDomain)}${row('ALLOWED_HOSTS', cfg.allowedHosts.join(', '))}${row('SESSION_DOMAIN', cfg.sessionDomain)}${row('FORCE_HTTPS', cfg.forceHttps ? 'on' : 'off')}</table>
<p style="color:var(--mut)">${t('Change these in the hosting environment, no code change needed. When ADMIN_DOMAIN and CLIENT_DOMAIN are set, every other hostname is rejected unless it is in ALLOWED_HOSTS or is a verified client domain.')}</p></div>`, nav(req)));
    });
    app.post('/admin/system/brand', needSuper, (req, res) => {
      const n = String(req.body.brand_name || '').trim().slice(0, 60);
      if (!n) return go(res, '/admin/system', 'err', req.i.t('required'));
      run("DELETE FROM app_settings WHERE k='brand_name'"); run("INSERT INTO app_settings(k,v) VALUES('brand_name',?)", n);
      loadBrand(); audit(req, 'brand_changed', n); go(res, '/admin/system', 'ok', req.i.t('Saved'));
    });

    // ---- Client custom domains
    const getCo = (req, res) => { const c = q1('SELECT * FROM companies WHERE id=?', Number(req.params.id)); if (!c) res.status(404).send('Not found'); return c; };
    app.get('/admin/companies/:id/domains', needSuper, (req, res) => {
      const co = getCo(req, res); if (!co) return;
      const t = req.i.t, c = ctx(req);
      const rows = q('SELECT * FROM tenant_domains WHERE company_id=? ORDER BY id', co.id);
      res.send(page(c, co.name, `<div class="card"><h3>${esc(co.name)} - ${t('Custom domains')}</h3><p style="color:var(--mut)">${t('Add the domain, then create the DNS TXT record shown, then press Verify. Until verified the domain is never served.')}</p>
<form method="post" action="/admin/companies/${co.id}/domains" class="row">${csrfField(c)}${field(t('Domain'), 'domain', '', { req: true })}<div style="padding-top:22px"><button>${t('Add')}</button></div></form></div>
<div class="card tbl"><table><tr><th>${t('Domain')}</th><th>${t('Status')}</th><th>DNS TXT</th><th></th></tr>${rows.map((r) => `<tr><td>${esc(r.domain)}</td><td>${r.verified ? t('Verified') : t('Pending')}</td><td>${r.verified ? '' : `<code>_verify.${esc(r.domain)}</code> = <code>${esc(r.token)}</code>`}</td><td>${r.verified ? '' : `<form class="inline" method="post" action="/admin/companies/${co.id}/domains/${r.id}/verify">${csrfField(c)}<button>${t('Verify')}</button></form> `}<form class="inline" method="post" action="/admin/companies/${co.id}/domains/${r.id}/delete">${csrfField(c)}<button class="bad">${t('Remove')}</button></form></td></tr>`).join('') || `<tr><td colspan="4">${t('No results')}</td></tr>`}</table></div>
<p><a href="/admin/companies/${co.id}">${t('Back')}</a></p>`, nav(req)));
    });
    app.post('/admin/companies/:id/domains', needSuper, (req, res) => {
      const co = getCo(req, res); if (!co) return;
      const back = `/admin/companies/${co.id}/domains`, t = req.i.t;
      const d = V.hostOnly(req.body.domain);
      const reserved = [cfg.adminDomain, cfg.clientDomain, ...cfg.allowedHosts].filter(Boolean);
      if (!FQDN.test(d) || reserved.includes(d) || /(^|\.)(localhost|local|internal|invalid|test|example)$/.test(d)) return go(res, back, 'err', t('Invalid domain'));
      if (q1('SELECT 1 x FROM tenant_domains WHERE domain=?', d)) return go(res, back, 'err', t('duplicate'));
      run('INSERT INTO tenant_domains(company_id,domain,token) VALUES(?,?,?)', co.id, d, 'mc-' + crypto.randomBytes(16).toString('hex'));
      audit(req, 'domain_added', d, co.id); go(res, back, 'ok', t('Saved'));
    });
    app.post('/admin/companies/:id/domains/:rid/verify', needSuper, async (req, res) => {
      const co = getCo(req, res); if (!co) return;
      const back = `/admin/companies/${co.id}/domains`, t = req.i.t;
      const r = q1('SELECT * FROM tenant_domains WHERE id=? AND company_id=?', Number(req.params.rid), co.id);
      if (!r) return go(res, back, 'err', t('Not found'));
      let ok = false;
      try { const recs = await dns.resolveTxt('_verify.' + r.domain); ok = recs.some((x) => x.join('') === r.token); } catch (e) { ok = false; }
      if (!ok) { audit(req, 'domain_verify_failed', r.domain, co.id); return go(res, back, 'err', t('DNS record not found yet')); }
      run('UPDATE tenant_domains SET verified=1, verified_at=? WHERE id=?', sqlTs(Date.now()), r.id);
      audit(req, 'domain_verified', r.domain, co.id); go(res, back, 'ok', t('Verified'));
    });
    app.post('/admin/companies/:id/domains/:rid/delete', needSuper, (req, res) => {
      const co = getCo(req, res); if (!co) return;
      run('DELETE FROM tenant_domains WHERE id=? AND company_id=?', Number(req.params.rid), co.id);
      audit(req, 'domain_removed', String(req.params.rid), co.id); go(res, `/admin/companies/${co.id}/domains`, 'ok', req.i.t('Saved'));
    });

    // ---- Security & System Monitoring
    app.get('/admin/security', needSuper, (req, res) => {
      const t = req.i.t, c = ctx(req), day = sqlTs(Date.now() - 864e5);
      const n = (s, ...a) => q1(s, ...a).n;
      const fails = n("SELECT count(*) n FROM login_history WHERE success=0 AND ts>?", day);
      const oks = n("SELECT count(*) n FROM login_history WHERE success=1 AND ts>?", day);
      const locked = q('SELECT username, locked_until FROM users WHERE locked_until>?', Date.now());
      const ips = q("SELECT ip, count(*) n FROM login_history WHERE success=0 AND ts>? GROUP BY ip HAVING count(*)>=5 ORDER BY n DESC LIMIT 10", day);
      const sup = q("SELECT username, totp_on FROM users WHERE role='super_admin'");
      const priv = q("SELECT ts, action, detail, ip FROM audit_log WHERE action IN ('password_changed','password_reset_issued','password_reset_done','brand_changed','domain_added','domain_verified','domain_removed','company_deleted','2fa_enabled','2fa_disabled','role_changed') ORDER BY id DESC LIMIT 15");
      const resets = n("SELECT count(*) n FROM reset_requests WHERE status='open'");
      const devAuth = n("SELECT count(*) n FROM device_alerts WHERE created_at>?", day);
      const rec = q('SELECT ts, identifier, reason, ip FROM login_history WHERE success=0 ORDER BY id DESC LIMIT 15');
      const chk = (ok, label, note = '') => `<tr><td>${ok ? '<b style="color:var(--ok)">OK</b>' : '<b style="color:var(--bad)">!</b>'}</td><td>${t(label)}</td><td style="color:var(--mut)">${note ? t(note) : ''}</td></tr>`;
      const stat = (v, l) => `<div class="stat"><b>${v}</b><span>${t(l)}</span></div>`;
      res.send(page(c, 'Security', `<div class="grid">${stat(fails, 'Failed logins (24h)')}${stat(oks, 'Successful logins (24h)')}${stat(locked.length, 'Locked accounts')}${stat(ips.length, 'Suspicious IPs')}${stat(resets, 'Open reset requests')}${stat(devAuth, 'Device alerts (24h)')}</div>
<div class="card tbl" style="margin-top:16px"><h3>${t('Security controls')}</h3><table>
${chk(!!opts.secureCookies, 'Secure cookies and HSTS', 'Turn on COOKIE_SECURE')}${chk(!!process.env.DATA_KEY, 'Dedicated encryption key (DATA_KEY)', 'Set DATA_KEY in the environment')}${chk(sup.every((s) => s.totp_on), 'Two-factor on every Super Admin', 'Enable 2FA in Account')}${chk(!!(cfg.adminDomain && cfg.clientDomain), 'Separate Admin and Client domains', 'Set ADMIN_DOMAIN and CLIENT_DOMAIN after buying a domain')}${chk(cfg.forceHttps, 'HTTP to HTTPS redirect (app level)', 'Set FORCE_HTTPS=1')}
<tr><td><b style="color:var(--warn)">?</b></td><td>${t('Automated encrypted off-site backups')}</td><td style="color:var(--mut)">${t('Not configured. Manual export only (backup.js). See BACKUP_AND_RECOVERY.md')}</td></tr>
<tr><td><b style="color:var(--warn)">?</b></td><td>${t('Vulnerability scan results')}</td><td style="color:var(--mut)">${t('No scanner connected. Dependency audit is run manually.')}</td></tr></table></div>
<div class="card tbl"><h3>${t('Suspicious IPs (5+ failures in 24h)')}</h3><table>${ips.map((r) => `<tr><td>${esc(r.ip)}</td><td>${r.n}</td></tr>`).join('') || `<tr><td>${t('No results')}</td></tr>`}</table></div>
<div class="card tbl"><h3>${t('Locked accounts')}</h3><table>${locked.map((r) => `<tr><td>${esc(r.username)}</td><td>${esc(sqlTs(r.locked_until))}</td></tr>`).join('') || `<tr><td>${t('No results')}</td></tr>`}</table></div>
<div class="card tbl"><h3>${t('Recent failed logins')}</h3><table>${rec.map((r) => `<tr><td>${esc(r.ts)}</td><td>${esc(r.identifier)}</td><td>${esc(r.reason)}</td><td>${esc(r.ip)}</td></tr>`).join('') || `<tr><td>${t('No results')}</td></tr>`}</table></div>
<div class="card tbl"><h3>${t('Privilege and configuration changes')}</h3><table>${priv.map((r) => `<tr><td>${esc(r.ts)}</td><td>${esc(r.action)}</td><td>${esc(r.detail)}</td><td>${esc(r.ip)}</td></tr>`).join('') || `<tr><td>${t('No results')}</td></tr>`}</table></div>`, nav(req)));
    });
  };
  return { init, hostGuard, portalSession, loginAllowed, bind, loadBrand, cfg };
};
