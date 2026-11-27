'use strict';
const crypto = require('node:crypto');
const qrcode = require('qrcode-generator');
const { esc, page, csrfField, field } = require('./views');

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32enc = (buf) => { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; };
const b32dec = (s) => { let bits = ''; for (const ch of String(s).replace(/=+$/, '')) { const v = B32.indexOf(ch); if (v < 0) return null; bits += v.toString(2).padStart(5, '0'); } const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
const newSecret = () => b32enc(crypto.randomBytes(20));
function hotp(secret, counter) {
  const key = b32dec(secret); const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(buf).digest(); const o = h[19] & 15;
  return String(((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1000000).padStart(6, '0');
}
const totp = (secret, now = Date.now()) => hotp(secret, Math.floor(now / 30000));
function verifyTotp(secret, code, now = Date.now()) {
  code = String(code || '').replace(/\s/g, ''); if (!/^\d{6}$/.test(code) || !secret) return false;
  for (const d of [-1, 0, 1]) { const x = hotp(secret, Math.floor(now / 30000) + d); if (crypto.timingSafeEqual(Buffer.from(x), Buffer.from(code))) return true; }
  return false;
}
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const newRecovery = () => Array.from({ length: 8 }, () => crypto.randomBytes(5).toString('hex').match(/.{5}/g).join('-'));
// returns true and consumes the code when it matches
function useRecovery(q1, run, u, code) {
  const c = String(code || '').trim().toLowerCase(); if (!/^[0-9a-f]{5}-[0-9a-f]{5}$/.test(c)) return false;
  const list = String(u.totp_recovery || '').split(',').filter(Boolean), h = sha(c);
  if (!list.includes(h)) return false;
  run('UPDATE users SET totp_recovery=? WHERE id=?', list.filter((x) => x !== h).join(','), u.id); return true;
}

function init(h) {
  const { S, app, q1, run, audit, ctx, go, needLogin, verifyPassword, nav } = h;
  const qr = (text) => { const m = qrcode(0, 'M'); m.addData(text); m.make(); return m.createSvgTag({ cellSize: 4, margin: 2, scalable: true }); };
  const fresh = (req) => q1('SELECT * FROM users WHERE id=?', req.user.id);

  app.get('/account/2fa', needLogin, (req, res) => {
    const t = req.i.t, c = ctx(req), u = fresh(req), codes = req.query.codes ? [] : null;
    let body;
    if (u.totp_on) {
      body = `<p>${t('Two-factor authentication is on')}</p><form method="post" action="/account/2fa/disable">${csrfField(c)}<div class="row">${field(t('Current password'), 'password', '', { type: 'password', req: true })}${field(t('Authentication code'), 'code', '', { req: true })}</div><p><button class="bad">${t('Turn off two-factor authentication')}</button></p></form>`;
    } else if (u.totp_secret) {
      const uri = `otpauth://totp/MikroCloud:${encodeURIComponent(u.username)}?secret=${S.dec(u.totp_secret)}&issuer=MikroCloud&digits=6&period=30`;
      body = `<p>${t('Scan the QR code with an authenticator app (Google Authenticator, Microsoft Authenticator, Authy), then enter the 6-digit code.')}</p><div style="max-width:200px;direction:ltr">${qr(uri)}</div><p class="mut" style="direction:ltr">${esc(u.totp_secret)}</p><form method="post" action="/account/2fa/enable">${csrfField(c)}<div class="row">${field(t('Authentication code'), 'code', '', { req: true })}</div><p><button>${t('Confirm and turn on')}</button></p></form>`;
    } else {
      body = `<p>${t('Add a second step at sign-in using an authenticator app. Optional.')}</p><form method="post" action="/account/2fa/start">${csrfField(c)}<p><button>${t('Set up two-factor authentication')}</button></p></form>`;
    }
    res.send(page(c, 'Two-factor authentication', `<div class="card"><h3>${t('Two-factor authentication')}</h3>${body}</div>`, nav(req)));
  });
  app.post('/account/2fa/start', needLogin, (req, res) => {
    const u = fresh(req); if (!u.totp_on) run("UPDATE users SET totp_secret=?, totp_on=0 WHERE id=?", S.enc(newSecret()), u.id);
    res.redirect(303, '/account/2fa');
  });
  app.post('/account/2fa/enable', needLogin, (req, res) => {
    const t = req.i.t, u = fresh(req);
    if (u.totp_on || !u.totp_secret || !verifyTotp(S.dec(u.totp_secret), req.body.code)) return go(res, '/account/2fa', 'err', t('Invalid code'));
    const rec = newRecovery();
    run('UPDATE users SET totp_on=1, totp_recovery=? WHERE id=?', rec.map(sha).join(','), u.id);
    audit(req, '2fa_enabled');
    const c = ctx(req);
    res.send(page(c, 'Two-factor authentication', `<div class="card"><h3>${t('Two-factor authentication is on')}</h3><p>${t('Save these recovery codes now. Each works once if you lose your phone. They will not be shown again.')}</p><pre style="direction:ltr;font-size:16px">${rec.join('\n')}</pre><p><a class="btn" href="/account">${t('Done')}</a></p></div>`, nav(req)));
  });
  app.post('/account/2fa/disable', needLogin, (req, res) => {
    const t = req.i.t, u = fresh(req);
    if (u.role === 'super_admin' && h.requireSuper2fa) return go(res, '/account/2fa', 'err', t('Two-factor cannot be turned off for the super admin'));
    if (!verifyPassword(String(req.body.password || ''), u.password_hash) || !(verifyTotp(S.dec(u.totp_secret), req.body.code) || useRecovery(q1, run, u, req.body.code))) { audit(req, '2fa_disable_failed'); return go(res, '/account/2fa', 'err', t('Invalid code')); }
    run("UPDATE users SET totp_on=0, totp_secret='', totp_recovery='' WHERE id=?", u.id); audit(req, '2fa_disabled');
    go(res, '/account/2fa', 'ok', t('Saved'));
  });
}
module.exports = { init, verifyTotp, useRecovery, totp, newSecret };
