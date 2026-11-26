const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const css = `
:root{--p:#2563eb;--bg:#f1f5f9;--card:#fff;--tx:#0f172a;--mut:#64748b;--bd:#e2e8f0;--ok:#16a34a;--bad:#dc2626;--warn:#d97706}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,"Segoe UI",Tahoma,Arial,sans-serif;background:var(--bg);color:var(--tx)}
a{color:var(--p);text-decoration:none}header{background:#0f172a;color:#fff;display:flex;align-items:center;gap:16px;padding:10px 20px;flex-wrap:wrap}
header a{color:#cbd5e1}header a:hover{color:#fff}header .brand{font-weight:700;color:#fff}header .sp{flex:1}
main{max-width:1100px;margin:20px auto;padding:0 14px}.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:18px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.stat{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:14px}
.info{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));border:1px solid var(--bd);border-radius:12px;overflow:hidden;margin:12px 0;background:#fff}.info>div{padding:12px 14px;border-inline-end:1px solid var(--bd);border-bottom:1px solid var(--bd);margin:0 -1px -1px 0}.info small{display:block;color:var(--mut);font-size:12px;margin-bottom:4px}.info strong{font-size:15px;font-weight:600;word-break:break-word}.head{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}.head h3{margin:0;font-size:22px}.acts{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.stat b{display:block;font-size:28px}.stat span{color:var(--mut);font-size:13px}
table{width:100%;border-collapse:collapse}th,td{padding:8px 10px;border-bottom:1px solid var(--bd);text-align:start;font-size:14px}th{color:var(--mut);font-weight:600}
.tbl{overflow-x:auto}label{display:block;margin:10px 0 4px;font-size:13px;color:var(--mut)}
input,select,textarea{width:100%;padding:9px 10px;border:1px solid var(--bd);border-radius:8px;font:inherit;background:#fff}
button,.btn{background:var(--p);color:#fff;border:0;border-radius:8px;padding:8px 14px;font:inherit;cursor:pointer;display:inline-block}
.btn.sec,button.sec{background:#e2e8f0;color:var(--tx)}button.bad{background:var(--bad)}button.ok{background:var(--ok)}
.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0 14px}.flash{padding:10px 14px;border-radius:8px;margin-bottom:12px}
.flash.err{background:#fee2e2;color:#991b1b}.flash.ok{background:#dcfce7;color:#166534}.badge{padding:2px 8px;border-radius:99px;font-size:12px;background:#e2e8f0}
.badge.active,.badge.paid{background:#dcfce7;color:#166534}.badge.suspended,.badge.expired,.badge.unpaid{background:#fee2e2;color:#991b1b}.badge.trial{background:#fef3c7;color:#92400e}
.login{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f172a,#1e3a8a)}
.login .box{background:#fff;border-radius:16px;padding:30px;width:min(400px,92vw);box-shadow:0 20px 50px rgba(0,0,0,.35)}
.logo{width:54px;height:54px;border-radius:14px;background:var(--p);color:#fff;display:flex;align-items:center;justify-content:center;font-size:26px;font-weight:700;margin:0 auto 10px}
.inline{display:inline}.pw{position:relative}.pw button{position:absolute;inset-inline-end:6px;top:6px;padding:4px 8px}
.spin{display:none;width:14px;height:14px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:s .7s linear infinite;vertical-align:middle;margin-inline-start:6px}
form.loading .spin{display:inline-block}@keyframes s{to{transform:rotate(360deg)}}.mut{color:var(--mut)}.pager{display:flex;gap:8px;margin-top:10px;align-items:center}
.checks label{display:inline-flex;gap:6px;align-items:center;margin:4px 12px 4px 0;color:var(--tx)}.checks input{width:auto}
  .row2{display:grid;grid-template-columns:1fr 1fr;gap:0 18px}@media(max-width:700px){.row2{grid-template-columns:1fr}}
@media(max-width:600px){header{padding:8px 10px}}
.shell{display:grid;grid-template-columns:minmax(0,1fr) 250px;gap:18px;max-width:1360px;margin:20px auto;padding:0 14px;direction:ltr;align-items:start}
.shell>*{direction:var(--dir)}.shell main{margin:0;padding:0;max-width:none;grid-column:1;grid-row:1;min-width:0}
.side{grid-column:2;grid-row:1;position:sticky;top:14px;background:#fff;border:1px solid var(--bd);border-radius:14px;padding:12px;font-size:15px}
.side a{display:block;padding:11px 14px;margin:0 0 9px;border-radius:10px;background:linear-gradient(#fff,#f1f5f9);border:1px solid #cbd5e1;box-shadow:0 2px 0 #cbd5e1,0 4px 10px rgba(15,23,42,.08);color:var(--tx);font-size:15px;font-weight:500;line-height:1.3;transition:transform .08s,box-shadow .08s}
.side a:hover{background:#eff6ff;border-color:var(--p);color:var(--p)}.side a:active{transform:translateY(2px);box-shadow:0 0 0 #cbd5e1}
.side a.on{background:var(--p);border-color:var(--p);color:#fff;box-shadow:0 2px 0 #1d4ed8,0 4px 10px rgba(37,99,235,.35)}.side a:last-child{margin-bottom:0}
@media(max-width:800px){.shell{grid-template-columns:1fr}.side{grid-column:1;grid-row:1;position:static}.shell main{grid-row:2;grid-column:1}}`;
const js = `document.addEventListener('submit',e=>{e.target.classList&&e.target.classList.add('loading')});
(function(){var s=document.getElementById('side');if(!s)return;var p=location.pathname,best=null;s.querySelectorAll('a').forEach(function(a){var h=a.getAttribute('href');if((p===h||(h.length>5&&p.indexOf(h)===0))&&(!best||h.length>best.getAttribute('href').length))best=a});if(best)best.className='on'})();
function tp(id,b){var i=document.getElementById(id);i.type=i.type==='password'?'text':'password'}`;

function page(ctx, title, body, nav = '') {
  const { i, user, csrf, flash, path } = ctx;
  const t = i.t;
  const side = !!(user && nav && user.role !== 'super_admin');
  const other = i.lang === 'ar' ? 'en' : 'ar';
  return `<!doctype html><html lang="${i.lang}" dir="${i.rtl ? 'rtl' : 'ltr'}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} - MikroCloud</title><style>${css}</style></head><body>
<header><span class="brand">MikroCloud</span>${side ? '' : nav}<span class="sp"></span>
<a href="/lang/${other}?back=${encodeURIComponent(path || '/')}">${other === 'ar' ? 'العربية' : 'English'}</a>
${user ? `<a href="/account">${esc(user.name)}</a><form class="inline" method="post" action="/logout"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="sec">${t('Logout')}</button></form>` : ''}</header>
${side ? `<div class="shell" style="--dir:${i.rtl ? 'rtl' : 'ltr'}">` : ''}<main>${flash ? `<div class="flash ${flash.type}">${esc(flash.msg)}</div>` : ''}${body}</main>${side ? `<aside class="side" id="side">${nav}</aside></div>` : ''}<script>${js}</script></body></html>`;
}
const csrfField = (ctx) => `<input type="hidden" name="_csrf" value="${esc(ctx.csrf)}">`;
const infoGrid = (items) => `<div class="info">${items.map(([l, x]) => `<div><small>${esc(l)}</small><strong>${x === undefined || x === null || x === '' ? '-' : x}</strong></div>`).join('')}</div>`;
const badge = (v, t) => `<span class="badge ${esc(v)}">${esc(t(v[0].toUpperCase() + v.slice(1)))}</span>`;
function field(label, name, val = '', opts = {}) {
  const { type = 'text', req = false, ta = false } = opts;
  return `<div><label>${esc(label)}${req ? ' *' : ''}</label>${ta
    ? `<textarea name="${name}" rows="3">${esc(val)}</textarea>`
    : `<input type="${type}" name="${name}" value="${esc(val)}" ${req ? 'required' : ''} ${type === 'password' ? 'autocomplete="new-password"' : ''}>`}</div>`;
}
function select(label, name, val, options) {
  return `<div><label>${esc(label)}</label><select name="${name}">${options.map(([v, l]) => `<option value="${esc(v)}" ${String(v) === String(val) ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></div>`;
}
function login(ctx, err) {
  const t = ctx.i.t;
  const other = ctx.i.lang === 'ar' ? 'en' : 'ar';
  return `<!doctype html><html lang="${ctx.i.lang}" dir="${ctx.i.rtl ? 'rtl' : 'ltr'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in - MikroCloud</title><style>${css}</style></head>
<body class="login"><div class="box"><div class="logo">M</div><h2 style="text-align:center;margin:4px 0 18px">${t('MikroCloud ISP Manager')}</h2>
${err ? `<div class="flash err">${esc(err)}</div>` : ''}
<form method="post" action="/login">${csrfField(ctx)}
<label>${t('Email or username')}</label><input name="identifier" required autofocus autocomplete="username">
<label>${t('Password')}</label><div class="pw"><input id="pw" type="password" name="password" required autocomplete="current-password"><button type="button" class="sec" onclick="tp('pw')">${t('Show')}/${t('Hide')}</button></div>
<label style="display:flex;gap:6px;align-items:center"><input type="checkbox" name="remember" value="1" style="width:auto"> ${t('Remember me')}</label>
<p style="margin:14px 0 0"><button style="width:100%">${t('Sign in')}<span class="spin"></span></button></p></form>
<p style="text-align:center;margin-top:14px"><a href="/lang/${other}?back=/login">${other === 'ar' ? 'العربية' : 'English'}</a></p></div><script>${js}</script></body></html>`;
}
module.exports = { infoGrid, esc, page, csrfField, badge, field, select, login };
