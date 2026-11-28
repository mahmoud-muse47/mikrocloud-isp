let BRAND = 'MikroCloud';
const setBrand = (b) => { BRAND = b || 'MikroCloud'; };
const getBrand = () => BRAND;
const hostOnly = (s) => String(s || '').toLowerCase().trim().replace(/^https?:\/\//, '').replace(/[/:?#].*$/, '');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const AD = require('./adminui');
const css0 = `
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
.flash a{color:inherit;text-decoration:underline}.flash.warn{background:#fef3c7;color:#92400e}.flash.err{background:#fee2e2;color:#991b1b}.flash.ok{background:#dcfce7;color:#166534}.badge{padding:2px 8px;border-radius:99px;font-size:12px;background:#e2e8f0}
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
.side summary{display:block;list-style:none;cursor:pointer;padding:11px 14px;margin:0 0 9px;border-radius:10px;background:linear-gradient(#fff,#f1f5f9);border:1px solid #cbd5e1;box-shadow:0 2px 0 #cbd5e1,0 4px 10px rgba(15,23,42,.08);color:var(--tx);font-size:15px;font-weight:500;line-height:1.3}.side summary::-webkit-details-marker{display:none}.side summary:after{content:'\\25BE';float:inline-end}.side details:not([open]) summary:after{content:'\\25B8'}.side details a{margin-inline-start:18px;font-size:14px}.side a.on{background:var(--p);border-color:var(--p);color:#fff;box-shadow:0 2px 0 #1d4ed8,0 4px 10px rgba(37,99,235,.35)}.side a:last-child{margin-bottom:0}
.cl{--p:#16a34a}.cl header{background:#14532d}.cl a{color:#15803d}.cl header a{color:#d1fae5}.cl .side a{color:var(--tx)}.cl .side a:hover{background:#f0fdf4}.cl .side a.on,.cl .side a.on:hover{color:#fff;box-shadow:0 2px 0 #15803d,0 4px 10px rgba(22,163,74,.35)}.cl .side summary{color:var(--tx)}.cl button:not(.sec):not(.bad),.cl .btn:not(.sec){background:#16a34a}.cl.login{background:linear-gradient(135deg,#052e16,#166534)}
.rtchip{display:inline-flex;align-items:center;gap:6px;background:rgba(255,255,255,.16);color:#fff;border-radius:999px;padding:3px 12px;font-size:13px;text-decoration:none;margin-inline-start:12px}.rtchip i{width:10px;height:10px;border-radius:50%;display:inline-block;box-shadow:0 0 0 2px rgba(255,255,255,.5)}
.vb{background:#b91c1c;color:#fff;text-align:center;padding:8px 12px;font-weight:600;position:sticky;top:0;z-index:50;display:flex;gap:14px;justify-content:center;align-items:center}.vb button{padding:4px 14px}
.mo{position:fixed;inset:0;background:rgba(15,23,42,.55);display:flex;align-items:center;justify-content:center;z-index:9999;padding:16px}.mb{background:#fff;border-radius:14px;border:2px solid #dc2626;max-width:440px;width:100%;padding:26px 24px;text-align:center;box-shadow:0 20px 50px rgba(0,0,0,.35);font-size:17px;line-height:1.6;color:#b91c1c;font-weight:600}.mb .bt{margin-top:18px;display:flex;gap:10px;justify-content:center}.mb button{min-width:100px;font-size:16px;background:#dc2626;color:#fff;border:0;border-radius:9px;padding:9px 18px;cursor:pointer}.mb button.sec{background:#e2e8f0;color:#334155}.mb.ok{border-color:#16a34a;color:#166534}.mb.ok button{background:#16a34a}.mb.warn{border-color:#d97706;color:#b45309}.mb.warn button{background:#d97706}
@media(max-width:800px){.shell{grid-template-columns:1fr}.side{grid-column:1;grid-row:1;position:static}.shell main{grid-row:2;grid-column:1}}`;
const css = css0 + AD.css;
const js = `document.addEventListener('submit',e=>{e.target.classList&&e.target.classList.add('loading')});
(function(){var s=document.getElementById('side');if(!s)return;var p=location.pathname,best=null;s.querySelectorAll('a').forEach(function(a){var h=a.getAttribute('href');if((p===h||(h.length>5&&p.indexOf(h)===0))&&(!best||h.length>=best.getAttribute('href').length))best=a});if(best)best.className='on'})();

(function(){var last=null,okFlag=false;document.addEventListener('submit',function(e){last=e.target},true);
function ar(){return document.documentElement.lang==='ar'}
window.mcModal=function(msg,yes,cls){var o=document.createElement('div');o.className='mo';var b=document.createElement('div');b.className='mb '+(cls||'');var m=document.createElement('div');m.textContent=msg;var t=document.createElement('div');t.className='bt';var ok=document.createElement('button');ok.type='button';ok.textContent=ar()?'موافق':'OK';t.appendChild(ok);if(yes){var c=document.createElement('button');c.type='button';c.className='sec';c.textContent=ar()?'إلغاء':'Cancel';c.onclick=function(){o.remove()};t.appendChild(c)}ok.onclick=function(){o.remove();if(yes)yes()};b.appendChild(m);b.appendChild(t);o.appendChild(b);document.body.appendChild(o);ok.focus()};
window.confirm=function(msg){if(okFlag){okFlag=false;return true}var f=last;if(f){f.classList.remove('loading');window.mcModal(String(msg),function(){okFlag=true;if(f.requestSubmit)f.requestSubmit();else f.submit()})}return false};
window.alert=function(msg){window.mcModal(String(msg))}})();
(function(){function pad(n){return n<10?'0'+n:''+n}
function conv(root){var re=/(\\d{4})-(\\d{2})-(\\d{2}) (\\d{2}):(\\d{2})(:(\\d{2}))?/g,w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT,null),n,L=[];while(n=w.nextNode()){var p=n.parentNode&&n.parentNode.nodeName;if(p==='SCRIPT'||p==='STYLE'||p==='TEXTAREA'||p==='OPTION')continue;if(re.test(n.nodeValue))L.push(n);re.lastIndex=0}
L.forEach(function(n){n.nodeValue=n.nodeValue.replace(re,function(m,y,mo,d,h,mi,sx,s){var dt=new Date(Date.UTC(+y,+mo-1,+d,+h,+mi,+(s||0)));if(isNaN(dt))return m;return dt.getFullYear()+'-'+pad(dt.getMonth()+1)+'-'+pad(dt.getDate())+' '+pad(dt.getHours())+':'+pad(dt.getMinutes())+(sx?':'+pad(dt.getSeconds()):'')});re.lastIndex=0;if(n.parentNode&&n.parentNode.setAttribute)n.parentNode.setAttribute('title','UTC')})}
window.mcLocalTimes=conv;conv(document.body);
var a=document.querySelector('[data-autorefresh]');if(a)setInterval(function(){var e=document.activeElement;if(document.hidden||document.querySelector('.mo')||(e&&/^(INPUT|SELECT|TEXTAREA)$/.test(e.tagName)))return;location.reload()},30000)})();
function tp(id,b){var i=document.getElementById(id);i.type=i.type==='password'?'text':'password'}`;

function page(ctx, title, body, nav = '') {
  const { i, user, csrf, flash, path, viewAs } = ctx;
  const t = i.t;
  const side = !!(user && nav);
  const other = i.lang === 'ar' ? 'en' : 'ar';
  return `<!doctype html><html lang="${i.lang}" dir="${i.rtl ? 'rtl' : 'ltr'}"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} - ${esc(BRAND)}</title><style>${css}</style></head><body class="${user && user.role !== 'super_admin' ? 'cl' : user ? 'ad' : ''}">
${viewAs ? `<div class="vb"><span>${esc(t('View only'))}: ${esc(viewAs.name)}</span><form id="vx" method="post" action="/view-as/exit" style="display:inline"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="sec">${esc(t('Exit view'))}</button></form></div>` : ''}<header>${user && user.role === 'super_admin' && side ? `<button type="button" class="menubtn sec" aria-label="Menu" onclick="document.body.classList.toggle('nav-open')">${AD.ico('menu', 22)}</button>` : ''}<span class="brand">${esc(BRAND)}</span>${ctx.rt ? `<a class="rtchip" href="/app/network/discovery" title="${esc(t('Router connection'))}"><i style="background:${{ online: '#16a34a', unstable: '#eab308', offline: '#dc2626', none: '#9ca3af' }[ctx.rt.st]}"></i>${esc(t(ctx.rt.label))}${ctx.rt.st === 'none' ? '' : ' &middot; ' + esc(ctx.rt.ago)}</a>` : ''}${side ? '' : nav}<span class="sp"></span>
<a href="/lang/${other}?back=${encodeURIComponent(path || '/')}">${other === 'ar' ? 'العربية' : 'English'}</a>
${user ? `<a href="/account">${esc(user.name)}</a><form class="inline" method="post" action="/logout"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="sec">${t('Logout')}</button></form>` : ''}</header>
${side ? `<div class="shell" style="--dir:${i.rtl ? 'rtl' : 'ltr'}">` : ''}<main>${body}</main>${side ? `<aside class="side" id="side">${nav}</aside></div>` : ''}<script>${js}</script>${viewAs ? `<script>document.querySelectorAll('form:not(#vx) button,form:not(#vx) input[type=submit]').forEach(function(b){b.disabled=true;b.title='View only'})</script>` : ''}${flash ? `<script>mcModal(${JSON.stringify(String(flash.msg)).replace(/</g, '\\u003c')},null,${JSON.stringify(flash.type === 'err' ? '' : flash.type === 'warn' ? 'warn' : 'ok')})</script>` : ''}</body></html>`;
}
const csrfField = (ctx) => `<input type="hidden" name="_csrf" value="${esc(ctx.csrf)}">`;
const infoGrid = (items) => `<div class="info">${items.map(([l, x]) => `<div><small>${esc(l)}</small><strong>${x === undefined || x === null || x === '' ? '-' : x}</strong></div>`).join('')}</div>`;
const badge = (v, t) => `<span class="badge ${esc(v)}">${esc(t(v[0].toUpperCase() + v.slice(1)))}</span>`;
function field(label, name, val = '', opts = {}) {
  const { type = 'text', req = false, ta = false } = opts;
  return `<div><label>${esc(label)}${req ? ' <span style="color:#dc2626;font-weight:700">*</span>' : ''}</label>${ta
    ? `<textarea name="${name}" rows="3">${esc(val)}</textarea>`
    : `<input type="${type}" name="${name}" value="${esc(val)}" ${type === 'number' ? 'step="any"' : ''} ${req ? 'required' : ''} ${type === 'password' ? 'autocomplete="new-password"' : ''}>`}</div>`;
}
function select(label, name, val, options) {
  return `<div><label>${esc(label)}</label><select name="${name}">${options.map(([v, l]) => `<option value="${esc(v)}" ${String(v) === String(val) ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></div>`;
}
function login2fa(ctx, err) {
  const t = ctx.i.t;
  return `<!doctype html><html lang="${ctx.i.lang}" dir="${ctx.i.rtl ? 'rtl' : 'ltr'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(BRAND)}</title><style>${css}</style></head>
<body class="login${ctx.admin ? '' : ' cl'}"><div class="box"><div class="logo">M</div><h2 style="text-align:center;margin:4px 0 18px">${t('Two-factor authentication')}</h2>
<form method="post" action="/login/2fa">${csrfField(ctx)}
<label>${t('Authentication code')}</label><input name="code" required autofocus autocomplete="one-time-code" inputmode="numeric"><button style="width:100%;margin-top:14px">${t('Sign in')}</button></form></div><script>${js}</script>${err ? `<script>mcModal(${JSON.stringify(String(err)).replace(/</g, '\\u003c')},null,'')</script>` : ''}</body></html>`;
}
function login(ctx, err) {
  const t = ctx.i.t;
  const other = ctx.i.lang === 'ar' ? 'en' : 'ar';
  return `<!doctype html><html lang="${ctx.i.lang}" dir="${ctx.i.rtl ? 'rtl' : 'ltr'}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in - ${esc(BRAND)}</title><style>${css}</style></head>
<body class="login${ctx.admin ? '' : ' cl'}"><div class="box"><div class="logo">${esc(BRAND.slice(0, 1).toUpperCase())}</div><h2 style="text-align:center;margin:4px 0 18px">${BRAND === 'MikroCloud' ? t('MikroCloud ISP Manager') : esc(BRAND)}</h2>

<form method="post" action="/login">${csrfField(ctx)}
<label>${t('Email or username')}</label><input name="identifier" required autofocus autocomplete="username">
<label>${t('Password')}</label><div class="pw"><input id="pw" type="password" name="password" required autocomplete="current-password"><button type="button" class="sec" onclick="tp('pw')">${t('Show')}/${t('Hide')}</button></div>
<label style="display:flex;gap:6px;align-items:center"><input type="checkbox" name="remember" value="1" style="width:auto"> ${t('Remember me')}</label>
<p style="margin:14px 0 0"><button style="width:100%">${t('Sign in')}<span class="spin"></span></button></p></form>
<p style="text-align:center;margin-top:14px"><a href="/forgot">${t('Forgot password?')}</a> &nbsp;|&nbsp; <a href="/lang/${other}?back=/login">${other === 'ar' ? 'العربية' : 'English'}</a></p></div><script>${js}</script>${err ? `<script>mcModal(${JSON.stringify(String(err)).replace(/</g, '\\u003c')},null,${JSON.stringify('')})</script>` : ''}</body></html>`;
}
module.exports = { setBrand, getBrand, hostOnly, infoGrid, esc, page, csrfField, badge, field, select, login, login2fa };
