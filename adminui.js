// Super admin design system. Everything is scoped under body.ad so client pages are untouched.
const P = {
  grid: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  users: 'M16 11a4 4 0 1 0-8 0 4 4 0 0 0 8 0zM4 21a8 8 0 0 1 16 0',
  tag: 'M20 12l-8 8-9-9V3h8zM7.5 7.5h.01',
  card: 'M2 6h20v12H2zM2 10h20',
  cash: 'M3 7h18v10H3zM12 9.5a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
  shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z',
  db: 'M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3zM4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
  cog: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19 12l2-1-2-4-2 1-2-1V5h-4v2l-2 1-2-1-2 4 2 1v2l-2 1 2 4 2-1 2 1v2h4v-2l2-1 2 1 2-4-2-1z',
  plus: 'M12 5v14M5 12h14',
  clock: 'M12 7v5l3 2M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z',
  pause: 'M9 5v14M15 5v14',
  alert: 'M12 4l9 16H3zM12 10v4M12 17h.01',
  check: 'M5 13l4 4L19 7',
  wifi: 'M3 9a14 14 0 0 1 18 0M6 12.5a10 10 0 0 1 12 0M9 16a5 5 0 0 1 6 0M12 19.5h.01',
  menu: 'M4 6h16M4 12h16M4 18h16'
};
const ico = (n, s = 18) => `<svg class="ic" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${P[n] || P.grid}"/></svg>`;

const css = `
body.ad{--p:#2563eb;--bg:#f5f7fb;--tx:#172033;--mut:#64748b;--bd:#e2e8f0;--navy:#14213d;--deep:#0f172a;--ok:#16a34a;--warn:#d97706;--bad:#dc2626;
font-family:"IBM Plex Sans Arabic",Cairo,Inter,system-ui,"Segoe UI",Tahoma,Arial,sans-serif;font-size:14px;line-height:1.55;background:var(--bg);color:var(--tx)}
body.ad .ic{flex:none;vertical-align:middle}
body.ad header{background:var(--deep);padding:0 20px;height:56px;gap:14px;flex-wrap:nowrap;border-bottom:1px solid #1e293b}
body.ad header .brand{display:flex;align-items:center;gap:10px;font-size:15px;letter-spacing:.2px}
body.ad header .brand:before{content:"";width:26px;height:26px;border-radius:7px;background:linear-gradient(135deg,#2563eb,#1d4ed8);display:inline-block}
body.ad header a{font-size:13px;color:#cbd5e1}
body.ad header button{padding:5px 12px;font-size:13px;background:#1e293b;color:#e2e8f0}
body.ad header .menubtn{display:none;background:transparent;padding:4px}
body.ad .shell{max-width:1440px;grid-template-columns:minmax(0,1fr) 232px;gap:20px;margin:18px auto}
body.ad .side{background:var(--navy);border:0;border-radius:12px;padding:10px;top:12px}
body.ad .side a,body.ad .side summary{display:flex;align-items:center;gap:10px;background:none;border:0;box-shadow:none;border-radius:8px;margin:0 0 2px;padding:9px 12px;font-size:14px;font-weight:500;color:#cbd5e1;transition:background .15s,color .15s}
body.ad .side a:hover,body.ad .side summary:hover{background:rgba(255,255,255,.08);color:#fff;border:0}
body.ad .side a:active{transform:none;box-shadow:none}
body.ad .side a.on,body.ad .side a.on:hover{background:var(--p);color:#fff;box-shadow:none}
body.ad .side summary:after{margin-inline-start:auto;float:none;opacity:.6}
body.ad .side details a{margin-inline-start:12px;font-size:13.5px;padding:8px 12px}
body.ad .side .sec-t{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#64748b;padding:10px 12px 4px}
body.ad .card{border-radius:10px;padding:16px 18px;box-shadow:none}
body.ad .card h3{margin:0 0 8px;font-size:16px}
body.ad h1.pt{margin:0;font-size:20px;font-weight:600}
body.ad .ph{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:14px}
body.ad .ph p{margin:2px 0 0;color:var(--mut);font-size:13px}
body.ad table{font-size:13.5px;font-variant-numeric:tabular-nums}
body.ad th{background:#f8fafc;font-size:11.5px;color:var(--mut);padding:10px;white-space:nowrap}
body.ad td{padding:9px 10px;vertical-align:middle}
body.ad td .btn,body.ad td button{padding:4px 9px;font-size:12.5px}
body.ad td .btn.sec,body.ad td button.sec{white-space:nowrap}
body.ad tbody tr:hover td,body.ad table tr:hover td{background:#f8fafc}
body.ad .tbl{padding:0;overflow-x:auto}
body.ad .card.tbl>h3{padding:14px 18px 0}
body.ad input,body.ad select,body.ad textarea{border-radius:7px;padding:8px 10px;min-height:36px;border-color:#cbd5e1}
body.ad input:focus,body.ad select:focus,body.ad textarea:focus,body.ad button:focus-visible,body.ad a:focus-visible{outline:2px solid #93c5fd;outline-offset:1px}
body.ad button,body.ad .btn{border-radius:7px;padding:7px 14px;font-size:13.5px;font-weight:500;transition:background .15s}
body.ad button:hover,body.ad .btn:hover{background:#1d4ed8}
body.ad .btn.sec,body.ad button.sec{background:#fff;color:var(--tx);border:1px solid #cbd5e1}
body.ad .btn.sec:hover,body.ad button.sec:hover{background:#f1f5f9}
body.ad button.bad,body.ad button.danger{background:var(--bad);color:#fff;border:0}
body.ad button.ok{background:var(--ok)}
body.ad .badge{font-size:12px;padding:2px 9px;font-weight:500}
body.ad .badge.pending{background:#fef3c7;color:#92400e}
.kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:14px}
.kpi{display:flex;gap:12px;align-items:center;background:#fff;border:1px solid var(--bd);border-radius:10px;padding:14px;color:var(--tx);transition:border-color .15s,transform .15s}
.kpi:hover{border-color:#93c5fd;transform:translateY(-1px);color:var(--tx)}
.kpi .ki{width:40px;height:40px;border-radius:10px;background:#eff6ff;color:#2563eb;display:flex;align-items:center;justify-content:center;flex:none}
.kpi.w .ki{background:#fffbeb;color:#d97706}.kpi.b .ki{background:#fef2f2;color:#dc2626}.kpi.g .ki{background:#f0fdf4;color:#16a34a}
.kpi b{display:block;font-size:22px;line-height:1.2;font-weight:600}.kpi small{display:block;color:var(--mut);font-size:12.5px}.kpi em{display:block;font-style:normal;color:var(--mut);font-size:11.5px}
.two{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,2fr);gap:12px;margin-bottom:14px}
.two{align-items:start}.two .card{margin:0}
.ft{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.chip{display:inline-flex;gap:6px;align-items:center;padding:4px 11px;border:1px solid #cbd5e1;border-radius:99px;background:#fff;color:var(--tx);font-size:13px}
.chip:hover{background:#f1f5f9}.chip.on{background:var(--p);border-color:var(--p);color:#fff}.chip i{font-style:normal;opacity:.7;font-size:12px}
.qa{display:flex;gap:8px;flex-wrap:wrap}
.qa a{display:inline-flex;gap:7px;align-items:center;padding:7px 12px;border:1px solid var(--bd);background:#fff;border-radius:8px;color:var(--tx);font-size:13px}
.qa a:hover{border-color:#93c5fd;color:var(--p)}
.bars{display:flex;align-items:flex-end;gap:10px;height:150px;padding-top:8px}
.bars div{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;height:100%;min-width:0}
.bars i{display:block;width:100%;max-width:44px;background:#2563eb;border-radius:5px 5px 0 0;min-height:2px}
.bars span{font-size:11px;color:var(--mut);margin-top:5px;white-space:nowrap}.bars b{font-size:11px;font-weight:500;margin-bottom:3px}
.dist{display:grid;gap:9px}.dist .r{display:grid;grid-template-columns:110px 1fr 34px;gap:8px;align-items:center;font-size:13px}
.dist .t{height:8px;background:#e2e8f0;border-radius:99px;overflow:hidden}.dist .t i{display:block;height:100%;background:#2563eb}
.tool{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.tool input,.tool select{width:auto;min-width:150px}.tool .grow{flex:1;min-width:200px}
.pgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:12px}
.pcard{background:#fff;border:1px solid var(--bd);border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:10px}
.pcard.rec{border-color:#2563eb;box-shadow:0 0 0 1px #2563eb}.pcard.off{opacity:.75}
.pcard h3{margin:0;font-size:16px}.pcard .pr{font-size:24px;font-weight:600}.pcard .pr small{font-size:12px;color:var(--mut);font-weight:400}
.pcard ul{list-style:none;margin:0;padding:0;display:grid;gap:5px;font-size:13px}.pcard li{display:flex;justify-content:space-between;border-bottom:1px dashed var(--bd);padding-bottom:4px}
.pcard li span{color:var(--mut)}.pcard .ft2{margin-top:auto;display:flex;justify-content:space-between;align-items:center}
.sum{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:14px}
.sum div{background:#fff;border:1px solid var(--bd);border-radius:10px;padding:12px 14px}.sum small{color:var(--mut);display:block;font-size:12.5px}.sum b{font-size:20px;font-weight:600}
.pager a,.pager span{padding:4px 10px;border:1px solid #cbd5e1;border-radius:6px;background:#fff;color:var(--tx)}.pager span{background:#f1f5f9;color:var(--mut)}
.empty{padding:26px;text-align:center;color:var(--mut)}
@media(max-width:1100px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}.two{grid-template-columns:1fr}}
@media(max-width:800px){body.ad .shell{grid-template-columns:1fr;margin:10px auto}body.ad header .menubtn{display:inline-flex}
body.ad .side{display:none;position:fixed;inset:56px 0 0 auto;width:min(280px,86vw);z-index:60;border-radius:0;overflow:auto;top:56px}
body.ad.nav-open .side{display:block}.kpis{grid-template-columns:1fr 1fr}.kpi{padding:10px}.kpi b{font-size:18px}}
@media(max-width:480px){.kpis{grid-template-columns:1fr}}
`;

const ACTIONS = {
  login: 'Signed in', logout: 'Signed out', company_created: 'Client created', company_updated: 'Client updated', company_deleted: 'Client deleted',
  company_suspended: 'Client suspended', company_activated: 'Client activated', company_exported: 'Client data exported', company_settings_updated: 'Client settings updated',
  subscription_extended: 'Subscription extended', password_changed: 'Password changed', password_reset_requested: 'Password reset requested',
  password_reset_link_issued: 'Reset link issued', password_reset_completed: 'Password reset completed', password_set_by_admin: 'Password set by admin',
  password_change_failed: 'Password change failed', logout_other_sessions: 'Other sessions signed out', customer_created: 'Subscriber added',
  customer_updated: 'Subscriber updated', customer_deleted: 'Subscriber deleted', customers_exported: 'Subscribers exported', employee_created: 'Employee added',
  employee_deleted: 'Employee deleted', employee_updated: 'Employee updated', limit_blocked: 'Limit reached', view_as_client: 'Viewed as client'
};
const actionLabel = (a, t) => (ACTIONS[a] ? t(ACTIONS[a]) : t(String(a || '')));

function bars(rows, fmt) {
  const max = Math.max(1, ...rows.map((r) => r[1]));
  return `<div class="bars">${rows.map(([l, v]) => `<div title="${l}: ${fmt ? fmt(v) : v}"><b>${v ? (fmt ? fmt(v) : v) : ''}</b><i style="height:${Math.round((v / max) * 100)}%"></i><span>${l}</span></div>`).join('')}</div>`;
}
function pager(base, page, pages, t) {
  if (pages <= 1) return '';
  const u = (p) => `${base}${base.includes('?') ? '&' : '?'}page=${p}`;
  return `<div class="pager" style="display:flex;gap:8px;align-items:center;padding:12px 18px">${page > 1 ? `<a href="${u(page - 1)}">${t('Previous')}</a>` : ''}<span>${page} / ${pages}</span>${page < pages ? `<a href="${u(page + 1)}">${t('Next')}</a>` : ''}</div>`;
}
module.exports = { ico, css, actionLabel, bars, pager };
