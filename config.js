'use strict';
// Environment-driven domain and brand configuration. Nothing here is a hardcoded production value.
//   APP_NAME       temporary product name shown in the UI (can also be changed in the Super Admin System page)
//   APP_URL        public base URL of the platform (informational, used in links shown to admins)
//   ADMIN_DOMAIN   host of the Super Admin portal, e.g. admin.example.com (empty = path-based /admin on any host)
//   CLIENT_DOMAIN  host of the Client portal, e.g. portal.example.com
//   ALLOWED_HOSTS  comma list of any other hostnames that may reach the app (e.g. the Render hostname during migration)
//   SESSION_DOMAIN optional cookie Domain attribute. Leave empty so each portal keeps its own host-only cookies.
//   FORCE_HTTPS    1 = redirect http to https (needs TRUST_PROXY so X-Forwarded-Proto is trusted)
const list = (s) => String(s || '').toLowerCase().split(',').map((x) => x.trim()).filter(Boolean);
const host = (s) => String(s || '').toLowerCase().trim().replace(/^https?:\/\//, '').replace(/[/:].*$/, '');
module.exports = function config(env = process.env) {
  return {
    appName: String(env.APP_NAME || 'MikroCloud').slice(0, 60),
    appUrl: String(env.APP_URL || env.BASE_URL || ''),
    adminDomain: host(env.ADMIN_DOMAIN),
    clientDomain: host(env.CLIENT_DOMAIN),
    allowedHosts: list(env.ALLOWED_HOSTS).map(host),
    sessionDomain: /^[a-z0-9.-]+$/i.test(env.SESSION_DOMAIN || '') ? env.SESSION_DOMAIN : '',
    forceHttps: env.FORCE_HTTPS === '1',
  };
};
module.exports.host = host;
