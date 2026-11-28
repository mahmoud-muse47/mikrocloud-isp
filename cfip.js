'use strict';
// Cloudflare published ranges (https://www.cloudflare.com/ips-v4 and ips-v6). The cf-connecting-ip header is trusted only if the peer is one of these.
const net = require('net');
const RANGES = '173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32'.trim().split(/\s+/);
const bl = new net.BlockList();
for (const r of RANGES) { const [a, p] = r.split('/'); bl.addSubnet(a, Number(p), a.includes(':') ? 'ipv6' : 'ipv4'); }
function isCloudflare(ip) {
  if (!ip) return false;
  ip = String(ip).replace(/^::ffff:/i, '');
  const f = net.isIP(ip); if (!f) return false;
  try { return bl.check(ip, f === 6 ? 'ipv6' : 'ipv4'); } catch { return false; }
}
module.exports = { isCloudflare };
