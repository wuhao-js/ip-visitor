'use strict';

const os = require('os');

// 收集本机所有 IP（含回环），用于入站方向判定
function buildLocalIps() {
  const set = new Set();
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const info of ifaces[name] || []) {
      if (info.family === 'IPv4' || info.family === 'IPv6') {
        set.add(info.address.toLowerCase());
        if (info.family === 'IPv4') {
          // IPv4-mapped IPv6 形式也视为本机
          set.add('::ffff:' + info.address);
        }
      }
    }
  }
  return set;
}

// 组播/广播目标视为入站可达（mDNS/SSDP/DHCP 等能反映来访客户端）
function isMulticastDst(ip) {
  if (ip.includes(':')) return /^ff[0-9a-f]{2}:/.test(ip); // ff00::/8
  const parts = ip.split('.');
  const first = Number(parts[0]);
  return Number(parts[3]) === 255 || (first >= 224 && first <= 239);
}

// mode: 'Q' = 内核级 -Q in 已过滤入站（仍剔除自身互访）
//       'filter' = 解析层判定：目标为本机(或组播) 且 来源非本机
function shouldRecord(rec, mode, localIps) {
  if (!rec) return false;
  if (rec.srcIp === rec.dstIp) return false; // 本机自访问（回环）
  if (mode === 'Q') return true;
  const srcLocal = localIps.has(rec.srcIp.toLowerCase());
  const dstLocal = localIps.has(rec.dstIp.toLowerCase()) || isMulticastDst(rec.dstIp);
  return dstLocal && !srcLocal;
}

module.exports = { buildLocalIps, shouldRecord, isMulticastDst };
