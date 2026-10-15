'use strict';

// 解析 tcpdump -l -nn -tttt -q 的文本输出行（每行一个包）
// 仅识别 tcp / udp / icmp / 其他 IP 协议；ARP、多行续行、截断行返回 null

const HDR = /^(?:(\d{4})-(\d{2})-(\d{2})[ T])?(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?\s+(IP6?)\s+(\S+)\s+>\s+(\S+):\s+(.*)$/;

// tcpdump 会以协议名开头的 IP 层协议（非端口型）
const IP_PROTO_KEYWORDS = new Set([
  'icmp', 'icmp6', 'esp', 'ah', 'gre', 'ospf', 'vrrp', 'sctp', 'ipip', 'ipv6-icmp',
]);

function normalizeV6(host) {
  return host.toLowerCase();
}

// token: '1.2.3.4.80'(ip+port) | '1.2.3.4'(无端口) | 'fe80::1.443'(v6+port) | 'fe80::1'(v6无端口)
function parseHostPort(token) {
  if (!token) return null;
  const isV6 = token.includes(':');
  let host = token;
  let port = 0;
  const dot = token.lastIndexOf('.');
  if (dot !== -1) {
    const tail = token.slice(dot + 1);
    const prefix = token.slice(0, dot);
    if (/^\d{1,5}$/.test(tail)) {
      const p = parseInt(tail, 10);
      if (p <= 65535 && (isV6 ? prefix.includes(':') : prefix.split('.').length === 4)) {
        host = prefix;
        port = p;
      }
    }
  }
  if (isV6) host = normalizeV6(host);
  return { host, port };
}

// now: 无日期行（旧 tcpdump 无 -tttt）使用当天日期
function parseLine(line, { now = Date.now() } = {}) {
  if (!line) return null;
  const text = line.replace(/\r$/, '');
  if (text === '' || /^\s/.test(text)) return null; // 空行 / 嵌套续行
  const m = HDR.exec(text);
  if (!m) return null;
  const [, y, mo, d, hh, mm, ss, frac, _iptok, srcTok, dstTok, body] = m;

  let ms = 0;
  if (frac) ms = parseInt(frac.slice(0, 3).padEnd(3, '0'), 10);
  let ts;
  if (y) {
    ts = new Date(+y, +mo - 1, +d, +hh, +mm, +ss, ms).getTime();
  } else {
    const base = new Date(now);
    ts = new Date(base.getFullYear(), base.getMonth(), base.getDate(), +hh, +mm, +ss, ms).getTime();
  }
  if (!Number.isFinite(ts)) return null;

  const src = parseHostPort(srcTok);
  const dst = parseHostPort(dstTok);
  if (!src || !dst) return null;

  // 协议识别：-q 输出为 "tcp N" / "udp N"；ICMP 为 "ICMP ..."; "Flags [" 为旧格式 TCP
  let proto = null;
  const kwMatch = body.match(/^([A-Za-z0-9_-]+)/);
  const kw = kwMatch ? kwMatch[1].toLowerCase() : '';
  if (kw === 'tcp' || body.startsWith('Flags [')) proto = 'tcp';
  else if (kw === 'udp') proto = 'udp';
  else if (kw === 'icmp6' || kw === 'ipv6-icmp') proto = 'icmp';
  else if (kw === 'icmp') proto = 'icmp';
  else if (IP_PROTO_KEYWORDS.has(kw)) proto = kw;
  else return null; // 应用层解码行（无 -q 的 DNS 等）或无法识别，跳过

  let bytes = 0;
  const qlm = body.match(/^(?:tcp|udp) (\d+)$/); // -q 格式：数字即负载长度
  const lm = qlm ? null : body.match(/length (\d+)/i);
  if (qlm) bytes = parseInt(qlm[1], 10);
  else if (lm) bytes = parseInt(lm[1], 10);

  return { ts, srcIp: src.host, dstIp: dst.host, srcPort: src.port, dstPort: dst.port, proto, bytes };
}

module.exports = { parseLine, parseHostPort };
