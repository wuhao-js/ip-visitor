'use strict';

// 纯 JS 解析 pcap 文件（libpcap 经典格式）并解码 L2-L4 头，供页面查看报文
// 支持：Ethernet(1) / Linux SLL(113) / raw IP(101) / Linux SLL2(276)

const IPPROTO = { 1: 'icmp', 2: 'igmp', 6: 'tcp', 17: 'udp', 47: 'gre', 58: 'icmp', 89: 'ospf', 132: 'sctp' };
const ICMP_TYPE = {
  0: 'echo reply', 3: 'dest unreachable', 5: 'redirect', 8: 'echo request',
  9: 'router adv', 10: 'router solicitation', 11: 'ttl exceeded', 12: 'param problem',
  13: 'timestamp', 128: 'echo request', 129: 'echo reply', 133: 'rs', 134: 'ra', 135: 'ns', 136: 'na',
};
const TCP_FLAG_BITS = [[1, 'F'], [2, 'S'], [4, 'R'], [8, 'P'], [16, 'A'], [32, 'U']];

function readGlobalHeader(buf) {
  if (buf.length < 24) return null;
  const magic = buf.readUInt32LE(0);
  let le = true, nano = false;
  if (magic === 0xa1b2c3d4) { le = true; }
  else if (magic === 0xd4c3b2a1) { le = false; }
  else if (magic === 0xa1b23c4d) { le = true; nano = true; }
  else if (magic === 0x4d3cb2a1) { le = false; nano = true; }
  else return null;
  const rd = (off) => (le ? buf.readUInt32LE(off) : buf.readUInt32BE(off));
  return { le, nano, linktype: rd(20) };
}

// L2 剥离 → {l3off, protoName}
function stripLinkLayer(linktype, data) {
  if (linktype === 1) { // Ethernet
    if (data.length < 14) return null;
    let et = data.readUInt16BE(12);
    let off = 14;
    while (et === 0x8100 || et === 0x88a8) { // VLAN
      if (data.length < off + 4) return null;
      et = data.readUInt16BE(off + 2);
      off += 4;
    }
    return { l3off: off, etype: et };
  }
  if (linktype === 113) { // Linux SLL
    if (data.length < 16) return null;
    return { l3off: 16, etype: data.readUInt16BE(14) };
  }
  if (linktype === 276) { // Linux SLL2
    if (data.length < 20) return null;
    return { l3off: 20, etype: data.readUInt16BE(0) };
  }
  if (linktype === 101 || linktype === 12 || linktype === 14) { // raw IP
    return { l3off: 0, etype: (data[0] >> 4) === 6 ? 0x86dd : 0x0800 };
  }
  return null;
}

function decodeIPv4(data, off) {
  if (data.length < off + 20) return null;
  const ihl = (data[off] & 0x0f) * 4;
  if (ihl < 20 || data.length < off + ihl) return null;
  const protoNum = data[off + 9];
  const totalLen = data.readUInt16BE(off + 2);
  const src = `${data[off + 12]}.${data[off + 13]}.${data[off + 14]}.${data[off + 15]}`;
  const dst = `${data[off + 16]}.${data[off + 17]}.${data[off + 18]}.${data[off + 19]}`;
  return { ipProto: protoNum, src, dst, l4off: off + ihl, totalLen };
}

const IPV6_EXT = new Set([0, 43, 44, 51, 60, 135]); // hop-by-hop/routing/frag/dst/mobility
function decodeIPv6(data, off) {
  if (data.length < off + 40) return null;
  let p = data[off + 6];
  let cur = off + 40;
  let hops = 0;
  while (IPV6_EXT.has(p) && hops < 8) {
    if (p === 44) { // fragment header 固定 8 字节
      if (data.length < cur + 8) return null;
      p = data[cur];
      cur += 8;
    } else {
      if (data.length < cur + 8) return null;
      const len = (data[cur + 1] + 1) * 8;
      if (data.length < cur + len) return null;
      p = data[cur];
      cur += len;
    }
    hops += 1;
  }
  const src = formatV6(data, off + 8);
  const dst = formatV6(data, off + 24);
  return { ipProto: p, src, dst, l4off: cur, totalLen: data.length - off };
}

function formatV6(data, off) {
  const parts = [];
  for (let i = 0; i < 8; i++) parts.push(data.readUInt16BE(off + i * 2).toString(16));
  // 最长连续零段（>=2 组）压缩为 ::
  let bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  parts.forEach((p, i) => {
    if (p === '0') {
      if (curStart < 0) { curStart = i; curLen = 1; } else { curLen += 1; }
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  });
  if (bestLen >= 2) {
    return parts.slice(0, bestStart).join(':') + '::' + parts.slice(bestStart + bestLen).join(':');
  }
  return parts.join(':');
}

function decodeL4(proto, data, off, ipTotalLen) {
  const avail = Math.max(0, Math.min(data.length, off + (ipTotalLen || 0)) - off) || Math.max(0, data.length - off);
  if (proto === 'tcp') {
    if (data.length < off + 20) return { proto, len: avail };
    const doff = (data[off + 12] >> 4) * 4;
    const srcPort = data.readUInt16BE(off);
    const dstPort = data.readUInt16BE(off + 2);
    const flags = data[off + 13];
    const flagStr = TCP_FLAG_BITS.filter(([bit]) => flags & bit).map(([, ch]) => ch).join('');
    const payLen = avail > doff ? avail - doff : 0;
    return {
      proto, srcPort, dstPort, tcpFlags: flagStr,
      tcpSeq: data.readUInt32BE(off + 4), tcpAck: data.readUInt32BE(off + 8), tcpWin: data.readUInt16BE(off + 14),
      len: payLen, payload: payLen > 0 ? data.subarray(off + doff, off + doff + payLen) : undefined,
    };
  }
  if (proto === 'udp') {
    if (data.length < off + 8) return { proto, len: avail };
    const payLen = avail > 8 ? avail - 8 : 0;
    return { proto, srcPort: data.readUInt16BE(off), dstPort: data.readUInt16BE(off + 2), len: payLen, payload: payLen > 0 ? data.subarray(off + 8, off + 8 + payLen) : undefined };
  }
  if (proto === 'icmp') {
    const t = data[off], c = data[off + 1];
    return { proto, icmpType: t, icmpCode: c, summary: ICMP_TYPE[t] || `type ${t}`, len: avail };
  }
  return { proto, len: avail };
}

// 单包解码：data 为该包完整字节（含链路层）
function decodePacket(linktype, data) {
  try {
    const l2 = stripLinkLayer(linktype, data);
    if (!l2) return { error: `不支持的链路层类型 ${linktype}` };
    let ip;
    if (l2.etype === 0x86dd) ip = decodeIPv6(data, l2.l3off);
    else if (l2.etype === 0x0800) ip = decodeIPv4(data, l2.l3off);
    else return { error: `非 IP 帧 (ethertype 0x${l2.etype.toString(16)})` };
    if (!ip) return { error: 'IP 头截断' };
    const proto = IPPROTO[ip.ipProto] || `proto-${ip.ipProto}`;
    const l4 = decodeL4(proto, data, ip.l4off, ip.totalLen);
    return { src: ip.src, dst: ip.dst, ...l4 };
  } catch (e) {
    return { error: e.message };
  }
}

// 解析整个 pcap 文件 → { linktype, packets: [{no, tsMs, len, data}], truncated }
function parsePcap(buf, { maxPackets = 5000 } = {}) {
  const gh = readGlobalHeader(buf);
  if (!gh) return { error: '不是有效的 pcap 文件（magic 不匹配）' };
  const rd32 = (off) => (gh.le ? buf.readUInt32LE(off) : buf.readUInt32BE(off));
  const packets = [];
  let off = 24;
  let no = 0;
  let truncated = false;
  while (off + 16 <= buf.length && packets.length < maxPackets) {
    const tsSec = rd32(off);
    const tsFrac = rd32(off + 4);
    const inclLen = rd32(off + 8);
    const origLen = rd32(off + 12);
    off += 16;
    if (inclLen > 262144) return { error: `pcap 第 ${no + 1} 包长度异常，文件可能损坏`, linktype: gh.linktype, packets };
    // 抓包被强杀/断流时最后一个包可能只写了一半：丢弃残包而不是整个文件报损坏
    if (off + inclLen > buf.length) { truncated = true; break; }
    const data = buf.subarray(off, off + inclLen);
    const tsMs = tsSec * 1000 + (gh.nano ? Math.round(tsFrac / 1e6) : Math.round(tsFrac / 1e3));
    packets.push({ no: ++no, tsMs, len: origLen, data });
    off += inclLen;
  }
  return { linktype: gh.linktype, packets, truncated };
}

function hexDump(data, maxBytes = 512) {
  const lines = [];
  // maxBytes<=0 表示全量展示
  const end = maxBytes > 0 ? Math.min(data.length, maxBytes) : data.length;
  for (let off = 0; off < end; off += 16) {
    const chunk = data.subarray(off, Math.min(off + 16, end));
    const hex = [...chunk].map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    const ascii = [...chunk].map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.').join('');
    lines.push(`${off.toString(16).padStart(4, '0')}  ${hex}  |${ascii}|`);
  }
  if (data.length > end) lines.push(`… 共 ${data.length} 字节，仅显示前 ${end} 字节`);
  return lines.join('\n');
}

module.exports = { parsePcap, decodePacket, hexDump, formatV6 };
