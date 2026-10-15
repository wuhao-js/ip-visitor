'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { parsePcap, decodePacket, hexDump, formatV6 } = require('../src/pcap');

// ---- 构造工具 ----
function pcapGlobalHeader(linktype = 1, le = true) {
  const b = Buffer.alloc(24);
  b.writeUInt32LE(le ? 0xa1b2c3d4 : 0xd4c3b2a1, 0);
  b.writeUInt32LE(2, 4); b.writeUInt32LE(0, 8);
  b.writeUInt32LE(0, 12); b.writeUInt32LE(0, 16);
  if (le) b.writeUInt32LE(linktype, 20); else b.writeUInt32BE(linktype, 20);
  return b;
}
function pcapPacket(data, tsSec = 1791960000, tsUsec = 123456, le = true) {
  const b = Buffer.alloc(16);
  const wr = (off, v) => { if (le) b.writeUInt32LE(v, off); else b.writeUInt32BE(v, off); };
  wr(0, tsSec); wr(4, tsUsec); wr(8, data.length); wr(12, data.length);
  return Buffer.concat([b, data]);
}
function ethFrame(payload, etype = 0x0800) {
  const b = Buffer.alloc(14);
  b.writeUInt16BE(etype, 12);
  return Buffer.concat([b, payload]);
}
function ipv4Packet(proto, l4, src = [192, 168, 1, 23], dst = [10, 10, 10, 5]) {
  const b = Buffer.alloc(20);
  b[0] = 0x45;
  b.writeUInt16BE(20 + l4.length, 2);
  b[8] = 64; b[9] = proto;
  b.set(src, 12); b.set(dst, 16);
  return Buffer.concat([b, l4]);
}
function tcpSegment(sport = 52114, dport = 22, flags = 0x02, payload = Buffer.alloc(0), seq = 0, ack = 0, win = 0) {
  const b = Buffer.alloc(20);
  b.writeUInt16BE(sport, 0); b.writeUInt16BE(dport, 2);
  b.writeUInt32BE(seq, 4); b.writeUInt32BE(ack, 8);
  b[12] = 5 << 4; b[13] = flags;
  b.writeUInt16BE(win, 14);
  return Buffer.concat([b, payload]);
}
function udpDatagram(sport = 5353, dport = 5353, payload = Buffer.alloc(4)) {
  const b = Buffer.alloc(8);
  b.writeUInt16BE(sport, 0); b.writeUInt16BE(dport, 2);
  b.writeUInt16BE(8 + payload.length, 4);
  return Buffer.concat([b, payload]);
}
function icmpEcho() {
  const b = Buffer.alloc(8);
  b[0] = 8; b[1] = 0;
  return Buffer.concat([b, Buffer.from([1, 0, 0, 0, 0, 0, 0, 0])]);
}
function sll2Frame(etype, payload) {
  const b = Buffer.alloc(20);
  b.writeUInt16BE(etype, 0);
  return Buffer.concat([b, payload]);
}

test('pcap: Ethernet + IPv4 TCP 解码', () => {
  const frame = ethFrame(ipv4Packet(6, tcpSegment(52114, 22, 0x18, Buffer.from([1, 2, 3, 4]))));
  const buf = Buffer.concat([pcapGlobalHeader(1), pcapPacket(frame)]);
  const r = parsePcap(buf);
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.linktype, 1);
  assert.strictEqual(r.packets.length, 1);
  const d = decodePacket(1, r.packets[0].data);
  assert.strictEqual(d.src, '192.168.1.23');
  assert.strictEqual(d.dst, '10.10.10.5');
  assert.strictEqual(d.proto, 'tcp');
  assert.strictEqual(d.srcPort, 52114);
  assert.strictEqual(d.dstPort, 22);
  assert.strictEqual(d.tcpFlags, 'PA');
  assert.strictEqual(d.len, 4);
  assert.deepStrictEqual([...d.payload], [1, 2, 3, 4], 'TCP 应用层载荷字节');
  assert.strictEqual(r.packets[0].tsMs, 1791960000123);
});

test('pcap: TCP SEQ/ACK/窗口 解码', () => {
  const seg = tcpSegment(52114, 22, 0x12, Buffer.alloc(0), 0x11223344, 0x55667788, 8192);
  const d = decodePacket(1, ethFrame(ipv4Packet(6, seg)));
  assert.strictEqual(d.tcpFlags, 'SA');
  assert.strictEqual(d.tcpSeq, 0x11223344);
  assert.strictEqual(d.tcpAck, 0x55667788);
  assert.strictEqual(d.tcpWin, 8192);
});

test('pcap: SLL2 (tcpdump -i any 新格式) + UDP', () => {
  const frame = sll2Frame(0x0800, ipv4Packet(17, udpDatagram(40000, 53, Buffer.alloc(12))));
  const buf = Buffer.concat([pcapGlobalHeader(276), pcapPacket(frame)]);
  const r = parsePcap(buf);
  assert.ok(!r.error);
  const d = decodePacket(276, r.packets[0].data);
  assert.strictEqual(d.proto, 'udp');
  assert.strictEqual(d.dstPort, 53);
  assert.strictEqual(d.len, 12);
});

test('pcap: raw IP 链路层 + ICMP', () => {
  const frame = ipv4Packet(1, icmpEcho());
  const buf = Buffer.concat([pcapGlobalHeader(101), pcapPacket(frame)]);
  parsePcap(buf);
  const d = decodePacket(101, frame);
  assert.strictEqual(d.proto, 'icmp');
  assert.strictEqual(d.summary, 'echo request');
  assert.strictEqual(d.dstPort, undefined);
});

test('pcap: IPv6 TCP 与 v6 地址格式化', () => {
  const b = Buffer.alloc(40);
  b[0] = 0x60;
  b.writeUInt16BE(20, 4);
  b[6] = 6; // next header tcp
  b[7] = 64;
  // src 2001:db8::5 dst 2001:db8::1
  b.writeUInt16BE(0x2001, 8); b.writeUInt16BE(0x0db8, 10); b.writeUInt16BE(5, 22);
  b.writeUInt16BE(0x2001, 24); b.writeUInt16BE(0x0db8, 26); b.writeUInt16BE(1, 38);
  const ip6 = Buffer.concat([b, tcpSegment(60100, 80, 0x02)]);
  assert.strictEqual(formatV6(ip6, 8), '2001:db8::5');
  assert.strictEqual(formatV6(ip6, 24), '2001:db8::1');
  const d = decodePacket(1, ethFrame(ip6, 0x86dd));
  assert.strictEqual(d.proto, 'tcp');
  assert.strictEqual(d.src, '2001:db8::5');
  assert.strictEqual(d.dstPort, 80);
});

test('pcap: 大端文件与多包', () => {
  const f1 = ethFrame(ipv4Packet(6, tcpSegment()));
  const f2 = ethFrame(ipv4Packet(1, icmpEcho()));
  const buf = Buffer.concat([
    pcapGlobalHeader(1, false),
    pcapPacket(f1, 1791960000, 1, false),
    pcapPacket(f2, 1791960001, 2, false),
  ]);
  const r = parsePcap(buf);
  assert.ok(!r.error);
  assert.strictEqual(r.packets.length, 2);
  const d2 = decodePacket(1, r.packets[1].data);
  assert.strictEqual(d2.proto, 'icmp');
});

test('pcap: 非法 magic 与损坏长度', () => {
  assert.ok(parsePcap(Buffer.alloc(100)).error);
  const bad = Buffer.concat([pcapGlobalHeader(1), pcapPacket(Buffer.alloc(10))]);
  bad.writeUInt32LE(999999, 24 + 8); // inclLen 超界
  const r = parsePcap(bad);
  assert.ok(r.error);
});

test('pcap: 尾部截断容错（抓包被强杀时最后一个包只写了一半）', () => {
  const good = ethFrame(ipv4Packet(6, tcpSegment(40001, 3306, 0x02)));
  const half = ethFrame(ipv4Packet(6, tcpSegment(40001, 443, 0x02)));
  const full = Buffer.concat([pcapGlobalHeader(1), pcapPacket(good), pcapPacket(half)]);
  // 模拟断流：截掉最后一个包的最后 5 个字节
  const truncated = full.subarray(0, full.length - 5);
  const r = parsePcap(truncated);
  assert.ok(!r.error, r.error);
  assert.strictEqual(r.truncated, true);
  assert.strictEqual(r.packets.length, 1, '残包被丢弃，完整包保留');
  const d = decodePacket(1, r.packets[0].data);
  assert.strictEqual(d.dstPort, 3306);
  // 完整文件不标记截断
  const r2 = parsePcap(full);
  assert.strictEqual(r2.truncated, false);
  assert.strictEqual(r2.packets.length, 2);
});

test('pcap: hexDump 输出格式', () => {
  const out = hexDump(Buffer.from([0x47, 0x45, 0x54, 0x20, 0x2f, 0x01, 0x02]));
  assert.match(out, /0000  47 45 54 20 2f 01 02/);
  assert.match(out, /\|GET \/\.\.\|/);
  const big = hexDump(Buffer.alloc(600));
  assert.match(big, /共 600 字节/);
});
