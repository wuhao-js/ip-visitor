'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { CaptureManager } = require('../src/capture');

function gh(linktype = 1) {
  const b = Buffer.alloc(24);
  b.writeUInt32LE(0xa1b2c3d4, 0);
  b.writeUInt32LE(linktype, 20);
  return b;
}
function pk(d, sec = 1791960000, usec = 100000) {
  const b = Buffer.alloc(16);
  b.writeUInt32LE(sec, 0); b.writeUInt32LE(usec, 4);
  b.writeUInt32LE(d.length, 8); b.writeUInt32LE(d.length, 12);
  return Buffer.concat([b, d]);
}
function eth(ip) {
  const b = Buffer.alloc(14);
  b.writeUInt16BE(0x0800, 12);
  return Buffer.concat([b, ip]);
}
function ip4(proto, l4) {
  const b = Buffer.alloc(20);
  b[0] = 0x45; b.writeUInt16BE(20 + l4.length, 2); b[9] = proto;
  b.set([172, 16, 8, 100], 12); b.set([10, 10, 10, 5], 16);
  return Buffer.concat([b, l4]);
}
function tcpSeg(sport, dport, flags) {
  const b = Buffer.alloc(20);
  b.writeUInt16BE(sport, 0); b.writeUInt16BE(dport, 2);
  b[12] = 0x50; b[13] = flags;
  return b;
}
function udp(sport, dport) {
  const b = Buffer.alloc(8);
  b.writeUInt16BE(sport, 0); b.writeUInt16BE(dport, 2);
  b.writeUInt16BE(8, 4);
  return b;
}

test('getPacketPage：注入合成 pcap 的分页与解码', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipv-cap-'));
  const file = path.join(dir, 't.pcap');
  const pcap = Buffer.concat([
    gh(),
    pk(eth(ip4(6, tcpSeg(40001, 3306, 0x02))), 1791960000, 100000),
    pk(eth(ip4(6, tcpSeg(40001, 3306, 0x12))), 1791960000, 200000),
    pk(eth(ip4(17, udp(5353, 5353))), 1791960001, 300000),
  ]);
  fs.writeFileSync(file, pcap);

  const cm = new CaptureManager({ captureDir: dir });
  cm.captures.set(1, { id: 1, target: 'fake-host', status: 'done', file, size: pcap.length, filter: 'src host 172.16.8.100 and port 3306' });

  const page = cm.getPacketPage(1, 1, 2);
  assert.ok(!page.error, page.error);
  assert.strictEqual(page.total, 3);
  assert.strictEqual(page.matched, 3);
  assert.strictEqual(page.packets.length, 2);
  assert.strictEqual(page.packets[0].src, '172.16.8.100');
  assert.strictEqual(page.packets[0].dstPort, 3306);
  assert.strictEqual(page.packets[0].tcpFlags, 'S');
  assert.strictEqual(page.packets[1].tcpFlags, 'SA');
  // 列表不再携带 hex（hex 走单包详情接口，避免分页响应膨胀）
  assert.strictEqual(page.packets[0].hex, undefined);
  assert.strictEqual(page.target, 'fake-host');

  // 第 2 页只剩 1 条（udp）
  const page2 = cm.getPacketPage(1, 2, 2);
  assert.strictEqual(page2.packets.length, 1);
  assert.strictEqual(page2.packets[0].proto, 'udp');

  // 显示过滤：syn 命中 2 条（S 与 SA 都含 SYN），udp 命中 1 条，端口过滤
  const qSyn = cm.getPacketPage(1, 1, 50, 'syn');
  assert.strictEqual(qSyn.matched, 2);
  const qUdp = cm.getPacketPage(1, 1, 50, 'udp');
  assert.strictEqual(qUdp.matched, 1);
  assert.strictEqual(qUdp.packets[0].proto, 'udp');
  const qPort = cm.getPacketPage(1, 1, 50, 'ip:172.16.8.100 port:5353');
  assert.strictEqual(qPort.matched, 1);
  const qNone = cm.getPacketPage(1, 1, 50, 'ip:1.2.3.4');
  assert.strictEqual(qNone.matched, 0);
  assert.strictEqual(qNone.packets.length, 0);

  // 单包详情：解码字段 + 全量 hex
  const d1 = cm.getPacketDetail(1, 1);
  assert.ok(!d1.error, d1.error);
  assert.strictEqual(d1.no, 1);
  assert.strictEqual(d1.src, '172.16.8.100');
  assert.strictEqual(d1.dstPort, 3306);
  assert.strictEqual(d1.tcpFlags, 'S');
  assert.strictEqual(d1.tcpSeq, 0);
  assert.strictEqual(d1.tcpWin, 0);
  assert.match(d1.hex, /0000  /);
  const d3 = cm.getPacketDetail(1, 3);
  assert.strictEqual(d3.proto, 'udp');
  assert.ok(cm.getPacketDetail(1, 99).error, '不存在的包号应报错');
  assert.strictEqual(cm.getPacketDetail(99, 1), null);

  // 未完成/不存在的 id
  assert.strictEqual(cm.getPacketPage(99), null);
  assert.strictEqual(cm.getPacketPage(2), null);

  fs.rmSync(dir, { recursive: true, force: true });
});

test('analyze：页内分析摘要聚合（协议/TCP标志/来源/端口/对话）', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipv-ana-'));
  const file = path.join(dir, 'a.pcap');
  const pcap = Buffer.concat([
    gh(),
    pk(eth(ip4(6, tcpSeg(40001, 3306, 0x02))), 1791960000, 0),
    pk(eth(ip4(6, tcpSeg(40001, 3306, 0x12))), 1791960001, 0),
    pk(eth(ip4(6, tcpSeg(40002, 443, 0x04))), 1791960002, 0),
    pk(eth(ip4(17, udp(5353, 5353))), 1791960003, 0),
  ]);
  fs.writeFileSync(file, pcap);

  const cm = new CaptureManager({ captureDir: dir });
  cm.captures.set(7, { id: 7, target: 'local', status: 'done', file, size: pcap.length, filter: 'src host 172.16.8.100' });

  const an = cm.analyze(7);
  assert.ok(!an.error, an.error);
  assert.strictEqual(an.total, 4);
  assert.strictEqual(an.srcCount, 1);
  assert.strictEqual(an.protoList[0].k, 'tcp');
  assert.strictEqual(an.protoList[0].c, 3);
  assert.deepStrictEqual(Object.fromEntries(an.flagsList.map(x => [x.k, x.c])), { S: 2, A: 1, R: 1 });
  assert.strictEqual(an.topPorts[0].k, '3306');
  assert.strictEqual(an.topPorts[0].c, 2);
  assert.strictEqual(an.topSrcs[0].k, '172.16.8.100');
  assert.match(an.topConvs[0].k, /172\.16\.8\.100:40001 → 10\.10\.10\.5:3306/);
  assert.strictEqual(an.durationMs, 3000);
  assert.ok(an.pps > 0);
  assert.strictEqual(an.truncated, false);

  // 未完成/不存在 → null
  assert.strictEqual(cm.analyze(88), null);

  fs.rmSync(dir, { recursive: true, force: true });
});
