'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { parseLine, parseHostPort } = require('../src/parser');

const NOW = new Date(2026, 9, 14, 12, 0, 0).getTime();

test('IPv4 TCP 带 -q 输出', () => {
  const r = parseLine('2026-10-14 09:00:01.123456 IP 192.168.1.23.52114 > 10.10.10.5.22: tcp 0');
  assert.ok(r);
  assert.strictEqual(r.ts, new Date(2026, 9, 14, 9, 0, 1, 123).getTime());
  assert.strictEqual(r.srcIp, '192.168.1.23');
  assert.strictEqual(r.dstIp, '10.10.10.5');
  assert.strictEqual(r.srcPort, 52114);
  assert.strictEqual(r.dstPort, 22);
  assert.strictEqual(r.proto, 'tcp');
  assert.strictEqual(r.bytes, 0);
});

test('旧格式 TCP（Flags）', () => {
  const r = parseLine('2026-10-14 10:00:00.000000 IP 1.2.3.4.12345 > 5.6.7.8.443: Flags [P.], seq 1:517, ack 2, win 64240, length 516');
  assert.ok(r);
  assert.strictEqual(r.proto, 'tcp');
  assert.strictEqual(r.dstPort, 443);
  assert.strictEqual(r.bytes, 516);
});

test('UDP', () => {
  const r = parseLine('2026-10-14 09:00:10.100000 IP 192.168.50.7.5353 > 10.10.10.5.5353: udp 100');
  assert.ok(r);
  assert.strictEqual(r.proto, 'udp');
  assert.strictEqual(r.dstPort, 5353);
  assert.strictEqual(r.bytes, 100);
});

test('ICMP 无端口', () => {
  const r = parseLine('2026-10-14 09:00:12.000000 IP 8.8.8.8 > 10.10.10.5: ICMP echo reply, id 5, seq 1, length 64');
  assert.ok(r);
  assert.strictEqual(r.srcIp, '8.8.8.8');
  assert.strictEqual(r.dstIp, '10.10.10.5');
  assert.strictEqual(r.proto, 'icmp');
  assert.strictEqual(r.dstPort, 0);
  assert.strictEqual(r.srcPort, 0);
  assert.strictEqual(r.bytes, 64);
});

test('IPv6 TCP 带端口', () => {
  const r = parseLine('2026-10-14 09:00:18.000000 IP6 2001:DB8::5.60100 > 2001:DB8::1.80: tcp 512');
  assert.ok(r);
  assert.strictEqual(r.srcIp, '2001:db8::5');
  assert.strictEqual(r.dstIp, '2001:db8::1');
  assert.strictEqual(r.dstPort, 80);
  assert.strictEqual(r.proto, 'tcp');
  assert.strictEqual(r.bytes, 512);
});

test('IPv6 UDP 多播目标', () => {
  const r = parseLine('2026-10-14 09:00:15.000000 IP6 fe80::a1.546 > ff02::1.2: udp 200');
  assert.ok(r);
  assert.strictEqual(r.srcIp, 'fe80::a1');
  assert.strictEqual(r.dstIp, 'ff02::1');
  assert.strictEqual(r.dstPort, 2);
  assert.strictEqual(r.proto, 'udp');
});

test('IPv6 ICMP6 归类为 icmp', () => {
  const r = parseLine('2026-10-14 09:00:16.000000 IP6 fe80::1 > ff02::2: ICMP6 router solicitation, length 16');
  assert.ok(r);
  assert.strictEqual(r.proto, 'icmp');
  assert.strictEqual(r.dstPort, 0);
  assert.strictEqual(r.bytes, 16);
});

test('无日期行使用当天', () => {
  const r = parseLine('09:00:01.123456 IP 1.2.3.4.1000 > 5.6.7.8.80: tcp 10');
  assert.ok(r);
  const d = new Date(r.ts);
  const base = new Date(NOW);
  assert.strictEqual(d.getFullYear(), base.getFullYear());
  assert.strictEqual(d.getHours(), 9);
});

test('ARP / 续行 / 截断 / 应用层解码行 跳过', () => {
  assert.strictEqual(parseLine('2026-10-14 09:00:30.000000 ARP, Request who-has 10.0.0.1 tell 10.0.0.5, length 46'), null);
  assert.strictEqual(parseLine('    0x0000:  4500 004c 1234 4000 4011 7c61 0a0a 0a05'), null);
  assert.strictEqual(parseLine('2026-10-14 09:00:35.000000 IP 172.16.9.9.4444 > 10.10.10.5.8080: [|tcp]'), null);
  assert.strictEqual(parseLine('2026-10-14 09:00:40.000000 IP 1.2.3.4.53 > 5.6.7.8.55555: 40411+ [1au] A? example.com. (42)'), null);
  assert.strictEqual(parseLine(''), null);
  assert.strictEqual(parseLine(null), null);
});

test('其他 IP 协议保留原始名', () => {
  const r = parseLine('2026-10-14 09:00:50.000000 IP 1.2.3.4 > 5.6.7.8: ESP(spi=0x12345678,seq=0x1), length 100');
  assert.ok(r);
  assert.strictEqual(r.proto, 'esp');
  assert.strictEqual(r.dstPort, 0);
});

test('parseHostPort 边界', () => {
  assert.deepStrictEqual(parseHostPort('1.2.3.4.80'), { host: '1.2.3.4', port: 80 });
  assert.deepStrictEqual(parseHostPort('1.2.3.4'), { host: '1.2.3.4', port: 0 });
  assert.deepStrictEqual(parseHostPort('fe80::1.443'), { host: 'fe80::1', port: 443 });
  assert.deepStrictEqual(parseHostPort('fe80::1'), { host: 'fe80::1', port: 0 });
});
