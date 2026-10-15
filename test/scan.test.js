'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const dbm = require('../src/db');

const TMP = path.join(os.tmpdir(), `ipv-scan-test-${process.pid}.db`);

test('扫描嫌疑检测：窗口内端口数达标才命中', () => {
  dbm.open(TMP);
  const now = Date.now();
  const scanner = [];
  for (let i = 0; i < 15; i++) {
    scanner.push({ ts: now - i * 1000, srcIp: '9.9.9.9', proto: 'tcp', dstPort: 1000 + i, bytes: 0 });
  }
  const normal = [
    { ts: now - 1000, srcIp: '8.8.8.8', proto: 'tcp', dstPort: 443, bytes: 0 },
    { ts: now - 2000, srcIp: '8.8.8.8', proto: 'tcp', dstPort: 443, bytes: 0 },
  ];
  // icmp 端口 0 不计入扫描
  const icmpNoise = [
    { ts: now - 1000, srcIp: '7.7.7.7', proto: 'icmp', dstPort: 0, bytes: 64 },
  ];
  dbm.insertBatch([...scanner, ...normal, ...icmpNoise]);

  const suspects = dbm.findScanSuspects(600000, 15);
  const hit = suspects.find(s => s.ip === '9.9.9.9');
  assert.ok(hit, '扫描者应命中');
  assert.strictEqual(hit.ports, 15);
  assert.ok(!suspects.find(s => s.ip === '8.8.8.8'), '正常客户端不应命中');
  assert.ok(!suspects.find(s => s.ip === '7.7.7.7'), 'icmp 端口0 不计');

  // 阈值提高后不命中
  const strict = dbm.findScanSuspects(600000, 16);
  assert.ok(!strict.find(s => s.ip === '9.9.9.9'));

  // 告警表读写
  dbm.insertAlert(now, 'port_scan', '9.9.9.9', '测试告警');
  const alerts = dbm.getAlerts(10);
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].type, 'port_scan');

  dbm.close();
  fs.rmSync(TMP, { force: true });
  fs.rmSync(TMP + '-wal', { force: true });
  fs.rmSync(TMP + '-shm', { force: true });
});

test('新 IP 判定数据源 getAllKnownIps', () => {
  dbm.open(TMP);
  dbm.insertBatch([{ ts: Date.now(), srcIp: '5.5.5.5', proto: 'tcp', dstPort: 80, bytes: 0 }]);
  assert.ok(dbm.getAllKnownIps().includes('5.5.5.5'));
  dbm.close();
  fs.rmSync(TMP, { force: true });
  fs.rmSync(TMP + '-wal', { force: true });
  fs.rmSync(TMP + '-shm', { force: true });
});
