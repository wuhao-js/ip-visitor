'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { shouldRecord } = require('../src/direction');

const localIps = new Set(['10.10.10.5', '::ffff:10.10.10.5', '127.0.0.1']);

test('filter 模式：目标本机且来源外部 → 记录', () => {
  const rec = { srcIp: '8.8.8.8', dstIp: '10.10.10.5' };
  assert.strictEqual(shouldRecord(rec, 'filter', localIps), true);
});

test('filter 模式：服务器主动外访 → 不记录', () => {
  const rec = { srcIp: '10.10.10.5', dstIp: '8.8.8.8' };
  assert.strictEqual(shouldRecord(rec, 'filter', localIps), false);
});

test('本机自访问（回环/同机）→ 不记录', () => {
  assert.strictEqual(shouldRecord({ srcIp: '127.0.0.1', dstIp: '127.0.0.1' }, 'Q', localIps), false);
  assert.strictEqual(shouldRecord({ srcIp: '10.10.10.5', dstIp: '10.10.10.5' }, 'Q', localIps), false);
});

test('Q 模式：内核已过滤，仅剔除自访问', () => {
  assert.strictEqual(shouldRecord({ srcIp: '8.8.8.8', dstIp: '1.1.1.1' }, 'Q', localIps), true);
});

test('无效记录 → 不记录', () => {
  assert.strictEqual(shouldRecord(null, 'Q', localIps), false);
});

test('IPv6 大小写归一', () => {
  assert.strictEqual(shouldRecord({ srcIp: '2001:DB8::9', dstIp: 'fe80::5' }, 'filter', new Set(['fe80::5'])), true);
});

test('组播/广播目标视为入站', () => {
  assert.strictEqual(shouldRecord({ srcIp: '192.168.1.9', dstIp: '224.0.0.251' }, 'filter', new Set()), true);
  assert.strictEqual(shouldRecord({ srcIp: '192.168.1.9', dstIp: '192.168.1.255' }, 'filter', new Set()), true);
  assert.strictEqual(shouldRecord({ srcIp: 'fe80::1', dstIp: 'ff02::fb' }, 'filter', new Set()), true);
  assert.strictEqual(shouldRecord({ srcIp: '10.10.10.5', dstIp: '224.0.0.1' }, 'filter', localIps), false); // 来源本机仍排除
});
