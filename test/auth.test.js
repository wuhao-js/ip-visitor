'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const { makeSession, verifySession, hashPassword, verifyPassword } = require('../src/auth');

const SECRET = 'test-secret-abc';

test('session：携带用户身份的签发与校验', () => {
  const tk = makeSession(SECRET, 60 * 1000, { user: 'wuhao', role: 'admin' });
  const s = verifySession(SECRET, tk);
  assert.ok(s);
  assert.strictEqual(s.user, 'wuhao');
  assert.strictEqual(s.role, 'admin');
  assert.ok(s.exp > Date.now());

  const v = verifySession(SECRET, makeSession(SECRET, 1000, { user: 'zhang.san', role: 'viewer' }));
  assert.strictEqual(v.user, 'zhang.san');
  assert.strictEqual(v.role, 'viewer');
});

test('session：过期、篡改、旧格式、坏输入一律拒绝', () => {
  assert.strictEqual(verifySession(SECRET, makeSession(SECRET, -1000, { user: 'a' })), null, '过期');
  assert.strictEqual(verifySession(SECRET, makeSession('other-secret', 60000, { user: 'a' })), null, '密钥不符');
  const tk = makeSession(SECRET, 60000, { user: 'a', role: 'viewer' });
  assert.strictEqual(verifySession(SECRET, tk.slice(0, -1) + (tk.endsWith('0') ? '1' : '0')), null, '签名篡改');
  assert.strictEqual(verifySession(SECRET, '123.abc'), null, '旧两段式格式');
  assert.strictEqual(verifySession(SECRET, ''), null);
  assert.strictEqual(verifySession(SECRET, undefined), null);
  assert.strictEqual(verifySession(SECRET, 'x.y.z'), null, '内容非 base64 JSON');
});

test('session：role 非法值一律按 viewer 处理', () => {
  const tk = makeSession(SECRET, 60000, { user: 'a', role: 'superadmin' });
  assert.strictEqual(verifySession(SECRET, tk).role, 'viewer');
});

test('password：scrypt 哈希与校验', () => {
  const stored = hashPassword('S3cret-密码');
  assert.match(stored, /^[0-9a-f]{32}:[0-9a-f]{64}$/, 'salt:hash 十六进制格式');
  assert.ok(!stored.includes('S3cret'), '不落明文');
  assert.strictEqual(verifyPassword('S3cret-密码', stored), true);
  assert.strictEqual(verifyPassword('wrong', stored), false);
  assert.strictEqual(verifyPassword('', stored), false);
  assert.strictEqual(verifyPassword('x', 'not-a-hash'), false);
  assert.strictEqual(verifyPassword('x', undefined), false);
  // 同密码两次哈希 salt 不同
  assert.notStrictEqual(hashPassword('abc'), hashPassword('abc'));
});
