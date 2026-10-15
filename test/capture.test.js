'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { validIp, buildBpf, CaptureManager, validateRemoteHost, decodeAppPayload, matchPktFilter } = require('../src/capture');

test('validIp 校验（防 BPF 注入）', () => {
  assert.strictEqual(validIp('192.168.1.5'), true);
  assert.strictEqual(validIp('fe80::1'), true);
  assert.strictEqual(validIp('2001:DB8::1'), true);
  assert.strictEqual(validIp('256.1.1.1'), false, 'IPv4 八位组超界');
  assert.strictEqual(validIp('1.2.3'), false);
  assert.strictEqual(validIp('foo'), false);
  assert.strictEqual(validIp('1.2.3.4 or host x'), false, '带空格的注入串');
  assert.strictEqual(validIp('1.2.3.4;rm'), false, '带分号的注入串');
  assert.strictEqual(validIp(''), false);
  assert.strictEqual(validIp(undefined), false);
});

test('buildBpf 组合（IP 双向匹配）', () => {
  assert.strictEqual(buildBpf({ ip: '1.2.3.4', port: 3306, proto: 'tcp' }), 'host 1.2.3.4 and port 3306 and tcp');
  assert.strictEqual(buildBpf({ ip: '1.2.3.4' }), 'host 1.2.3.4');
  assert.strictEqual(buildBpf({ proto: 'icmp' }), 'icmp or icmp6');
  assert.strictEqual(buildBpf({}), '');
});

test('远程主机缺 password/keyFile 时给出明确报错', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipv-cap2-'));
  const cm = new CaptureManager({ captureDir: dir, remoteHosts: [{ name: 'h1', host: '10.0.0.9', user: 'root' }] });
  assert.throws(
    () => cm.start({ target: 'h1', port: 3306, seconds: 10 }),
    /未配置 password 或 keyFile/
  );
  // 未配置的主机名仍报未知
  assert.throws(
    () => cm.start({ target: 'nope', port: 3306, seconds: 10 }),
    /未配置的远程主机/
  );
  fs.rmSync(dir, { recursive: true, force: true });
});

test('spawnRemote 密码认证返回 child 风格接口（连接失败走 error）', async () => {
  const cm = new CaptureManager({ remoteHosts: [{ name: 'h2', host: '127.0.0.1', port: 1, user: 'root', password: 'x' }] });
  const host = cm.findHost('h2');
  const child = cm.spawnRemote(host, 'port 3306');
  assert.ok(child.stdout && typeof child.stdout.pipe === 'function', 'stdout 即刻可用');
  assert.ok(typeof child.kill === 'function');
  const evt = await new Promise((resolve) => {
    child.on('error', (e) => resolve({ type: 'error', e }));
    child.on('exit', (code) => resolve({ type: 'exit', code }));
    setTimeout(() => resolve({ type: 'timeout' }), 15000);
  });
  assert.strictEqual(evt.type, 'error', `预期 ECONNREFUSED，实际 ${JSON.stringify(evt)}`);
  assert.match(evt.e.message, /connect|refused|ECONNREFUSED/i);
});

test('validateRemoteHost：页面管理主机的校验与密码保留', () => {
  // 正常新增
  const e1 = validateRemoteHost({ name: 'web-1', host: '10.0.0.11', port: '22', user: 'root', password: 'p1' });
  assert.strictEqual(e1.password, 'p1');
  assert.strictEqual(e1.port, 22);
  // 名称重复
  assert.throws(() => validateRemoteHost({ name: 'web-1', host: '10.0.0.12', user: 'root', password: 'p' }, { names: ['web-1'] }), /已存在/);
  // 名称含空格/特殊字符
  assert.throws(() => validateRemoteHost({ name: 'a b', host: '10.0.0.1', user: 'root', password: 'p' }), /名称/);
  // 主机非法
  assert.throws(() => validateRemoteHost({ name: 'h', host: 'a b c', user: 'root', password: 'p' }), /主机/);
  // 新增时密码与密钥都没有
  assert.throws(() => validateRemoteHost({ name: 'h', host: '10.0.0.1', user: 'root' }), /至少配一项/);
  // 编辑留空密码 → 保留原密码
  const existing = { name: 'h', host: '10.0.0.1', port: 22, user: 'root', password: 'old' };
  const e2 = validateRemoteHost({ name: 'h', host: '10.0.0.1', port: 22, user: 'root', password: '' }, { existing, names: ['h'] });
  assert.strictEqual(e2.password, 'old', '编辑时密码留空应保留原值');
  // 编辑时改名冲突检测
  assert.throws(() => validateRemoteHost({ name: 'other', host: '10.0.0.1', user: 'root' }, { existing, names: ['h', 'other'] }), /已存在/);
});

test('decodeAppPayload：JSON/文本直接解析，二进制返回 null', () => {
  assert.deepStrictEqual(decodeAppPayload(Buffer.from('{"a":1,"b":"你好"}')), { kind: 'json', text: '{\n  "a": 1,\n  "b": "你好"\n}' });
  assert.strictEqual(decodeAppPayload(Buffer.from('[1,2,3]')).kind, 'json');
  const http = 'GET /api/x HTTP/1.1\r\nHost: 10.0.0.5\r\n\r\n';
  const t = decodeAppPayload(Buffer.from(http));
  assert.strictEqual(t.kind, 'text');
  assert.ok(t.text.startsWith('GET /api/x'));
  assert.strictEqual(decodeAppPayload(Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0x80])), null, '二进制走 hex');
  assert.strictEqual(decodeAppPayload(Buffer.alloc(0)), null);
  assert.strictEqual(decodeAppPayload(undefined), null);
  // 非法 JSON 开头像 JSON 但解析失败 → 按文本
  assert.strictEqual(decodeAppPayload(Buffer.from('{not json}')).kind, 'text');
});

test('matchPktFilter：显示过滤 token 组合（AND 语义）', () => {
  const pkt = {
    src: '198.51.100.77', dst: '198.51.100.99', proto: 'tcp',
    srcPort: 45417, dstPort: 16002, tcpFlags: 'PA', summary: '',
    payloadLen: 128, payloadKind: 'json', payloadText: '{"user":"wuhao"}',
  };
  const syn = { src: '1.2.3.4', dst: '198.51.100.99', proto: 'tcp', srcPort: 5000, dstPort: 443, tcpFlags: 'S', summary: '', payloadLen: 0, payloadKind: '', payloadText: '' };
  const icmp = { src: '1.2.3.4', dst: '198.51.100.99', proto: 'icmp', srcPort: 0, dstPort: 0, tcpFlags: '', summary: 'echo request', payloadLen: 0, payloadKind: '', payloadText: '' };

  assert.strictEqual(matchPktFilter(pkt, ''), true, '空过滤全匹配');
  assert.strictEqual(matchPktFilter(pkt, 'ip:198.51.100.77'), true, 'src 命中');
  assert.strictEqual(matchPktFilter(pkt, 'ip:198.51.100.99'), true, 'dst 命中');
  assert.strictEqual(matchPktFilter(pkt, 'ip:1.2.3.4'), false);
  assert.strictEqual(matchPktFilter(pkt, 'port:16002'), true);
  assert.strictEqual(matchPktFilter(pkt, 'port:45417'), true, 'srcPort 也参与');
  assert.strictEqual(matchPktFilter(pkt, 'tcp'), true);
  assert.strictEqual(matchPktFilter(pkt, 'psh'), true);
  assert.strictEqual(matchPktFilter(pkt, 'syn'), false, 'PA 不含 SYN');
  assert.strictEqual(matchPktFilter(syn, 'syn'), true);
  assert.strictEqual(matchPktFilter(icmp, 'icmp'), true);
  assert.strictEqual(matchPktFilter(icmp, 'tcp'), false);
  assert.strictEqual(matchPktFilter(pkt, 'has:payload'), true);
  assert.strictEqual(matchPktFilter(syn, 'has:payload'), false);
  assert.strictEqual(matchPktFilter(pkt, 'json'), true);
  assert.strictEqual(matchPktFilter(pkt, 'text'), false);
  assert.strictEqual(matchPktFilter(pkt, 'text:wuhao'), true);
  assert.strictEqual(matchPktFilter(pkt, 'text:nobody'), false);
  assert.strictEqual(matchPktFilter(pkt, '198.51'), true, '裸词包含匹配');
  assert.strictEqual(matchPktFilter(icmp, 'echo'), true, '裸词命中 summary');
  // AND 组合
  assert.strictEqual(matchPktFilter(pkt, 'ip:198.51.100.77 port:16002 json'), true);
  assert.strictEqual(matchPktFilter(pkt, 'ip:198.51.100.77 port:16002 syn'), false);
  // IPv6 值含冒号也能匹配
  const v6 = { src: 'fe80::1', dst: '2001:db8::5', proto: 'udp', srcPort: 5353, dstPort: 5353, tcpFlags: '', summary: '', payloadLen: 0, payloadKind: '', payloadText: '' };
  assert.strictEqual(matchPktFilter(v6, 'ip:2001:db8::5'), true);
  assert.strictEqual(matchPktFilter(pkt, 'foo:bar'), false, '未知 key:value 不匹配');
});
