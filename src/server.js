'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const express = require('express');
const { loadConfig } = require('./config');
const db = require('./db');
const { Collector } = require('./collector');
const { AlertManager } = require('./alerts');
const { CaptureManager, validateRemoteHost } = require('./capture');
const {
  COOKIE_NAME, makeSession, verifySession, parseCookies, cookieHeader, LoginThrottle, hashPassword, verifyPassword,
} = require('./auth');

// ---- 命令行参数 ----
function parseArgv(argv) {
  const out = { config: 'config.json' };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--config') out.config = argv[++i];
    else if (a === '--replay') out.replay = argv[++i];
    else if (a === '--loop') out.loop = true;
    else if (a === '--port') out.port = Number(argv[++i]);
    else if (a === '--host') out.host = argv[++i];
    else if (a === '--iface') out.iface = argv[++i];
    else if (a === '--force-no-q') out.forceNoQ = true;
    else if (a === '--no-auth') out.noAuth = true;
    else if (a === '--help') out.help = true;
  }
  return out;
}

const argv = parseArgv(process.argv);

// 打包为单文件 exe（pkg）时，把工作目录切到数据目录：
// 桌面版由 Electron 壳通过 LAILU_HOME 指定（%APPDATA%，安装版对 Program Files 无写权限），
// 未设置时落在 exe 旁边（绿色版整目录拷贝即迁移）
if (process.pkg) process.chdir(process.env.LAILU_HOME || path.dirname(process.execPath));
if (argv.help) {
  console.log(`用法: node src/server.js [选项]
  --config <file>    配置文件路径（默认 config.json）
  --replay <file>    回放 tcpdump 文本样本（代替实时抓包，用于本机验证）
  --loop             回放模式循环执行
  --port <n>         覆盖监听端口
  --host <addr>      覆盖监听地址（默认 0.0.0.0；桌面模式用 127.0.0.1 仅本机访问）
  --iface <name>     覆盖抓包网卡（默认 any）
  --force-no-q       不使用 -Q in，改按本机 IP 过滤入站
  --no-auth          免登录模式（桌面版内置；所有请求按管理员放行）`);
  process.exit(0);
}

const config = loadConfig(argv.config);
if (argv.port) config.port = argv.port;
if (argv.host) config.listenHost = argv.host;
if (argv.iface) config.iface = argv.iface;
if (argv.replay) config.replay = argv.replay;
if (argv.loop) config.loop = true;
if (argv.forceNoQ) config.forceNoQ = true;
if (argv.noAuth) config.noAuth = true;

const store = db.open(config.dbFile);
console.log(`[db] SQLite 已打开: ${config.dbFile} (driver=${db.driverName})`);

// 多用户引导：users 表为空时，把 config.password 迁移为管理员账号 admin（哈希存储）
if (db.countUsers() === 0) {
  db.insertUser('admin', hashPassword(config.password), 'admin');
  console.log('[auth] 已创建管理员账号 admin（初始密码 admin123，登录后可在「账号」页修改）');
}

const collector = new Collector(config, db);
collector.on('error', (e) => console.error('[collector]', e.message));
collector.start();

const alerts = new AlertManager(config, db).init();
const captures = new CaptureManager(config);

// ---- SSE 客户端 ----
const sseClients = new Set();
function sseBroadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of sseClients) { try { c.write(payload); } catch (_e) { /* ignore */ } }
}
collector.on('records', (rows) => {
  alerts.feed(rows);
  if (!sseClients.size) return;
  for (const r of rows) {
    sseBroadcast('record', { ts: r.ts, srcIp: r.srcIp, proto: r.proto, dstPort: r.dstPort, bytes: r.bytes });
  }
});
alerts.on('alert', (a) => sseBroadcast('alert', a));

// ---- 认证 ----
const throttle = new LoginThrottle();

function getSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  return verifySession(config.secret, cookies[COOKIE_NAME]);
}

// 检测 tcpdump 是否可用（spawn --version，结果缓存；error 事件即未安装）
let tcpdumpOkCache = null;
function detectTcpdump() {
  if (tcpdumpOkCache !== null) return Promise.resolve(tcpdumpOkCache);
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; tcpdumpOkCache = v; resolve(v); } };
    try {
      const c = spawn(config.tcpdumpBin || 'tcpdump', ['--version'], { stdio: 'ignore' });
      c.on('error', () => finish(false));
      c.on('exit', () => finish(true));
      setTimeout(() => { try { c.kill(); } catch (_e) { /* ignore */ } finish(false); }, 3000);
    } catch (_e) { finish(false); }
  });
}

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  next();
});
app.use(express.json());

// 公开端点
app.get('/login.html', (_req, res) => {
  if (config.noAuth) return res.redirect('/');
  res.sendFile(path.join(__dirname, '..', 'public', 'login.html'));
});
app.post('/login', (req, res) => {
  const key = req.socket.remoteAddress || 'unknown';
  const t = throttle.check(key);
  if (t.locked) return res.status(429).json({ error: `失败次数过多，请 ${t.retryAfterSec} 秒后再试` });
  const { user, password } = req.body || {};
  if (typeof user !== 'string' || typeof password !== 'string' || !user || !password) {
    throttle.fail(key);
    return res.status(401).json({ error: '请输入账号和密码' });
  }
  const u = db.getUser(user);
  if (!u || !verifyPassword(password, u.pass_hash)) {
    throttle.fail(key);
    return res.status(401).json({ error: '账号或密码错误' });
  }
  throttle.ok(key);
  const ttlMs = (config.sessionHours || 12) * 3600 * 1000;
  res.set('Set-Cookie', cookieHeader(makeSession(config.secret, ttlMs, { user: u.name, role: u.role }), ttlMs / 1000));
  res.json({ ok: true, user: u.name, role: u.role });
});

// 认证守卫：未授权 401 / 页面跳登录；已授权挂 req.user
// --no-auth（桌面版）：内核只绑 127.0.0.1，数据不出本机，直接按管理员放行
app.use((req, res, next) => {
  if (config.noAuth) { req.user = { user: 'admin', role: 'admin' }; return next(); }
  const sess = getSession(req);
  if (sess) { req.user = sess; return next(); }
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: '未授权' });
  return res.redirect('/login.html');
});

// 角色守卫：viewer 只读（GET 放行），写操作需管理员；改自己密码例外（路由内自校验）
app.use('/api', (req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  if (req.user.role === 'admin') return next();
  if (req.path === '/users/password') return next();
  return res.status(403).json({ error: '只读账号无此权限，请联系管理员' });
});

// ---- 用户管理 ----
app.get('/api/users', (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: '仅管理员可查看用户列表' });
  res.json(db.listUsers().map(u => ({ name: u.name, role: u.role, createdTs: u.created_ts })));
});
app.post('/api/users', (req, res) => {
  try {
    const { user, password, role } = req.body || {};
    const name = String(user || '').trim();
    if (!/^[\w.@-]{1,32}$/.test(name)) return res.status(400).json({ error: '账号限 1-32 位字母/数字/_/.@-' });
    if (typeof password !== 'string' || password.length < 4 || password.length > 64) return res.status(400).json({ error: '密码长度 4-64 位' });
    const r = role === 'admin' ? 'admin' : 'viewer';
    if (db.getUser(name)) return res.status(400).json({ error: `账号 ${name} 已存在` });
    db.insertUser(name, hashPassword(password), r);
    console.log(`[auth] 新建账号 ${name}（${r}）`);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
// 改密码：admin 可改任何人；viewer 只能改自己且需验证旧密码
app.post('/api/users/password', (req, res) => {
  try {
    const { user, oldPassword, password } = req.body || {};
    const name = req.user.role === 'admin' ? String(user || req.user.user).trim() : req.user.user;
    if (!db.getUser(name)) return res.status(404).json({ error: '账号不存在' });
    if (req.user.role !== 'admin' || name === req.user.user) {
      // 改自己的密码（含管理员）：需验证旧密码
      const u = db.getUser(name);
      if (!verifyPassword(String(oldPassword || ''), u.pass_hash)) return res.status(400).json({ error: '旧密码不正确' });
    }
    if (typeof password !== 'string' || password.length < 4 || password.length > 64) return res.status(400).json({ error: '新密码长度 4-64 位' });
    if (!db.updateUserPassword(name, hashPassword(password))) return res.status(404).json({ error: '账号不存在' });
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
app.delete('/api/users/:name', (req, res) => {
  const name = req.params.name;
  if (name === req.user.user) return res.status(400).json({ error: '不能删除当前登录的账号' });
  const u = db.getUser(name);
  if (!u) return res.status(404).json({ error: '账号不存在' });
  if (u.role === 'admin' && db.countAdmins() <= 1) return res.status(400).json({ error: '至少保留一个管理员账号' });
  db.deleteUser(name);
  console.log(`[auth] 删除账号 ${name}`);
  res.json({ ok: true });
});

app.post('/logout', (_req, res) => {
  res.set('Set-Cookie', cookieHeader('', 0));
  res.json({ ok: true });
});

app.get('/', (_req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

// 手写静态服务：pkg 打包的虚拟文件系统下 express.static(内部 send 模块) 会 404，
// 基于 fs.readFile 的实现在 pkg 与普通 node 下行为一致
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const STATIC_MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') return next();
  let rel;
  try { rel = decodeURIComponent(req.path.replace(/^\/+/, '')); } catch (_e) { return next(); }
  if (!rel || rel.includes('..') || rel.includes('\\')) return next();
  const file = path.join(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return next();
  fs.readFile(file, (err, data) => {
    if (err) return next();
    res.set('Content-Type', STATIC_MIME[path.extname(file).toLowerCase()] || 'application/octet-stream');
    res.set('Cache-Control', 'no-store'); // 前端改动即时生效，避免缓存旧 JS
    res.end(req.method === 'HEAD' ? undefined : data);
  });
});

// ---- API ----
app.get('/api/session', async (req, res) => {
  res.json({
    ok: true, ip: req.socket.remoteAddress, mode: collector.mode,
    capture: config.replay ? 'replay' : 'tcpdump',
    tcpdumpOk: await detectTcpdump(),
    user: req.user.user, role: req.user.role,
    noAuth: !!config.noAuth,
    lastError: collector.lastError || '',
    listen: {
      hostname: os.hostname(),
      iface: config.iface || 'any',
      localIps: [...(collector.localIps || [])].filter(x => !x.startsWith('::ffff:')).slice(0, 8),
      replay: config.replay || '',
    },
  });
});
app.post('/api/mode/real', (_req, res) => {
  try {
    if (!config.replay) return res.status(400).json({ error: '当前已经是真实抓包模式' });
    collector.startReal();
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get('/api/overview', (_req, res) => {
  res.json(db.getOverview({}));
});

app.get('/api/records', (req, res) => {
  const q = req.query;
  const f = {
    ip: q.ip || '',
    port: q.port === undefined || q.port === '' ? null : Number(q.port),
    proto: q.proto || '',
    from: q.from ? Number(q.from) : null,
    to: q.to ? Number(q.to) : null,
    page: q.page ? Number(q.page) : 1,
    size: q.size ? Number(q.size) : 50,
  };
  res.json(db.getRecords(f));
});

app.get('/api/clients', (req, res) => {
  const q = req.query;
  const f = {
    from: q.from ? Number(q.from) : null,
    to: q.to ? Number(q.to) : null,
    limit: 200,
    scan: {
      windowMs: (config.scanWindowMin || 10) * 60000,
      threshold: config.scanPortsThreshold || 15,
      newIpMs: (config.newIpHours || 24) * 3600 * 1000,
    },
  };
  res.json(db.getClients(f));
});

app.get('/api/alerts', (req, res) => {
  res.json(db.getAlerts(Number(req.query.limit) || 50));
});

// 测试告警链路（SSE 推送 + webhook 连通性），与真实告警走同一管道
app.post('/api/alerts/test', (_req, res) => {
  alerts.fire('test', '0.0.0.0', '测试告警：验证页面推送与 webhook 通知链路');
  res.json({ ok: true });
});

// ---- 按需抓包（本机 / SSH 远程）----
app.get('/api/captures/hosts', (_req, res) => {
  res.json(captures.hosts());
});
app.post('/api/captures', (req, res) => {
  try {
    const cap = captures.start(req.body || {});
    console.log(`[capture] 开始定向抓包 #${cap.id} @${cap.target} ${cap.filter || '(无过滤)'} ${cap.seconds}s`);
    res.json(cap);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
app.get('/api/captures', (_req, res) => {
  res.json(captures.list());
});
app.post('/api/captures/stop', (_req, res) => {
  const r = captures.stop();
  if (!r) return res.status(400).json({ error: '当前没有进行中的抓包任务' });
  console.log(`[capture] 手动停止抓包 #${r.id}`);
  res.json({ ok: true, id: r.id });
});

// ---- 远程主机管理：页面直接增删改，写回 config.json，热生效无需重启 ----
function persistRemoteHosts() {
  const cfgFile = argv.config || 'config.json';
  const raw = JSON.parse(fs.readFileSync(cfgFile, 'utf8'));
  raw.remoteHosts = config.remoteHosts;
  fs.writeFileSync(cfgFile, JSON.stringify(raw, null, 2) + '\n');
}
app.get('/api/remote-hosts', (_req, res) => {
  res.json((config.remoteHosts || []).map(h => ({
    name: h.name, host: h.host, port: h.port || 22, user: h.user,
    hasPassword: !!h.password, keyFile: h.keyFile || '',
  })));
});
app.post('/api/remote-hosts', (req, res) => {
  try {
    const body = req.body || {};
    const list = [...(config.remoteHosts || [])];
    const origName = String(body.origName || '').trim();
    const existing = origName ? list.find(h => h.name === origName) : null;
    if (origName && !existing) return res.status(400).json({ error: `要编辑的主机 ${origName} 不存在` });
    const entry = validateRemoteHost(body, { existing, names: list.map(h => h.name) });
    if (existing) list[list.indexOf(existing)] = entry;
    else list.push(entry);
    config.remoteHosts = list; // captures 持有同一 config 引用，热生效
    persistRemoteHosts();
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
app.delete('/api/remote-hosts/:name', (req, res) => {
  try {
    const before = (config.remoteHosts || []).length;
    config.remoteHosts = (config.remoteHosts || []).filter(h => h.name !== req.params.name);
    if (config.remoteHosts.length === before) return res.status(404).json({ error: '主机不存在' });
    persistRemoteHosts();
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
app.get('/api/captures/packets', (req, res) => {
  const r = captures.getPacketPage(req.query.id, Number(req.query.page) || 1, Number(req.query.size) || 50, req.query.q || '');
  if (!r) return res.status(404).json({ error: '抓包文件不存在或尚未完成' });
  if (r.error) return res.status(400).json({ error: r.error });
  res.json(r);
});
app.get('/api/captures/packet', (req, res) => {
  const r = captures.getPacketDetail(req.query.id, Number(req.query.no));
  if (!r) return res.status(404).json({ error: '抓包文件不存在或尚未完成' });
  if (r.error) return res.status(400).json({ error: r.error });
  res.json(r);
});
app.get('/api/captures/analyze', (req, res) => {
  const r = captures.analyze(req.query.id);
  if (!r) return res.status(404).json({ error: '抓包文件不存在或尚未完成' });
  if (r.error) return res.status(400).json({ error: r.error });
  res.json(r);
});
app.get('/api/captures/stream', (req, res) => {
  const r = captures.getStream(req.query.id, { a: req.query.a, ap: req.query.ap, b: req.query.b, bp: req.query.bp });
  if (!r) return res.status(404).json({ error: '抓包文件不存在或尚未完成' });
  if (r.error) return res.status(400).json({ error: r.error });
  res.json(r);
});
app.get('/api/captures/download', (req, res) => {
  const file = captures.getFile(req.query.id);
  if (!file) return res.status(404).json({ error: '抓包文件不存在或尚未完成' });
  res.set('Content-Type', 'application/vnd.tcpdump.pcap');
  res.set('Content-Disposition', `attachment; filename="ip-visitor-capture-${Number(req.query.id)}.pcap"`);
  fs.createReadStream(file).pipe(res);
});

app.get('/api/clients/:ip', (req, res) => {
  const q = req.query;
  const f = {
    from: q.from ? Number(q.from) : null,
    to: q.to ? Number(q.to) : null,
  };
  res.json(db.getClientDetail(req.params.ip, f));
});

app.get('/api/stream', (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });
  res.flushHeaders();
  res.write('retry: 3000\n\n');
  sseClients.add(res);
  const hb = setInterval(() => { try { res.write(': hb\n\n'); } catch (_e) { /* ignore */ } }, 25000);
  req.on('close', () => { clearInterval(hb); sseClients.delete(res); });
});

// ---- 保留期清理 ----
const RETENTION_MS = (config.retentionDays || 7) * 86400 * 1000;
function runCleanup() {
  if (!config.retentionDays || config.retentionDays <= 0) return;
  const cutoff = Date.now() - RETENTION_MS;
  const deleted = db.cleanup(config.retentionDays);
  const alertsDeleted = db.cleanupAlerts(config.retentionDays);
  if (deleted > 0 || alertsDeleted > 0) console.log(`[db] 清理 ${new Date(cutoff).toLocaleString()} 之前的记录 ${deleted} 条、告警 ${alertsDeleted} 条`);
}
runCleanup();
setInterval(runCleanup, 3600 * 1000).unref();

const listenHost = config.listenHost || '0.0.0.0';
const server = app.listen(config.port, listenHost, () => {
  console.log(`[web] http://${listenHost === '0.0.0.0' ? '<本机IP>' : listenHost}:${config.port}  (capture=${config.replay ? 'replay' : 'tcpdump'}, mode=${collector.mode}, auth=${config.noAuth ? '免登录' : '登录'})`);
});
server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`[web] 端口 ${config.port} 已被占用（可能已有本服务在运行），退出`);
    process.exit(1);
  }
  throw e;
});

function shutdown() {
  console.log('\n[server] 正在退出...');
  collector.stop();
  alerts.stop();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
