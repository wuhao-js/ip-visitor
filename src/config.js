'use strict';

const fs = require('fs');
const crypto = require('crypto');

const DEFAULTS = {
  port: 8321,
  password: '',           // 初始 admin 密码来源；留空用内置默认 admin123（登录后请修改）
  secret: '',
  dbFile: 'data/access.db',
  iface: 'any',
  retentionDays: 7,
  tcpdumpBin: 'tcpdump',
  sessionHours: 12,
  localIps: [], // 服务器自身 IP（NAT/多网卡时手动补充，用于入站方向判定与回放）
  scanPortsThreshold: 15, // 扫描判定：窗口内 distinct 端口数阈值
  scanWindowMin: 10,      // 扫描判定时间窗口（分钟）
  newIpHours: 24,         // 多少小时内首次出现的 IP 标记为"新"
  webhookUrl: '',         // 企业微信/钉钉群机器人 webhook，空为不通知
  captureDir: 'data/captures',
  // 远程抓包主机列表（password 与 keyFile 二选一）：
  // [{name:'web-1', host:'10.0.0.11', port:22, user:'root', password:'xxx', tcpdumpBin:'tcpdump'}]
  // 或密钥方式 {name, host, port, user, keyFile:'~/.ssh/id_rsa'}
  // user 非 root 时远端执行 `sudo -n tcpdump`，需配置 NOPASSWD
  remoteHosts: [],
};

// 内置默认账号 admin 的公开初始密码（首次启动自动建号，登录后请在「账号」页修改）
const DEFAULT_ADMIN_PASSWORD = 'admin123';

// 加载配置；不存在则生成 config.json（仅生成签名密钥，初始密码不落盘）
function loadConfig(configPath = 'config.json') {
  let cfg = {};
  if (fs.existsSync(configPath)) {
    cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  }
  const merged = { ...DEFAULTS, ...cfg };
  let created = false;
  if (!merged.password) merged.password = DEFAULT_ADMIN_PASSWORD;
  if (!merged.secret) { merged.secret = crypto.randomBytes(32).toString('hex'); created = true; }
  if (created || !fs.existsSync(configPath)) {
    const persist = { ...merged };
    delete persist.password;
    fs.writeFileSync(configPath, JSON.stringify(persist, null, 2) + '\n');
  }
  if (created) {
    console.log('='.repeat(56));
    console.log('首次启动已生成 config.json');
    console.log('初始账号: admin / admin123（登录后请在「账号」页修改密码）');
    console.log('='.repeat(56));
  }
  return merged;
}

module.exports = { loadConfig, DEFAULT_ADMIN_PASSWORD, DEFAULTS };
