'use strict';

const fs = require('fs');
const crypto = require('crypto');

const DEFAULTS = {
  port: 8321,
  password: '',
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

function genPassword(len = 12) {
  const chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) out += chars[bytes[i] % chars.length];
  return out;
}

// 加载配置；不存在则生成 config.json（自动生成密码与签名密钥并打印）
function loadConfig(configPath = 'config.json') {
  let cfg = {};
  if (fs.existsSync(configPath)) {
    cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  }
  const merged = { ...DEFAULTS, ...cfg };
  let created = false;
  if (!merged.password) { merged.password = genPassword(); created = true; }
  if (!merged.secret) { merged.secret = crypto.randomBytes(32).toString('hex'); created = true; }
  if (created || !fs.existsSync(configPath)) {
    fs.writeFileSync(configPath, JSON.stringify(merged, null, 2) + '\n');
  }
  if (created) {
    console.log('='.repeat(56));
    console.log('首次启动已生成 config.json');
    console.log(`访问密码: ${merged.password}`);
    console.log('（请妥善保管；修改 config.json 后重启生效）');
    console.log('='.repeat(56));
  }
  return merged;
}

module.exports = { loadConfig, genPassword, DEFAULTS };
