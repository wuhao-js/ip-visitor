'use strict';

const { EventEmitter } = require('events');

const COOLDOWN_MS = 30 * 60 * 1000; // 同类告警（type+ip）30 分钟内不重复

// 告警管理：新客户端首次来访 / 疑似端口扫描；入库 + SSE + webhook（企业微信/钉钉群机器人格式）
class AlertManager extends EventEmitter {
  constructor(cfg, db) {
    super();
    this.cfg = cfg;
    this.db = db;
    this.knownIps = new Set();
    this.cooldowns = new Map();
    this.scanTimer = null;
  }

  init() {
    for (const ip of this.db.getAllKnownIps()) this.knownIps.add(ip);
    // 启动后先查一次，覆盖服务重启前窗口内已发生的扫描
    this.startupTimer = setTimeout(() => this.checkScan(), 3000);
    this.startupTimer.unref();
    this.scanTimer = setInterval(() => this.checkScan(), 60 * 1000);
    this.scanTimer.unref();
    return this;
  }

  stop() {
    if (this.scanTimer) clearInterval(this.scanTimer);
    if (this.startupTimer) clearTimeout(this.startupTimer);
  }

  // 采集器每批记录喂入：识别首次来访 IP
  feed(records) {
    for (const r of records) {
      const ip = r.srcIp;
      if (this.knownIps.has(ip)) continue;
      this.knownIps.add(ip);
      this.fire('new_client', ip, `新客户端首次来访（${r.proto.toUpperCase()} 端口 ${r.dstPort || '-'}）`);
    }
  }

  checkScan() {
    const threshold = this.cfg.scanPortsThreshold || 15;
    const windowMs = (this.cfg.scanWindowMin || 10) * 60000;
    let suspects;
    try {
      suspects = this.db.findScanSuspects(windowMs, threshold);
    } catch (e) {
      console.error('[alerts] 扫描检测查询失败:', e.message);
      return;
    }
    for (const s of suspects) {
      this.fire('port_scan', s.ip, `疑似端口扫描：${Math.round(windowMs / 60000)} 分钟内试探 ${s.ports} 个端口（${s.packets} 个包）`);
    }
  }

  fire(type, ip, detail) {
    const key = `${type}:${ip}`;
    const last = this.cooldowns.get(key) || 0;
    if (Date.now() - last < COOLDOWN_MS) return;
    this.cooldowns.set(key, Date.now());
    const ts = Date.now();
    try {
      this.db.insertAlert(ts, type, ip, detail);
    } catch (e) {
      console.error('[alerts] 告警入库失败:', e.message);
    }
    const alert = { ts, type, ip, detail };
    console.log(`[alerts] [${type}] ${ip}: ${detail}`);
    this.emit('alert', alert);
    this.sendWebhook(alert);
  }

  sendWebhook(alert) {
    const url = this.cfg.webhookUrl;
    if (!url) return;
    const icon = alert.type === 'port_scan' ? '⚠️疑似端口扫描' : '🆕新客户端来访';
    const body = JSON.stringify({
      msgtype: 'text',
      text: { content: `[来访IP监控] ${icon}\nIP: ${alert.ip}\n${alert.detail}\n时间: ${new Date(alert.ts).toLocaleString()}` },
    });
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 5000);
    fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, signal: ctl.signal })
      .then(r => { if (!r.ok) console.error('[alerts] webhook 响应异常:', r.status); })
      .catch(e => console.error('[alerts] webhook 发送失败:', e.message))
      .finally(() => clearTimeout(timer));
  }
}

module.exports = { AlertManager };
