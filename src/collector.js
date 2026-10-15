'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const readline = require('readline');
const { EventEmitter } = require('events');
const { parseLine } = require('./parser');
const { shouldRecord } = require('./direction');

const FILTER = 'tcp or udp or icmp or icmp6';

// 采集器：spawn tcpdump 抓入站包 → 解析 → 批量入库；或 --replay 回放样本文件
class Collector extends EventEmitter {
  constructor(cfg, db) {
    super();
    this.cfg = cfg;
    this.db = db;
    this.buf = [];
    this.stopped = false;
    this.mode = cfg.replay ? 'filter' : (cfg.forceNoQ ? 'filter' : 'Q');
    this.retries = 0;
    this.child = null;
    this.lastError = '';
    this.stats = { parsed: 0, recorded: 0, skipped: 0 };
  }

  start() {
    this.localIps = require('./direction').buildLocalIps();
    for (const ip of this.cfg.localIps || []) this.localIps.add(String(ip).toLowerCase());
    if (this.cfg.replay) {
      this.replayOnce();
    } else {
      this.startTcpdump(!this.cfg.forceNoQ);
      this.flushTimer = setInterval(() => this.flush(), 1000);
    }
    return this;
  }

  stop() {
    this.stopped = true;
    if (this.child) { try { this.child.kill(); } catch (_e) { /* ignore */ } }
    if (this.flushTimer) clearInterval(this.flushTimer);
    if (this.replayTimer) clearTimeout(this.replayTimer);
  }

  // 运行时从回放切换到真实抓包（需本机有 tcpdump；失败置 lastError，经 /api/session 暴露）
  startReal() {
    this.stop();
    this.stopped = false;
    this.retries = 0;
    this.lastError = '';
    this.cfg.replay = null;
    this.cfg.loop = false;
    this.mode = this.cfg.forceNoQ ? 'filter' : 'Q';
    this.startTcpdump(!this.cfg.forceNoQ);
    this.flushTimer = setInterval(() => this.flush(), 1000);
  }

  startTcpdump(useQ) {
    const args = ['-l', '-nn', '-tttt', '-q', '-i', this.cfg.iface || 'any'];
    if (useQ) args.push('-Q', 'in');
    args.push(FILTER);
    const bin = this.cfg.tcpdumpBin || 'tcpdump';
    let stderrBuf = '';
    let gotData = false;

    let child;
    try {
      child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) {
      this.lastError = `无法启动 ${bin}: ${e.message}（Windows 本机请使用 --replay 模式验证）`;
      this.emit('error', new Error(this.lastError));
      return;
    }
    child.on('error', (e) => {
      this.lastError = `无法启动 ${bin}: ${e.message}（Windows 本机请使用 --replay 模式验证；Linux 部署需安装 tcpdump 并以 root 或 setcap 运行）`;
      this.emit('error', new Error(this.lastError));
    });
    this.child = child;
    this.mode = useQ ? 'Q' : 'filter';
    console.log(`[collector] 已启动 ${bin} ${args.join(' ')} (mode=${this.mode})`);

    readline.createInterface({ input: child.stdout, crlfDelay: Infinity })
      .on('line', (line) => {
        gotData = true;
        this.handleLine(line);
      });
    child.stderr.on('data', (d) => {
      stderrBuf = (stderrBuf + d).slice(-4000);
    });
    child.on('exit', (code) => {
      this.child = null;
      if (this.stopped) return;
      if (useQ && !gotData && code !== 0 && /option|usage|invalid|unknown/i.test(stderrBuf)) {
        console.log('[collector] 当前 tcpdump 不支持 -Q in，降级为按本机 IP 过滤入站方向');
        this.startTcpdump(false);
        return;
      }
      this.flush();
      console.error(`[collector] tcpdump 退出 code=${code}${stderrBuf ? ' stderr: ' + stderrBuf.trim().split('\n').pop() : ''}`);
      if (this.retries < 3) {
        this.retries += 1;
        console.error(`[collector] 5 秒后重试（第 ${this.retries}/3 次）`);
        setTimeout(() => { if (!this.stopped) this.startTcpdump(useQ); }, 5000);
      } else {
        this.lastError = 'tcpdump 反复退出，采集已停止（检查 root 权限 / 网卡名 / BPF 过滤器）';
        this.emit('error', new Error(this.lastError));
      }
    });
  }

  handleLine(line) {
    this.stats.parsed += 1;
    const rec = parseLine(line);
    if (!shouldRecord(rec, this.mode, this.localIps)) {
      this.stats.skipped += 1;
      return;
    }
    this.buf.push(rec);
    if (this.buf.length >= 300) this.flush();
  }

  flush() {
    if (!this.buf.length) return;
    const rows = this.buf.splice(0, this.buf.length);
    try {
      this.db.insertBatch(rows);
      this.stats.recorded += rows.length;
      this.emit('records', rows);
    } catch (e) {
      console.error('[collector] 入库失败:', e.message);
    }
  }

  // 回放 tcpdump 文本样本：时间整体平移到"最后一条=现在"，完整走 解析→过滤→入库→事件 流程
  replayOnce() {
    let lines;
    try {
      lines = fs.readFileSync(this.cfg.replay, 'utf8').split(/\r?\n/);
    } catch (e) {
      this.emit('error', new Error(`回放文件读取失败: ${e.message}`));
      return;
    }
    const parsed = lines.map(l => parseLine(l)).filter(Boolean);
    if (!parsed.length) {
      this.emit('error', new Error('回放文件中没有可解析的 tcpdump 行'));
      return;
    }
    // 方向过滤：回放统一用解析层判定
    const now = Date.now();
    const tmax = Math.max(...parsed.map(p => p.ts));
    const offset = now - tmax;
    const rows = parsed
      .map(p => ({ ...p, ts: p.ts + offset }))
      .filter(r => shouldRecord(r, 'filter', this.localIps));
    this.db.insertBatch(rows);
    this.stats.recorded += rows.length;
    console.log(`[collector] 回放 ${rows.length}/${parsed.length} 条记录（已平移到当前时间）`);
    this.emit('records', rows);
    if (this.cfg.loop) {
      this.replayTimer = setTimeout(() => this.replayOnce(), 3000);
    }
  }
}

module.exports = { Collector };
