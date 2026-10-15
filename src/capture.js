'use strict';

const { spawn } = require('child_process');
const { Client } = require('ssh2');
const EventEmitter = require('events');
const { PassThrough } = require('stream');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { parsePcap, decodePacket, hexDump } = require('./pcap');

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
// 严格校验，防止参数进入 BPF 过滤器造成注入
function validIp(ip) {
  if (!ip) return false;
  if (IPV4_RE.test(ip)) {
    return ip.split('.').every(o => Number(o) <= 255);
  }
  return /^[0-9a-fA-F:.]+$/.test(ip) && ip.includes(':') && ip.length <= 45;
}

// 按需定向抓包：本机 tcpdump -w 落盘，或 SSH 到远程主机 `tcpdump -w -` 流式回传
class CaptureManager {
  constructor(cfg) {
    this.cfg = cfg;
    this.captures = new Map(); // id -> capture 记录
    this.proc = null;
    this.stopping = false; // 主动终止标记（到时/手动停止），exit 时据此判 done 而非 error
    this.seq = Date.now();
  }

  hosts() {
    return [{ name: 'local', label: '本机' }].concat(
      (this.cfg.remoteHosts || []).map(h => ({ name: h.name, label: `${h.name}(${h.host})` }))
    );
  }

  findHost(name) {
    if (!name || name === 'local') return null;
    const h = (this.cfg.remoteHosts || []).find(x => x.name === name);
    if (!h) throw new Error(`未配置的远程主机: ${name}`);
    return h;
  }

  list() {
    return [...this.captures.values()].sort((a, b) => b.id - a.id).map(c => ({
      id: c.id, target: c.target, ip: c.ip, port: c.port, proto: c.proto, seconds: c.seconds,
      startedTs: c.startedTs, status: c.status, size: c.size, error: c.error || '',
      filter: c.filter,
    }));
  }

  // 手动停止当前抓包：主动终止按正常完成处理（pcap 尾部残包由解析容错丢弃）
  stop() {
    if (!this.proc) return null;
    const cap = [...this.captures.values()].find(c => c.status === 'running');
    this.stopping = true;
    try { this.proc.kill(); } catch (_e) { /* ignore */ }
    return cap ? { id: cap.id } : null;
  }

  start({ target, ip, port, proto, seconds }) {
    const host = this.findHost(target); // 抛错=未配置的主机
    // 回放模式只挡本机抓包；SSH 远程抓包不依赖本机网卡，仍然可用
    if (this.cfg.replay && !host) throw new Error('回放模式没有真实网卡，不支持本机抓包（远程主机抓包不受影响）');
    if (host && !host.password && !host.keyFile) {
      throw new Error(`远程主机 ${host.name} 未配置 password 或 keyFile，请在 config.json 的 remoteHosts 中补充`);
    }
    if (this.proc) throw new Error('已有抓包任务进行中，请等待完成');
    if (!ip && !port && !proto) throw new Error('IP / 端口 / 协议至少填一项，避免全量抓包撑爆磁盘');
    if (ip && !validIp(ip)) throw new Error('IP 格式不合法');
    if (port != null && port !== '' && !(Number.isInteger(Number(port)) && Number(port) >= 1 && Number(port) <= 65535)) throw new Error('端口不合法');
    if (proto && !['tcp', 'udp', 'icmp'].includes(proto)) throw new Error('协议只支持 tcp/udp/icmp');
    const secs = Number(seconds) || 60;
    if (!(secs >= 10 && secs <= 300)) throw new Error('抓包时长限 10-300 秒');

    const bpf = buildBpf({ ip, port, proto });
    const dir = this.cfg.captureDir || 'data/captures';
    fs.mkdirSync(dir, { recursive: true });
    const id = ++this.seq;
    const file = path.join(dir, `cap-${id}.pcap`);
    const cap = {
      id, target: host ? host.name : 'local', ip: ip || '', port: port || 0, proto: proto || '',
      seconds: secs, startedTs: Date.now(), status: 'running', file, size: 0, filter: bpf,
    };

    let child;
    let ws = null;
    if (host) {
      child = this.spawnRemote(host, bpf);
      ws = fs.createWriteStream(file);
      child.stdout.pipe(ws); // 远程 pcap 经 ssh stdout 流式落盘
    } else {
      child = this.spawnLocal(bpf, file); // 本机 tcpdump 直接 -w 写文件，不再二次管道
    }
    this.proc = child;
    this.captures.set(id, cap);

    let stderr = '';
    child.stderr.on('data', d => { stderr = (stderr + d).slice(-2000); });
    // ssh2 场景下 error 与 stream close 可能先后触发，finish 必须幂等
    let finished = false;
    const finish = (status) => {
      if (finished) return;
      finished = true;
      this.proc = null;
      this.stopping = false;
      cap.status = status;
      if (ws) ws.end();
      try { cap.size = fs.statSync(file).size; } catch (_e) { cap.size = 0; }
      if (status === 'error') cap.error = cap.error || (stderr || '').trim().split('\n').pop() || '抓包失败';
    };
    // 到时终止与手动停止都是我们主动 kill：tcpdump 被信号终止的退出码非 0，属正常结束不能判失败
    const timer = setTimeout(() => { this.stopping = true; try { child.kill(); } catch (_e) { /* ignore */ } }, secs * 1000);
    child.on('error', (e) => {
      clearTimeout(timer);
      if (!this.stopping) cap.error = cap.error || e.message;
      finish(this.stopping ? 'done' : 'error');
    });
    child.on('exit', (code) => {
      clearTimeout(timer);
      finish(this.stopping || code === 0 || code === null ? 'done' : 'error');
    });
    return { ...cap };
  }

  spawnLocal(bpf, file) {
    const args = ['-i', this.cfg.iface || 'any', '-nn', '-w', file];
    if (bpf) args.push(bpf);
    const bin = this.cfg.tcpdumpBin || 'tcpdump';
    try {
      return spawn(bin, args, { stdio: ['ignore', 'ignore', 'pipe'] });
    } catch (e) {
      throw new Error(`无法启动 ${bin}: ${e.message}`);
    }
  }

  // ssh2 远程抓包：用户名+密码 或 密钥认证；`tcpdump -w -` pcap 从 stdout 流式回传。
  // user!=root 时前置 sudo -n（需 NOPASSWD）。适配成 child_process 风格接口：
  // stdout/stderr 即刻可用（PassThrough 缓冲），SSH 流就绪后接入，kill/exit/error 语义与本地子进程一致
  spawnRemote(host, bpf) {
    const iface = this.cfg.iface || 'any';
    const tcpdumpBin = host.tcpdumpBin || this.cfg.tcpdumpBin || 'tcpdump';
    const prefix = host.user === 'root' ? '' : 'sudo -n ';
    const remoteCmd = `${prefix}${tcpdumpBin} -i ${iface} -nn -U -w - '${bpf || ''}'`.replace(/''$/, '');
    const auth = {};
    if (host.password) {
      auth.password = host.password;
    } else if (host.keyFile) {
      const kf = host.keyFile.replace(/^~(?=$|\/|\\)/, os.homedir());
      try {
        auth.privateKey = fs.readFileSync(kf);
      } catch (e) {
        throw new Error(`读取密钥文件 ${kf} 失败: ${e.message}`);
      }
    }

    const conn = new Client();
    const child = new EventEmitter();
    let stream = null;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => {
      try { if (stream) stream.close(); } catch (_e) { /* ignore */ }
      try { conn.end(); } catch (_e) { /* ignore */ }
    };
    conn.on('ready', () => {
      conn.exec(remoteCmd, (err, s) => {
        if (err) { child.emit('error', err); conn.end(); return; }
        stream = s;
        s.pipe(child.stdout);
        s.stderr.pipe(child.stderr);
        s.on('close', (code) => {
          child.stdout.end();
          child.stderr.end();
          conn.end();
          child.emit('exit', code);
        });
      });
    });
    conn.on('error', (e) => child.emit('error', e));
    conn.on('close', () => {
      // exec 流从未建立就断开（如就绪前手动停止）：补发 exit，避免任务永久卡在 running
      if (!stream) child.emit('exit', null);
    });
    conn.connect({
      host: host.host,
      port: Number(host.port) || 22,
      username: host.user || 'root',
      readyTimeout: 10000,
      ...auth,
    });
    console.log(`[capture] 远程抓包: ${host.user}@${host.host}:${host.port || 22}（${host.password ? '密码' : '密钥'}认证） ${remoteCmd}`);
    return child;
  }

  getFile(id) {
    const cap = this.captures.get(Number(id));
    if (!cap || cap.status !== 'done' || !cap.file) return null;
    return cap.file;
  }

  // 页内分析摘要：一次解析全量包，聚合协议/TCP标志/来源/端口/对话分布，并生成自动诊断结论
  analyze(id) {
    const cap = this.captures.get(Number(id));
    if (!cap || cap.status !== 'done' || !cap.file) return null;
    let buf;
    try {
      buf = fs.readFileSync(cap.file);
    } catch (e) {
      return { error: `读取抓包文件失败: ${e.message}` };
    }
    const parsed = parsePcap(buf);
    if (parsed.error) return { error: parsed.error };
    const proto = {}, flags = {}, srcs = {}, ports = {}, convs = {}, convMeta = {}, perSrc = {};
    const tcpPkts = [];
    let bytes = 0, t0 = 0, t1 = 0, badPackets = 0, httpPkts = 0;
    for (const p of parsed.packets) {
      bytes += p.len;
      if (!t0 || p.tsMs < t0) t0 = p.tsMs;
      if (p.tsMs > t1) t1 = p.tsMs;
      const d = decodePacket(parsed.linktype, p.data);
      if (d.error) { badPackets++; continue; }
      proto[d.proto] = (proto[d.proto] || 0) + 1;
      if (d.tcpFlags) for (const ch of d.tcpFlags) flags[ch] = (flags[ch] || 0) + 1;
      if (d.dstPort) ports[d.dstPort] = (ports[d.dstPort] || 0) + 1;
      const conv = `${d.src}${d.srcPort ? ':' + d.srcPort : ''} → ${d.dst}${d.dstPort ? ':' + d.dstPort : ''}`;
      convs[conv] = (convs[conv] || 0) + 1;
      convMeta[conv] = { a: d.src, ap: d.srcPort || 0, b: d.dst, bp: d.dstPort || 0 };
      if (d.src && d.src !== '?') {
        srcs[d.src] = (srcs[d.src] || 0) + 1;
        const ps = perSrc[d.src] || (perSrc[d.src] = { ports: {}, synOnly: 0, dataPkts: 0 });
        if (d.dstPort) ps.ports[`${d.proto}/${d.dstPort}`] = (ps.ports[`${d.proto}/${d.dstPort}`] || 0) + 1;
        if (d.proto === 'tcp') {
          if ((d.tcpFlags || '') === 'S') ps.synOnly++;
          if (d.payload && d.payload.length) ps.dataPkts++;
          tcpPkts.push({ tsMs: p.tsMs, src: d.src, dst: d.dst, sp: d.srcPort, dp: d.dstPort, flags: d.tcpFlags || '', seq: d.tcpSeq, ack: d.tcpAck });
        }
      }
      if (d.payload && d.payload.length > 5) {
        const head = d.payload.toString('latin1', 0, 5);
        if (/^(GET |POST |PUT |HEAD |DELETE|OPTIO|PATCH|HTTP\/)/.test(head)) httpPkts++;
      }
    }
    const top = (obj, n) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n).map(([k, v]) => ({ k, c: v, ...(convMeta[k] || {}) }));
    const durationMs = t1 && t0 ? t1 - t0 : 0;
    const secs = Math.max(1, Math.round(durationMs / 1000));
    const total = parsed.packets.length;
    const topSrcs = top(srcs, 5);
    const topPorts = top(ports, 5);

    // ---- 自动诊断结论：直接给"这堆包说明了什么" ----
    const findings = [];
    const offender = Object.entries(perSrc)
      .map(([ip, s]) => ({ ip, ...s, portCount: Object.keys(s.ports).length }))
      .filter(s => s.portCount >= 10 && s.dataPkts === 0)
      .sort((a, b) => b.portCount - a.portCount)[0];
    if (offender) {
      findings.push({ level: 'warn', text: `疑似端口扫描：${offender.ip} 在 ${secs} 秒内试探了 ${offender.portCount} 个不同端口、无任何数据载荷（含 ${offender.synOnly} 个 SYN 探测），是典型扫描器行为` });
    }
    const rst = flags.R || 0;
    if (total >= 10 && rst / total >= 0.2) {
      findings.push({ level: 'warn', text: `RST 重置包占 ${Math.round(rst / total * 100)}%（${rst}/${total}）：目标端口多半没有服务监听，或连接被拒绝` });
    }
    if (topSrcs.length && total > 0 && topSrcs[0].c / total >= 0.6) {
      // 只在该来源自己的主端口占比足够高时才提端口，避免把扫描者说成"主要访问某端口"
      const s0 = perSrc[topSrcs[0].k];
      const ent = s0 ? Object.entries(s0.ports).sort((a, b) => b[1] - a[1])[0] : null;
      const dominant = ent && ent[1] / srcs[topSrcs[0].k] >= 0.6 ? `，主要目标是端口 ${ent[0].split('/')[1]}` : '';
      findings.push({ level: 'info', text: `来源 ${topSrcs[0].k} 贡献了 ${Math.round(topSrcs[0].c / total * 100)}% 的报文${dominant}` });
    }
    const synAck = new Map();
    for (const t of tcpPkts) {
      if (t.flags === 'SA') {
        const key = `${t.src}:${t.sp}>${t.dst}:${t.dp}`;
        if (!synAck.has(key)) synAck.set(key, []);
        synAck.get(key).push(t);
      }
    }
    const rtts = [];
    for (const t of tcpPkts) {
      if (t.flags !== 'S' || rtts.length >= 50) continue;
      const list = synAck.get(`${t.dst}:${t.dp}>${t.src}:${t.sp}`);
      if (!list) continue;
      const hit = list.find(x => x.tsMs >= t.tsMs && x.ack === ((t.seq + 1) >>> 0));
      if (hit) rtts.push(hit.tsMs - t.tsMs);
    }
    if (rtts.length) {
      const avg = Math.round(rtts.reduce((a, b) => a + b, 0) / rtts.length);
      findings.push({ level: 'info', text: `TCP 握手（SYN→SYN/ACK）平均 ${avg} ms（采样 ${rtts.length} 次连接）${avg > 100 ? '，偏慢可关注网络路径' : '，连接建立正常'}` });
    }
    if (httpPkts) {
      findings.push({ level: 'info', text: `检测到 ${httpPkts} 个 HTTP 报文，点对话行的「流」按钮可还原完整请求/响应内容` });
    }
    if (!findings.length) {
      findings.push({ level: 'ok', text: `未检出端口扫描、大量 RST 等异常模式，${total} 包更像正常业务往返` });
    }

    return {
      total,
      bytes,
      durationMs,
      pps: durationMs > 0 ? +(total / (durationMs / 1000)).toFixed(1) : null,
      truncated: parsed.truncated,
      badPackets,
      srcCount: Object.keys(srcs).length,
      findings,
      httpPkts,
      protoList: top(proto, 6),
      flagsList: top(flags, 6),
      topSrcs,
      topPorts,
      topConvs: top(convs, 5),
      filter: cap.filter,
      target: cap.target,
    };
  }

  // 报文查看：解析 pcap → 解码全部包 → 按 q 过滤 → 分页返回（不含 hex，hex 走单包详情接口）
  getPacketPage(id, page = 1, size = 50, q = '') {
    const cap = this.captures.get(Number(id));
    if (!cap || cap.status !== 'done' || !cap.file) return null;
    let buf;
    try {
      buf = fs.readFileSync(cap.file);
    } catch (e) {
      return { error: `读取抓包文件失败: ${e.message}` };
    }
    const parsed = parsePcap(buf);
    if (parsed.error) return { error: parsed.error };
    const decoded = parsed.packets.map(p => {
      const d = decodePacket(parsed.linktype, p.data);
      const app = decodeAppPayload(d.payload);
      return {
        no: p.no, tsMs: p.tsMs, len: p.len,
        src: d.src || '?', dst: d.dst || '?',
        proto: d.proto || '-', srcPort: d.srcPort || 0, dstPort: d.dstPort || 0,
        tcpFlags: d.tcpFlags || '', summary: d.summary || '',
        error: d.error || '',
        payloadLen: d.payload ? d.payload.length : 0,
        payloadKind: app ? app.kind : '',
        payloadText: app ? app.text : '',
      };
    });
    const filtered = q ? decoded.filter(p => matchPktFilter(p, q)) : decoded;
    const sizeN = Math.min(200, Math.max(1, size | 0 || 50));
    const pageN = Math.max(1, page | 0 || 1);
    const start = (pageN - 1) * sizeN;
    const slice = filtered.slice(start, start + sizeN);
    return {
      total: parsed.packets.length,
      matched: filtered.length,
      page: pageN,
      size: sizeN,
      q: q || '',
      linktype: parsed.linktype,
      target: cap.target,
      filter: cap.filter,
      packets: slice.map(({ payloadText, ...rest }) => ({ ...rest, payloadPreview: payloadText ? payloadText.slice(0, 60) : '' })),
    };
  }

  // 单包详情：完整解码字段 + 载荷解码 + 全量 hex
  getPacketDetail(id, no) {
    const cap = this.captures.get(Number(id));
    if (!cap || cap.status !== 'done' || !cap.file) return null;
    let buf;
    try {
      buf = fs.readFileSync(cap.file);
    } catch (e) {
      return { error: `读取抓包文件失败: ${e.message}` };
    }
    const parsed = parsePcap(buf);
    if (parsed.error) return { error: parsed.error };
    const p = parsed.packets.find(x => x.no === Number(no));
    if (!p) return { error: `报文 #${no} 不存在` };
    const d = decodePacket(parsed.linktype, p.data);
    const app = decodeAppPayload(d.payload);
    return {
      no: p.no, tsMs: p.tsMs, len: p.len,
      src: d.src || '?', dst: d.dst || '?',
      proto: d.proto || '-', srcPort: d.srcPort || 0, dstPort: d.dstPort || 0,
      tcpFlags: d.tcpFlags || '', tcpSeq: d.tcpSeq, tcpAck: d.tcpAck, tcpWin: d.tcpWin,
      summary: d.summary || '',
      error: d.error || '',
      payloadLen: d.payload ? d.payload.length : 0,
      payloadKind: app ? app.kind : '',
      payloadText: app ? app.text : '',
      hex: hexDump(p.data, 0), // 全量 hex
    };
  }

  // 会话流还原：按对话（双向）取报文，载荷按时间排列 —— 类 Wireshark Follow Stream
  getStream(id, { a, ap, b, bp }) {
    const cap = this.captures.get(Number(id));
    if (!cap || cap.status !== 'done' || !cap.file) return null;
    ap = Number(ap); bp = Number(bp);
    if (!a || !b || !Number.isInteger(ap) || !Number.isInteger(bp)) return { error: '会话参数不完整' };
    let buf;
    try {
      buf = fs.readFileSync(cap.file);
    } catch (e) {
      return { error: `读取抓包文件失败: ${e.message}` };
    }
    const parsed = parsePcap(buf);
    if (parsed.error) return { error: parsed.error };
    const segments = [];
    let bytes = 0;
    for (const p of parsed.packets) {
      const d = decodePacket(parsed.linktype, p.data);
      if (d.error || !d.src) continue;
      const ab = d.src === a && (d.srcPort || 0) === ap && d.dst === b && (d.dstPort || 0) === bp;
      const ba = d.src === b && (d.srcPort || 0) === bp && d.dst === a && (d.dstPort || 0) === ap;
      if (!ab && !ba) continue;
      bytes += p.len;
      const app = decodeAppPayload(d.payload);
      segments.push({
        no: p.no, tsMs: p.tsMs, dir: ab ? 'ab' : 'ba', len: p.len,
        payloadLen: d.payload ? d.payload.length : 0,
        flags: d.tcpFlags || '', summary: d.summary || '',
        kind: app ? app.kind : '',
        text: app ? (app.text.length > 8192 ? app.text.slice(0, 8192) + '\n… 已截断' : app.text) : '',
      });
    }
    if (!segments.length) return { error: '该对话在本次抓包中没有报文' };
    const start = segments[0].tsMs;
    return {
      a, ap, b, bp,
      segCount: segments.length,
      bytes,
      durationMs: segments[segments.length - 1].tsMs - start,
      segments: segments.map(s => ({ ...s, dtMs: s.tsMs - start })),
    };
  }
}

// 显示过滤（Wireshark 简化版）：空格分隔的 token，全部满足（AND）才算命中
// ip:1.2.3.4（src 或 dst）· port:3306 · tcp/udp/icmp · syn/ack/psh/fin/rst/urg
// has:payload（有载荷）· json / text（载荷解码类型）· text:关键字（载荷文本包含）
// 其余裸词：对 来源/目标/摘要/载荷文本 做包含匹配；未知 key:value 一律不匹配
const FLAG_TOKENS = { syn: 'S', ack: 'A', psh: 'P', fin: 'F', rst: 'R', urg: 'U' };
function matchPktFilter(p, q) {
  const s = String(q || '').trim();
  if (!s) return true;
  for (const raw of s.split(/\s+/)) {
    const t = raw.toLowerCase();
    let ok;
    if (/^ip:/i.test(raw)) {
      const v = raw.slice(3);
      ok = p.src === v || p.dst === v;
    } else if (/^port:/i.test(raw)) {
      const n = Number(raw.slice(5));
      ok = Number.isInteger(n) && (p.srcPort === n || p.dstPort === n);
    } else if (/^text:/i.test(raw)) {
      ok = (p.payloadText || '').toLowerCase().includes(t.slice(5));
    } else if (t === 'has:payload' || t === 'payload') {
      ok = (p.payloadLen || 0) > 0;
    } else if (t === 'json' || t === 'text') {
      ok = p.payloadKind === t;
    } else if (t === 'icmp' || t === 'icmp6') {
      ok = p.proto === 'icmp';
    } else if (t === 'tcp' || t === 'udp') {
      ok = p.proto === t;
    } else if (FLAG_TOKENS[t]) {
      ok = p.proto === 'tcp' && (p.tcpFlags || '').includes(FLAG_TOKENS[t]);
    } else if (t.includes(':')) {
      ok = false;
    } else {
      ok = p.src.toLowerCase().includes(t) || p.dst.toLowerCase().includes(t)
        || (p.summary || '').toLowerCase().includes(t)
        || (p.payloadText || '').toLowerCase().includes(t);
    }
    if (!ok) return false;
  }
  return true;
}

function buildBpf({ ip, port, proto }) {
  const parts = [];
  // host 双向匹配（类 Wireshark 的 ip.addr）：填服务器 IP 或客户端 IP 都能抓到完整往返流量
  if (ip) parts.push(`host ${ip}`);
  if (port) parts.push(`port ${port}`);
  if (proto) parts.push(proto === 'icmp' ? 'icmp or icmp6' : proto);
  return parts.join(' and ');
}

// 页面「管理主机」提交的远程主机信息校验与规范化；有错抛出。
// 编辑（existing 存在）时密码留空 = 保持原密码
function validateRemoteHost(input, { existing = null, names = [] } = {}) {
  const name = String(input.name || '').trim();
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)) throw new Error('名称限 1-32 位字母/数字/-/_');
  if ((!existing || name !== existing.name) && names.includes(name)) throw new Error(`名称 ${name} 已存在`);
  const host = String(input.host || '').trim();
  if (!/^[A-Za-z0-9._-]{1,253}$/.test(host)) throw new Error('主机应为合法 IP 或域名');
  const port = Number(input.port) || 22;
  if (!(Number.isInteger(port) && port >= 1 && port <= 65535)) throw new Error('端口不合法');
  const user = String(input.user || '').trim();
  if (!/^[\w.@-]{1,64}$/.test(user)) throw new Error('用户名不合法');
  const password = String(input.password || '');
  if (password.length > 128) throw new Error('密码过长');
  const keyFile = String(input.keyFile || '').trim();
  if (!password && !(existing && existing.password) && !keyFile && !(existing && existing.keyFile)) {
    throw new Error('密码与密钥至少配一项');
  }
  const out = { name, host, port, user, tcpdumpBin: input.tcpdumpBin || (existing && existing.tcpdumpBin) || 'tcpdump' };
  if (keyFile) out.keyFile = keyFile;
  else if (existing && existing.keyFile) out.keyFile = existing.keyFile;
  if (password) out.password = password;
  else if (existing && existing.password) out.password = existing.password;
  return out;
}

// 应用层载荷智能解码：JSON 直接格式化、可读文本直接显示，二进制返回 null（走 hex 视图）
function decodeAppPayload(payload) {
  if (!payload || !payload.length || payload.length > 262144) return null;
  const s = payload.toString('utf8');
  const trimmed = s.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return { kind: 'json', text: JSON.stringify(JSON.parse(trimmed), null, 2) };
    } catch (_e) { /* 非合法 JSON，继续按文本/二进制判定 */ }
  }
  let bad = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0xfffd || (c < 32 && c !== 9 && c !== 10 && c !== 13)) bad++;
  }
  if (bad / s.length <= 0.1) {
    return { kind: 'text', text: s.length > 65536 ? s.slice(0, 65536) + `\n… 已截断，共 ${s.length} 字符` : s };
  }
  return null;
}

module.exports = { CaptureManager, validIp, buildBpf, validateRemoteHost, decodeAppPayload, matchPktFilter };
