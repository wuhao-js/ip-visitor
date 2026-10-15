'use strict';

// ---------- 工具 ----------
async function api(path, opts = {}) {
  if (opts.body) opts.headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const r = await fetch(path, opts);
  if (r.status === 401) { location.href = '/login.html'; throw new Error('unauthorized'); }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || ('HTTP ' + r.status));
  return r.json();
}

// 底部通知条：isErr 红色且停留更久
function toast(msg, isErr) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show' + (isErr ? ' err' : '');
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => t.classList.remove('show'), isErr ? 6000 : 3500);
}

function fmtTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts);
  const p = (n, w) => String(n).padStart(w || 2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function fmtSize(n) {
  if (!n) return '0 B';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

function fmtDuration(ms) {
  if (ms == null || ms <= 0) return '-';
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}天${h}小时`;
  if (h > 0) return `${h}小时${m}分`;
  if (m > 0) return `${m}分${s % 60}秒`;
  return `${s}秒`;
}

function fmtFreq(freq, durMs) {
  if (!freq) return '-';
  return durMs >= 60000 ? `${freq} 次/分` : `${freq} 次（<1分钟）`;
}

const PROTO_BADGE = { tcp: 'tcp', udp: 'udp', icmp: 'icmp' };
function protoBadge(el, proto) {
  el.textContent = proto.toUpperCase();
  el.className = 'badge ' + (PROTO_BADGE[proto] || 'other');
}

function cell(tr, text) {
  const td = document.createElement('td');
  td.textContent = text == null ? '-' : String(text);
  tr.appendChild(td);
  return td;
}

function recordRow(rec, withIp) {
  const tr = document.createElement('tr');
  cell(tr, fmtTime(rec.ts));
  if (withIp) cell(tr, rec.srcIp);
  const td = document.createElement('td');
  protoBadge(td, rec.proto);
  tr.appendChild(td);
  cell(tr, rec.dstPort ? svcLabel(rec.dstPort) : '-');
  cell(tr, rec.bytes || 0);
  return tr;
}

// ---------- 页签 ----------
document.querySelectorAll('nav .tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav .tab').forEach(b => b.classList.toggle('active', b === btn));
    document.querySelectorAll('.tabpane').forEach(p => p.classList.toggle('active', p.id === 'tab-' + btn.dataset.tab));
    if (btn.dataset.tab === 'history') loadHistory();
    if (btn.dataset.tab === 'clients') loadClients();
    if (btn.dataset.tab === 'capture') loadCaptures();
    if (btn.dataset.tab === 'live') refreshOverview();
  });
});

// ---------- 概览：趋势图 + Top ----------
let lastTrend = [];
function drawTrend(trend) {
  if (trend) lastTrend = trend;
  const canvas = document.getElementById('trend-canvas');
  if (!canvas.clientWidth) return; // 面板隐藏时不画，切回时 refreshOverview 会重画
  // 按 devicePixelRatio 放大画布实际像素再缩回 CSS 尺寸，高分屏下才清晰
  const dpr = window.devicePixelRatio || 1;
  const W = canvas.clientWidth;
  const H = 150;
  if (canvas.width !== Math.round(W * dpr) || canvas.height !== Math.round(H * dpr)) {
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const PAD = 24, PADB = 18;
  ctx.clearRect(0, 0, W, H);
  const nowHour = Math.floor(Date.now() / 3600000) * 3600000;
  const buckets = [];
  for (let i = 23; i >= 0; i--) {
    const t = nowHour - i * 3600000;
    const hit = lastTrend.find(x => x.t === t);
    buckets.push({ t, c: hit ? hit.c : 0 });
  }
  const max = Math.max(1, ...buckets.map(b => b.c));
  const bw = (W - PAD * 2) / 24;
  ctx.font = '11px sans-serif';
  buckets.forEach((b, i) => {
    const h = Math.round((b.c / max) * (H - PAD - PADB));
    const x = PAD + i * bw + 2;
    ctx.fillStyle = b.c ? '#4f7cff' : '#e5e6eb';
    ctx.fillRect(x, H - PADB - h, bw - 4, h);
    if (b.c) {
      ctx.fillStyle = '#4e5969';
      ctx.fillText(String(b.c), x, H - PADB - h - 3);
    }
    if (i % 4 === 0) {
      ctx.fillStyle = '#86909c';
      const d = new Date(b.t);
      ctx.fillText(`${String(d.getHours()).padStart(2, '0')}:00`, x, H - 4);
    }
  });
}
window.addEventListener('resize', () => drawTrend());

function renderTopList(el, items, textFn) {
  el.textContent = '';
  const max = Math.max(1, ...items.map(i => i.c));
  if (!items.length) {
    const d = document.createElement('div');
    d.className = 'muted'; d.textContent = '暂无数据';
    el.appendChild(d);
    return;
  }
  for (const it of items) {
    const row = document.createElement('div');
    row.className = 'toprow';
    const bar = document.createElement('div');
    bar.className = 'topbar';
    bar.style.width = Math.max(4, Math.round((it.c / max) * 100)) + '%';
    const label = document.createElement('span');
    label.textContent = textFn(it);
    row.appendChild(bar);
    row.appendChild(label);
    el.appendChild(row);
  }
}

async function refreshOverview() {
  try {
    const o = await api('/api/overview');
    document.getElementById('hd-clients').textContent = o.clients24h;
    document.getElementById('hd-packets').textContent = o.packets24h;
    drawTrend(o.trend || []);
    renderTopList(document.getElementById('top-clients'), o.topClients || [], it => `${it.ip} (${it.c})`);
    renderTopList(document.getElementById('top-ports'), o.topPorts || [], it => `${svcLabel(it.port)} (${it.c})`);
  } catch (_e) { /* ignore */ }
}

// ---------- 告警 ----------
const alertsPanel = document.getElementById('alerts-panel');
const alertDot = document.getElementById('alert-dot');
let unreadAlerts = 0;

function alertRow(a) {
  const tr = document.createElement('tr');
  cell(tr, fmtTime(a.ts));
  const td = document.createElement('td');
  td.textContent = a.type === 'port_scan' ? '⚠ 疑似扫描' : (a.type === 'test' ? '测试' : '🆕 新来访');
  td.className = a.type === 'port_scan' ? 'alert-scan' : 'alert-new';
  tr.appendChild(td);
  cell(tr, a.ip);
  cell(tr, a.detail);
  return tr;
}

async function loadAlerts() {
  try {
    const list = await api('/api/alerts?limit=50');
    const tb = document.getElementById('alerts-tbody');
    tb.textContent = '';
    for (const a of list) tb.appendChild(alertRow(a));
  } catch (_e) { /* ignore */ }
}

function showNewAlert(a) {
  unreadAlerts += 1;
  alertDot.classList.remove('hidden');
  alertDot.title = `${unreadAlerts} 条新告警：${a.ip} ${a.detail}`;
  if (!alertsPanel.classList.contains('hidden')) loadAlerts();
}

alertDot.addEventListener('click', () => {
  alertsPanel.classList.toggle('hidden');
  unreadAlerts = 0;
  alertDot.classList.add('hidden');
  loadAlerts();
});
document.getElementById('alerts-close').addEventListener('click', () => alertsPanel.classList.add('hidden'));
document.getElementById('alerts-test').addEventListener('click', async () => {
  try {
    await api('/api/alerts/test', { method: 'POST' });
    toast('测试告警已发送（页面红点与 webhook 链路一致）');
    setTimeout(loadAlerts, 300);
  } catch (err) { toast(err.message, true); }
});

// ---------- 实时 ----------
const liveTbody = document.getElementById('live-tbody');
const liveState = document.getElementById('live-state');
const liveDot = document.getElementById('live-dot');
const liveCount = document.getElementById('live-count');
let liveReceived = 0;

document.getElementById('btn-clear-live').addEventListener('click', () => {
  liveTbody.textContent = '';
  liveReceived = 0;
  liveCount.textContent = '已接收 0 条';
});

function addLiveRecord(rec) {
  const tr = recordRow(rec, true);
  liveTbody.insertBefore(tr, liveTbody.firstChild);
  while (liveTbody.children.length > 200) liveTbody.removeChild(liveTbody.lastChild);
  liveReceived += 1;
  liveCount.textContent = `已接收 ${liveReceived} 条`;
}

function connectSSE() {
  const es = new EventSource('/api/stream');
  es.addEventListener('open', () => { liveDot.className = 'live-dot on'; liveState.textContent = '实时连接中'; });
  es.addEventListener('record', (e) => {
    try { addLiveRecord(JSON.parse(e.data)); } catch (_err) { /* ignore */ }
  });
  es.addEventListener('alert', (e) => {
    try { showNewAlert(JSON.parse(e.data)); } catch (_err) { /* ignore */ }
  });
  es.addEventListener('error', () => { liveDot.className = 'live-dot off'; liveState.textContent = '连接断开，自动重连…'; });
}

// ---------- 历史 ----------
const histForm = document.getElementById('hist-form');
const histTbody = document.getElementById('hist-tbody');
let histPage = 1;

function histQuery() {
  const fd = new FormData(histForm);
  const q = new URLSearchParams();
  for (const k of ['ip', 'port', 'proto']) {
    const v = (fd.get(k) || '').trim();
    if (v) q.set(k, v);
  }
  const from = fd.get('from'), to = fd.get('to');
  if (from) q.set('from', String(new Date(from).getTime()));
  if (to) q.set('to', String(new Date(to).getTime()));
  q.set('page', String(histPage));
  q.set('size', '50');
  return '/api/records?' + q.toString();
}

async function loadHistory() {
  try {
    const data = await api(histQuery());
    histTbody.textContent = '';
    if (!data.rows.length) {
      const tr = document.createElement('tr');
      const td = cell(tr, '无匹配记录');
      td.colSpan = 5; td.style.color = '#86909c';
      histTbody.appendChild(tr);
    }
    for (const rec of data.rows) histTbody.appendChild(recordRow(rec, true));
    const pages = Math.max(1, Math.ceil(data.total / data.size));
    histPage = Math.min(histPage, pages);
    document.getElementById('hist-total').textContent = `共 ${data.total} 条`;
    document.getElementById('hist-page').textContent = `${histPage} / ${pages}`;
  } catch (_e) { /* ignore */ }
}

histForm.addEventListener('submit', (e) => { e.preventDefault(); histPage = 1; loadHistory(); });
document.getElementById('hist-reset').addEventListener('click', () => { histForm.reset(); histPage = 1; loadHistory(); });
document.getElementById('hist-prev').addEventListener('click', () => { if (histPage > 1) { histPage--; loadHistory(); } });
document.getElementById('hist-next').addEventListener('click', () => { histPage++; loadHistory(); });

// ---------- 客户端统计 ----------
const clTbody = document.getElementById('cl-tbody');
const clDetail = document.getElementById('cl-detail');
let clCurrentFrom = null;
let clCurrentDetailIp = '';

function behaviorCell(tr, c) {
  const td = document.createElement('td');
  if (c.scanPorts) {
    td.textContent = `⚠ 疑似端口扫描`;
    td.className = 'alert-scan';
    td.title = `${c.scanWindowMin || 10} 分钟内试探了 ${c.scanPorts} 个不同端口`;
  } else if (c.byProto.icmp && c.byProto.icmp === c.count) {
    td.textContent = 'ICMP 探测';
  } else {
    const top = c.ports.slice(0, 2).map(p => svcLabel(p.port)).join(', ');
    td.textContent = top ? `访问 ${top}` : '-';
  }
  if (c.isNew) {
    const tag = document.createElement('span');
    tag.textContent = ' 新';
    tag.className = 'alert-new';
    td.appendChild(tag);
  }
  tr.appendChild(td);
}

async function loadClients() {
  clCurrentFrom = clFrom();
  const q = clCurrentFrom ? '?from=' + clCurrentFrom : '';
  try {
    const list = await api('/api/clients' + q);
    clTbody.textContent = '';
    for (const c of list) {
      const tr = document.createElement('tr');
      tr.className = 'clickable';
      tr.addEventListener('click', () => showClientDetail(c.ip));
      cell(tr, c.ip);
      behaviorCell(tr, c);
      cell(tr, c.count);
      cell(tr, fmtDuration(c.durationMs));
      cell(tr, fmtFreq(c.freqPerMin, c.durationMs));
      cell(tr, fmtTime(c.firstTs));
      cell(tr, fmtTime(c.lastTs));
      const portsText = c.ports.map(p => `${svcLabel(p.port)}×${p.count}`).join(', ');
      const td = cell(tr, `${portsText}  —  ${c.portCount} 个端口`);
      td.title = portsText;
      clTbody.appendChild(tr);
    }
    if (!list.length) {
      const tr = document.createElement('tr');
      const td = cell(tr, '暂无数据');
      td.colSpan = 8; td.style.color = '#86909c';
      clTbody.appendChild(tr);
    }
  } catch (_e) { /* ignore */ }
}

async function showClientDetail(ip) {
  const q = clCurrentFrom ? '?from=' + clCurrentFrom : '';
  try {
    const d = await api('/api/clients/' + encodeURIComponent(ip) + q);
    clDetail.classList.remove('hidden');
    clCurrentDetailIp = d.ip;
    document.getElementById('cl-detail-ip').textContent = `${d.ip} — 共 ${d.count} 次，持续 ${fmtDuration(d.durationMs)}`;
    const portsTb = document.getElementById('cl-detail-ports');
    portsTb.textContent = '';
    for (const p of d.ports) {
      const tr = document.createElement('tr');
      cell(tr, svcLabel(p.port));
      const td = document.createElement('td');
      protoBadge(td, p.proto);
      tr.appendChild(td);
      cell(tr, p.count);
      cell(tr, fmtTime(p.firstTs));
      cell(tr, fmtTime(p.lastTs));
      portsTb.appendChild(tr);
    }
    const recTb = document.getElementById('cl-detail-recent');
    recTb.textContent = '';
    for (const rec of d.recent) {
      const tr = document.createElement('tr');
      cell(tr, fmtTime(rec.ts));
      const td = document.createElement('td');
      protoBadge(td, rec.proto);
      tr.appendChild(td);
      cell(tr, rec.dstPort ? svcLabel(rec.dstPort) : '-');
      cell(tr, rec.bytes || 0);
      recTb.appendChild(tr);
    }
    clDetail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } catch (_e) { /* ignore */ }
}

document.getElementById('cl-refresh').addEventListener('click', loadClients);
document.getElementById('cl-detail-close').addEventListener('click', () => clDetail.classList.add('hidden'));
document.getElementById('cl-range').addEventListener('change', loadClients);
document.getElementById('cl-detail-capture').addEventListener('click', () => {
  document.querySelector('#cap-form input[name=ip]').value = clCurrentDetailIp;
  document.querySelector('nav .tab[data-tab=capture]').click();
});

// ---------- 抓包诊断 ----------
const capTbody = document.getElementById('cap-tbody');
const pktPanel = document.getElementById('pkt-panel');
let capRefreshTimer = null;
let capHosts = [];
const capPrevStatus = new Map(); // 上轮轮询的任务状态，用于检测 running→done/error 转变
let pktPage = 1;
let pktCurrentId = 0;
let pktQ = '';
let pktSelectedNo = 0;
let pktDetailData = null; // 当前详情包数据，供复制按钮使用

async function loadCaptureHosts() {
  try {
    capHosts = await api('/api/captures/hosts');
    const sel = document.getElementById('cap-target');
    sel.textContent = '';
    for (const h of capHosts) {
      const opt = document.createElement('option');
      opt.value = h.name;
      opt.textContent = h.label;
      sel.appendChild(opt);
    }
    const hint = document.getElementById('cap-remote-hint');
    if (hint) {
      hint.textContent = capHosts.length <= 1
        ? ' 下拉只有「本机」？点「管理主机」直接添加要抓包的服务器，保存即生效，无需改配置文件。'
        : '';
    }
  } catch (_e) { /* ignore */ }
}

function hostLabel(name) {
  const h = capHosts.find(x => x.name === name);
  return h ? h.label : (name === 'local' ? '本机' : name);
}

// ---- 远程主机管理 ----
async function loadRemoteHosts() {
  try {
    const list = await api('/api/remote-hosts');
    const tb = document.getElementById('hosts-tbody');
    tb.textContent = '';
    if (!list.length) {
      const tr = document.createElement('tr');
      const td = cell(tr, '还没有远程主机，用上方表单添加');
      td.colSpan = 6; td.style.color = '#86909c';
      tb.appendChild(tr);
      return;
    }
    for (const h of list) {
      const tr = document.createElement('tr');
      cell(tr, h.name);
      cell(tr, h.host);
      cell(tr, h.port);
      cell(tr, h.user);
      cell(tr, h.hasPassword ? '密码' : (h.keyFile ? '密钥' : '-'));
      const op = document.createElement('td');
      const edit = document.createElement('button');
      edit.className = 'ghost';
      edit.textContent = '编辑';
      edit.addEventListener('click', () => {
        const f = document.getElementById('host-form');
        f.origName.value = h.name;
        f.name.value = h.name;
        f.host.value = h.host;
        f.port.value = h.port;
        f.user.value = h.user;
        f.password.value = '';
        document.getElementById('host-cancel').classList.remove('hidden');
        f.name.focus();
      });
      op.appendChild(edit);
      const del = document.createElement('button');
      del.className = 'ghost';
      del.textContent = '删除';
      del.addEventListener('click', async () => {
        if (!confirm(`删除远程主机 ${h.name}(${h.host})？`)) return;
        try {
          await api('/api/remote-hosts/' + encodeURIComponent(h.name), { method: 'DELETE' });
          toast(`已删除主机 ${h.name}`);
          loadRemoteHosts();
          loadCaptureHosts();
        } catch (err) {
          toast(err.message, true);
        }
      });
      op.appendChild(del);
      tr.appendChild(op);
      tb.appendChild(tr);
    }
  } catch (_e) { /* ignore */ }
}

function resetHostForm() {
  const f = document.getElementById('host-form');
  f.reset();
  f.origName.value = '';
  document.getElementById('host-cancel').classList.add('hidden');
}

document.getElementById('hosts-mgr').addEventListener('click', () => {
  const p = document.getElementById('hosts-panel');
  p.classList.toggle('hidden');
  if (!p.classList.contains('hidden')) loadRemoteHosts();
});
document.getElementById('hosts-close').addEventListener('click', () => document.getElementById('hosts-panel').classList.add('hidden'));
document.getElementById('host-cancel').addEventListener('click', resetHostForm);
document.getElementById('host-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const body = {
    origName: f.origName.value,
    name: f.name.value.trim(),
    host: f.host.value.trim(),
    port: Number(f.port.value) || 22,
    user: f.user.value.trim(),
    password: f.password.value,
  };
  try {
    await api('/api/remote-hosts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    toast(body.origName ? `主机 ${body.name} 已更新` : `主机 ${body.name} 已添加，可在「目标」下拉选择`);
    resetHostForm();
    loadRemoteHosts();
    loadCaptureHosts();
  } catch (err) {
    toast(err.message, true);
  }
});

function capRow(c) {
  const tr = document.createElement('tr');
  cell(tr, '#' + c.id);
  cell(tr, hostLabel(c.target));
  const ft = document.createElement('td');
  ft.textContent = c.filter || '(无过滤)';
  if (c.error) { ft.textContent += ` — ${c.error}`; ft.className = 'alert-scan'; }
  tr.appendChild(ft);
  cell(tr, c.seconds + ' 秒');
  cell(tr, fmtTime(c.startedTs));
  const st = document.createElement('td');
  st.textContent = c.status === 'running' ? '抓包中…' : (c.status === 'done' ? '已完成' : '失败');
  st.className = c.status === 'running' ? 'alert-new' : (c.status === 'error' ? 'alert-scan' : '');
  tr.appendChild(st);
  cell(tr, fmtSize(c.size));
  const op = document.createElement('td');
  if (c.status === 'done') {
    const view = document.createElement('button');
    view.className = 'ghost';
    view.textContent = '查看报文';
    view.addEventListener('click', () => { openPackets(c.id); });
    op.appendChild(view);
    const a = document.createElement('a');
    a.href = `/api/captures/download?id=${c.id}`;
    a.textContent = ' 下载 pcap';
    op.appendChild(a);
  }
  tr.appendChild(op);
  return tr;
}

async function loadCaptures() {
  try {
    const list = await api('/api/captures');
    capTbody.textContent = '';
    let running = false;
    for (const c of list) {
      capTbody.appendChild(capRow(c));
      if (c.status === 'running') running = true;
      // 检测上一轮轮询时还在跑的任务结束与否，给出结果反馈
      const prev = capPrevStatus.get(c.id);
      if (prev === 'running' && c.status === 'done') {
        stopCapCountdown();
        toast(`抓包 #${c.id} 完成，已打开报文列表`);
        pktPage = 1; openPackets(c.id);
        document.querySelector('nav .tab[data-tab=capture]').click();
      } else if (prev === 'running' && c.status === 'error') {
        stopCapCountdown();
        toast(`抓包 #${c.id} 失败：${c.error || '未知错误'}`, true);
      }
      capPrevStatus.set(c.id, c.status);
    }
    if (!list.length) {
      const tr = document.createElement('tr');
      const td = cell(tr, '暂无抓包任务');
      td.colSpan = 8; td.style.color = '#86909c';
      capTbody.appendChild(tr);
    }
    document.getElementById('cap-stop').style.display = running ? '' : 'none';
    clearTimeout(capRefreshTimer);
    if (running) capRefreshTimer = setTimeout(loadCaptures, 2000);
  } catch (_e) { /* ignore */ }
}

// 抓包按钮倒计时：期间禁用并显示剩余秒数
let capCountdownTimer = null;
function startCapCountdown(secs) {
  stopCapCountdown();
  const btn = document.getElementById('cap-start');
  let left = secs;
  capCountdownTimer = setInterval(() => {
    btn.textContent = left > 0 ? `抓包中 ${left}s` : '开始抓包';
    if (left <= 0) {
      clearInterval(capCountdownTimer);
      capCountdownTimer = null;
      btn.disabled = false;
    }
    left--;
  }, 1000);
  btn.textContent = `抓包中 ${left}s`;
  btn.disabled = true;
  left--;
}
function stopCapCountdown() {
  if (capCountdownTimer) { clearInterval(capCountdownTimer); capCountdownTimer = null; }
  const btn = document.getElementById('cap-start');
  btn.disabled = false;
  btn.textContent = '开始抓包';
}

// ---- 报文查看器（三栏：包列表 → 显示过滤 → 详情/载荷/字节）----
const TCP_FLAG_NAMES = { S: 'SYN', A: 'ACK', P: 'PSH', F: 'FIN', R: 'RST', U: 'URG' };

function pktSummary(p) {
  if (p.error) return p.error;
  let s;
  if (p.proto === 'tcp') s = `Flags [${p.tcpFlags || '.'}]`;
  else if (p.proto === 'icmp') s = p.summary || 'ICMP';
  else if (p.proto === 'udp') s = 'UDP';
  else s = p.proto;
  if (p.payloadKind === 'json') s += ' · JSON';
  else if (p.payloadKind === 'text') s += ' · 文本';
  if (p.payloadLen > 0) s += ` · ${p.payloadLen}B`;
  return s;
}

async function selectPacket(p) {
  pktSelectedNo = p.no;
  document.querySelectorAll('#pkt-tbody tr').forEach(tr => tr.classList.toggle('sel', Number(tr.dataset.no) === p.no));
  const box = document.getElementById('pkt-detail');
  box.classList.remove('hidden');
  document.getElementById('pd-title').textContent = `加载中…`;
  try {
    const d = await api(`/api/captures/packet?id=${pktCurrentId}&no=${p.no}`);
    pktDetailData = d;
    renderPacketDetail(d);
  } catch (err) {
    pktDetailData = null;
    document.getElementById('pd-title').textContent = `#${p.no} 加载失败`;
    toast(err.message, true);
  }
}

function pdItem(label, value) {
  const div = document.createElement('div');
  div.className = 'pd-item';
  const k = document.createElement('span');
  k.className = 'pd-k';
  k.textContent = label;
  const v = document.createElement('span');
  v.className = 'pd-v';
  v.textContent = value;
  div.append(k, v);
  return div;
}

function renderPacketDetail(d) {
  document.getElementById('pd-title').textContent =
    `#${d.no}  ${d.src}${d.srcPort ? ':' + d.srcPort : ''} → ${d.dst}${d.dstPort ? ':' + d.dstPort : ''}`;
  const grid = document.getElementById('pd-grid');
  grid.textContent = '';
  grid.appendChild(pdItem('时间', fmtTime(d.tsMs)));
  grid.appendChild(pdItem('帧长度', `${d.len} 字节`));
  grid.appendChild(pdItem('协议', d.proto.toUpperCase()));
  if (d.proto === 'tcp') {
    grid.appendChild(pdItem('TCP 标志', (d.tcpFlags || '').split('').map(f => TCP_FLAG_NAMES[f] || f).join(' + ') || '-'));
    grid.appendChild(pdItem('SEQ / ACK', `seq=${d.tcpSeq} ack=${d.tcpAck}`));
    grid.appendChild(pdItem('窗口', String(d.tcpWin)));
  }
  if (d.proto === 'icmp') grid.appendChild(pdItem('类型', d.summary || '-'));
  grid.appendChild(pdItem('载荷', d.payloadLen > 0 ? `${d.payloadLen} 字节${d.payloadKind ? `（${d.payloadKind === 'json' ? 'JSON' : '文本'}）` : '（二进制）'}` : '无'));
  if (d.error) grid.appendChild(pdItem('解码异常', d.error));
  const pay = document.getElementById('pd-payload');
  if (d.payloadLen <= 0) {
    pay.textContent = '（无应用层载荷）';
  } else if (d.payloadKind === 'json') {
    pay.textContent = d.payloadText;
  } else if (d.payloadKind === 'text') {
    pay.textContent = d.payloadText;
  } else {
    pay.textContent = `（二进制载荷 ${d.payloadLen} 字节，内容见下方原始字节）`;
  }
  document.getElementById('pkt-hex').textContent = d.hex || '(空)';
  document.getElementById('pd-copy').style.display = d.payloadText ? '' : 'none';
}

function pktRow(p) {
  const tr = document.createElement('tr');
  tr.className = 'clickable';
  tr.dataset.no = p.no;
  if (p.no === pktSelectedNo) tr.classList.add('sel');
  tr.addEventListener('click', () => selectPacket(p));
  cell(tr, p.no);
  cell(tr, fmtTime(p.tsMs));
  cell(tr, p.src + (p.srcPort ? ':' + p.srcPort : ''));
  cell(tr, p.dst + (p.dstPort ? ':' + p.dstPort : ''));
  const td = document.createElement('td');
  protoBadge(td, p.proto === 'proto-0' ? 'other' : p.proto);
  tr.appendChild(td);
  cell(tr, p.dstPort || (p.srcPort ? p.srcPort : '-'));
  cell(tr, pktSummary(p));
  cell(tr, p.len);
  return tr;
}

// 打开某个抓包的报文视图：重置过滤/选中/详情
function openPackets(id) {
  pktCurrentId = id;
  pktPage = 1;
  pktQ = '';
  pktSelectedNo = 0;
  pktDetailData = null;
  document.getElementById('pkt-filter').value = '';
  document.getElementById('pkt-match').textContent = '';
  document.getElementById('pkt-detail').classList.add('hidden');
  showPackets();
}

// 摘要标签点击 = 应用为过滤条件（类 Wireshark 的 Apply as Filter）
function applyPktFilter(q) {
  const input = document.getElementById('pkt-filter');
  if (q) {
    const cur = input.value.trim();
    if (!cur.includes(q)) input.value = cur ? `${cur} ${q}` : q;
  }
  pktQ = input.value.trim();
  pktPage = 1;
  pktSelectedNo = 0;
  pktDetailData = null;
  document.getElementById('pkt-detail').classList.add('hidden');
  showPackets();
}

function renderPktAnalysis(an) {
  const el = document.getElementById('pkt-analysis');
  el.textContent = '';
  if (!an || an.error) return;
  const head = document.createElement('div');
  head.className = 'pa-line';
  const secs = an.durationMs ? (an.durationMs / 1000).toFixed(1) + ' 秒' : '—';
  head.textContent = `共 ${an.total} 包 / ${fmtSize(an.bytes)} · ${an.srcCount} 个来源 · 时长 ${secs}` +
    (an.pps ? ` · 平均 ${an.pps} 包/秒` : '');
  if (an.badPackets) head.textContent += ` · ${an.badPackets} 包无法解码`;
  if (an.truncated) head.textContent += ' · 末尾截断（停止时最后一个包不完整，已忽略）';
  el.appendChild(head);
  // 点标签 → 直接生成过滤条件
  const chipRow = (label, items, fmt, qf) => {
    if (!items || !items.length) return;
    const row = document.createElement('div');
    row.className = 'pa-row';
    const t = document.createElement('span');
    t.className = 'pa-label';
    t.textContent = label;
    row.appendChild(t);
    for (const it of items) {
      const chip = document.createElement('span');
      chip.className = 'pa-chip';
      chip.textContent = fmt(it);
      chip.title = '点击按此条件过滤';
      chip.style.cursor = 'pointer';
      chip.addEventListener('click', () => applyPktFilter(qf(it)));
      row.appendChild(chip);
    }
    el.appendChild(row);
  };
  chipRow('协议', an.protoList, it => `${it.k} ×${it.c}`, it => it.k);
  chipRow('TCP 标志', an.flagsList, it => `${TCP_FLAG_NAMES[it.k] || it.k} ×${it.c}`,
    it => ({ S: 'syn', A: 'ack', P: 'psh', F: 'fin', R: 'rst', U: 'urg' }[it.k] || ''));
  chipRow('Top端口', an.topPorts, it => `${svcLabel(Number(it.k))} ×${it.c}`, it => `port:${it.k}`);
  chipRow('Top来源', an.topSrcs, it => `${it.k} ×${it.c}`, it => `ip:${it.k}`);
  chipRow('对话', an.topConvs, it => `${it.k} ×${it.c}`, it => {
    const m = String(it.k).match(/^(\S+):(\d+)\s*→\s*(\S+):(\d+)$/);
    if (!m) return '';
    return `ip:${m[1]} ip:${m[3]} port:${m[4]}`;
  });
}

async function showPackets() {
  try {
    const [r, an] = await Promise.all([
      api(`/api/captures/packets?id=${pktCurrentId}&page=${pktPage}&size=50&q=${encodeURIComponent(pktQ)}`),
      api(`/api/captures/analyze?id=${pktCurrentId}`).catch(() => null),
    ]);
    pktPanel.classList.remove('hidden');
    document.getElementById('pkt-title').textContent = `抓包 #${pktCurrentId} 报文（${hostLabel(r.target)} — ${r.filter || '无过滤'}）`;
    const tb = document.getElementById('pkt-tbody');
    tb.textContent = '';
    for (const p of r.packets) tb.appendChild(pktRow(p));
    if (!r.packets.length) {
      const tr = document.createElement('tr');
      const td = cell(tr, pktQ ? '没有匹配的包（可点「清除」查看全部）' : '没有抓到包（过滤条件太严或期间无匹配流量）');
      td.colSpan = 8; td.style.color = '#86909c';
      tb.appendChild(tr);
    }
    const pages = Math.max(1, Math.ceil(r.matched / r.size));
    document.getElementById('pkt-total').textContent = `共 ${r.total} 包`;
    document.getElementById('pkt-match').textContent = pktQ ? `匹配 ${r.matched} / ${r.total} 包` : '';
    document.getElementById('pkt-page').textContent = `${pktPage} / ${pages}`;
    renderPktAnalysis(an);
  } catch (err) {
    toast(err.message, true);
  }
}

document.getElementById('pkt-close').addEventListener('click', () => pktPanel.classList.add('hidden'));
document.getElementById('cap-stop').addEventListener('click', async () => {
  try {
    await api('/api/captures/stop', { method: 'POST' });
    toast('已发送停止指令，抓包收尾中…');
    setTimeout(loadCaptures, 600);
  } catch (err) {
    toast(err.message, true);
  }
});
document.getElementById('pkt-prev').addEventListener('click', () => { if (pktPage > 1) { pktPage--; showPackets(); } });
document.getElementById('pkt-next').addEventListener('click', () => { pktPage++; showPackets(); });

// ---- 显示过滤栏 ----
document.getElementById('pkt-filter-go').addEventListener('click', () => applyPktFilter(''));
document.getElementById('pkt-filter').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') applyPktFilter('');
});
document.getElementById('pkt-filter-clear').addEventListener('click', () => {
  document.getElementById('pkt-filter').value = '';
  applyPktFilter('');
});
document.querySelectorAll('.f-chip').forEach(btn => {
  btn.addEventListener('click', () => {
    document.getElementById('pkt-filter').value = btn.dataset.q || '';
    applyPktFilter('');
  });
});

// 复制载荷文本
document.getElementById('pd-copy').addEventListener('click', async () => {
  if (!pktDetailData || !pktDetailData.payloadText) return;
  try {
    await navigator.clipboard.writeText(pktDetailData.payloadText);
    toast('载荷已复制到剪贴板');
  } catch (_e) {
    toast('复制失败（浏览器拒绝剪贴板权限）', true);
  }
});

document.getElementById('cap-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const target = fd.get('target') || 'local';
  const ip = (fd.get('ip') || '').trim();
  const port = (fd.get('port') || '').trim();
  const proto = fd.get('proto') || '';
  const seconds = Number(fd.get('seconds')) || 60;
  if (!ip && !port && !proto) {
    toast('请至少填写 来源IP / 端口 / 协议 之一，避免全量抓包撑爆磁盘', true);
    return;
  }
  const btn = document.getElementById('cap-start');
  btn.disabled = true;
  try {
    await api('/api/captures', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, ip, port, proto, seconds }),
    });
    const parts = [];
    if (ip) parts.push(`来源 ${ip}`);
    if (port) parts.push(`端口 ${port}${svcLabel(Number(port))}`);
    if (proto) parts.push(proto.toUpperCase());
    toast(`抓包已开始（${hostLabel(target)}${parts.length ? ' — ' + parts.join(' ') : ''}），${seconds} 秒后自动完成并打开报文`);
    startCapCountdown(seconds);
    loadCaptures();
  } catch (err) {
    toast(err.message, true);
    btn.disabled = false;
  }
});

// ---------- 退出 ----------
document.getElementById('btn-logout').addEventListener('click', async () => {
  await fetch('/logout', { method: 'POST' }).catch(() => {});
  location.href = '/login.html';
});

// ---------- 账号 ----------
let myRole = 'viewer';
document.getElementById('whoami').addEventListener('click', () => {
  document.querySelector('nav .tab[data-tab=users]').click();
});

document.getElementById('pw-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const oldPw = document.getElementById('pw-old').value;
  const nw = document.getElementById('pw-new').value;
  const nw2 = document.getElementById('pw-new2').value;
  if (nw.length < 4) return toast('新密码至少 4 位', true);
  if (nw !== nw2) return toast('两次输入的新密码不一致', true);
  try {
    await api('/api/users/password', { method: 'POST', body: JSON.stringify({ oldPassword: oldPw, password: nw }) });
    toast('密码已修改');
    e.target.reset();
  } catch (err) {
    toast(err.message, true);
  }
});

async function loadUsers() {
  if (myRole !== 'admin') return;
  try {
    const list = await api('/api/users');
    const tb = document.getElementById('users-tbody');
    tb.textContent = '';
    for (const u of list) {
      const tr = document.createElement('tr');
      cell(tr, u.name);
      cell(tr, u.role === 'admin' ? '管理员' : '只读');
      cell(tr, fmtTime(u.createdTs));
      const td = document.createElement('td');
      const del = document.createElement('button');
      del.className = 'ghost';
      del.textContent = '删除';
      del.addEventListener('click', async () => {
        if (!confirm(`删除账号 ${u.name}？`)) return;
        try {
          await api(`/api/users/${encodeURIComponent(u.name)}`, { method: 'DELETE' });
          toast(`已删除 ${u.name}`);
          loadUsers();
        } catch (err) { toast(err.message, true); }
      });
      td.appendChild(del);
      tr.appendChild(td);
      tb.appendChild(tr);
    }
    const sel = document.getElementById('user-reset-sel');
    sel.textContent = '';
    for (const u of list) {
      const opt = document.createElement('option');
      opt.value = u.name;
      opt.textContent = `${u.name}（${u.role === 'admin' ? '管理员' : '只读'}）`;
      sel.appendChild(opt);
    }
  } catch (err) {
    toast(err.message, true);
  }
}

document.getElementById('user-add-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  try {
    await api('/api/users', {
      method: 'POST',
      body: JSON.stringify({ user: fd.get('user'), password: fd.get('password'), role: fd.get('role') }),
    });
    toast('用户已添加');
    e.target.reset();
    loadUsers();
  } catch (err) {
    toast(err.message, true);
  }
});

document.getElementById('user-reset-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const user = fd.get('user');
  if (!confirm(`将 ${user} 的密码重置为输入的新密码？`)) return;
  try {
    await api('/api/users/password', { method: 'POST', body: JSON.stringify({ user, password: fd.get('password') }) });
    toast(`${user} 的密码已重置`);
    e.target.reset();
  } catch (err) {
    toast(err.message, true);
  }
});

// ---------- 启动 ----------
(async function init() {
  try {
    const s = await api('/api/session');
    myRole = s.role === 'admin' ? 'admin' : 'viewer';
    document.getElementById('whoami').textContent =
      `${s.user}（${myRole === 'admin' ? '管理员' : '只读'}）`;
    document.getElementById('users-mgr').classList.toggle('hidden', myRole !== 'admin');
    const modeEl = document.getElementById('capture-mode');
    const li = s.listen || {};
    if (s.capture === 'replay') {
      document.getElementById('cap-replay-hint').style.display = '';
      if (s.tcpdumpOk === false) {
        // 本机没有 tcpdump：切换必然失败，徽标只做说明不可点
        modeEl.textContent = '回放模式（本机无 tcpdump，仅演示数据）';
        modeEl.title = '本机未安装 tcpdump，无法真实抓包。部署到 Linux 服务器不带 --replay 启动即为真实监听。';
      } else {
        modeEl.textContent = '回放模式(点我切换)';
        modeEl.style.cursor = 'pointer';
        modeEl.addEventListener('click', async () => {
          const cur = await api('/api/session');
          if (!cur.listen.replay) { toast('当前已是真实抓包模式'); return; }
          if (!confirm('切换到真实抓包模式？\n- 需要本机已安装 tcpdump\n- 回放循环将停止，已入库的演示数据会保留')) return;
          try {
            await api('/api/mode/real', { method: 'POST' });
            toast('正在切换，检测 tcpdump 中…');
            setTimeout(async () => {
              try {
                const s2 = await api('/api/session');
                if (s2.lastError) toast(`切换失败：${s2.lastError}`, true);
                else { toast('已切换到真实抓包模式'); location.reload(); }
              } catch (err) { toast(err.message, true); }
            }, 2500);
          } catch (err) {
            toast(err.message, true);
          }
        });
      }
      document.getElementById('listen-info').textContent =
        `当前显示的是演示数据：循环回放样本 ${li.replay}（fe80::a1、端口 2 等均为样本内容，非真实来访）。部署到 Linux 服务器不带 --replay 启动即为真实监听${s.tcpdumpOk === false ? '；本机未装 tcpdump，抓包诊断仍可用远程主机' : '，也可点右上角切换'}。`;
    } else {
      modeEl.textContent = '实时抓包';
      document.getElementById('listen-info').textContent =
        `监听对象：${li.hostname} 网卡 ${li.iface} · 本机IP：${(li.localIps || []).join(' / ') || '自动识别'}${s.lastError ? ' · 采集异常：' + s.lastError : ''}`;
    }
  } catch (_e) { return; }
  connectSSE();
  loadCaptureHosts();
  refreshOverview();
  setInterval(refreshOverview, 60000);
  loadUsers();
})();
