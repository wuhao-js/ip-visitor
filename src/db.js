'use strict';

const fs = require('fs');
const path = require('path');

// 驱动自适应：优先 Node 内置 node:sqlite（>=22.13），回退 better-sqlite3
let Database;
let driverName;
try {
  Database = require('node:sqlite').DatabaseSync;
  driverName = 'node:sqlite';
} catch (_e) {
  Database = require('better-sqlite3');
  driverName = 'better-sqlite3';
}

let db = null;
let driver = null;

function open(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  db = new Database(file);
  db.exec('PRAGMA journal_mode = WAL');
  db.exec('PRAGMA synchronous = NORMAL');
  db.exec('PRAGMA auto_vacuum = INCREMENTAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS access (
      id       INTEGER PRIMARY KEY AUTOINCREMENT,
      ts       INTEGER NOT NULL,
      src_ip   TEXT    NOT NULL,
      proto    TEXT    NOT NULL,
      dst_port INTEGER NOT NULL DEFAULT 0,
      bytes    INTEGER NOT NULL DEFAULT 0
    )
  `);
  db.exec('CREATE INDEX IF NOT EXISTS idx_access_ts ON access(ts)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_access_src_ts ON access(src_ip, ts)');
  db.exec(`
    CREATE TABLE IF NOT EXISTS alerts (
      id     INTEGER PRIMARY KEY AUTOINCREMENT,
      ts     INTEGER NOT NULL,
      type   TEXT    NOT NULL,
      ip     TEXT    NOT NULL,
      detail TEXT    NOT NULL
    )
  `);
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      name       TEXT PRIMARY KEY,
      pass_hash  TEXT NOT NULL,
      role       TEXT NOT NULL DEFAULT 'viewer',
      created_ts INTEGER NOT NULL
    )
  `);
  return { driver: driverName, db };
}

function withTx(fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const r = fn();
    db.exec('COMMIT');
    return r;
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch (_e2) { /* ignore */ }
    throw e;
  }
}

// rows: [{ts, srcIp, proto, dstPort, bytes}]
function insertBatch(rows) {
  if (!rows.length) return 0;
  const stmt = db.prepare('INSERT INTO access (ts, src_ip, proto, dst_port, bytes) VALUES (?, ?, ?, ?, ?)');
  return withTx(() => {
    for (const r of rows) {
      stmt.run(r.ts, r.srcIp, r.proto, r.dstPort, r.bytes);
    }
    return rows.length;
  });
}

function buildWhere(f) {
  const conds = [];
  const params = [];
  if (f.from != null) { conds.push('ts >= ?'); params.push(f.from); }
  if (f.to != null) { conds.push('ts <= ?'); params.push(f.to); }
  if (f.ip) { conds.push('src_ip = ?'); params.push(String(f.ip).toLowerCase()); }
  if (f.port != null && f.port !== '') { conds.push('dst_port = ?'); params.push(Number(f.port)); }
  if (f.proto) { conds.push('proto = ?'); params.push(String(f.proto).toLowerCase()); }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  return { where, params };
}

function getRecords(f) {
  const { where, params } = buildWhere(f);
  const page = Math.max(1, f.page | 0 || 1);
  const size = Math.min(200, Math.max(1, f.size | 0 || 50));
  const total = db.prepare(`SELECT COUNT(*) AS c FROM access ${where}`).get(...params).c;
  const rows = db.prepare(
    `SELECT id, ts, src_ip, proto, dst_port, bytes FROM access ${where}
     ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`
  ).all(...params, size, (page - 1) * size);
  return {
    total,
    page,
    size,
    rows: rows.map(r => ({ ts: r.ts, srcIp: r.src_ip, proto: r.proto, dstPort: r.dst_port, bytes: r.bytes })),
  };
}

// 客户端统计：次数 / 持续时长 / 频率 / 端口列表 / 协议分布
function getClients(f) {
  const { where, params } = buildWhere(f);
  const limit = Math.min(1000, Math.max(1, f.limit | 0 || 200));
  const base = db.prepare(
    `SELECT src_ip, COUNT(*) AS cnt, MIN(ts) AS first_ts, MAX(ts) AS last_ts
     FROM access ${where} GROUP BY src_ip ORDER BY cnt DESC LIMIT ?`
  ).all(...params, limit);
  const portRows = db.prepare(
    `SELECT src_ip, dst_port, COUNT(*) AS c FROM access ${where} GROUP BY src_ip, dst_port`
  ).all(...params);
  const protoRows = db.prepare(
    `SELECT src_ip, proto, COUNT(*) AS c FROM access ${where} GROUP BY src_ip, proto`
  ).all(...params);

  const portMap = new Map();
  for (const r of portRows) {
    if (!portMap.has(r.src_ip)) portMap.set(r.src_ip, []);
    portMap.get(r.src_ip).push([r.dst_port, r.c]);
  }
  const protoMap = new Map();
  for (const r of protoRows) {
    if (!protoMap.has(r.src_ip)) protoMap.set(r.src_ip, {});
    protoMap.get(r.src_ip)[r.proto] = r.c;
  }
  // 行为判定：扫描嫌疑（窗口内端口数超阈值）+ 新 IP（全历史首见时间在窗口内）
  const scanMap = new Map();
  if (f.scan && f.scan.threshold > 0) {
    for (const s of findScanSuspects(f.scan.windowMs, f.scan.threshold)) {
      scanMap.set(s.ip, s.ports);
    }
  }
  const now = Date.now();
  const newIpCutoff = f.scan && f.scan.newIpMs ? now - f.scan.newIpMs : null;
  return base.map(r => {
    const dur = Math.max(0, r.last_ts - r.first_ts);
    const ports = (portMap.get(r.src_ip) || []).sort((a, b) => b[1] - a[1]);
    return {
      ip: r.src_ip,
      count: r.cnt,
      firstTs: r.first_ts,
      lastTs: r.last_ts,
      durationMs: dur,
      freqPerMin: dur >= 60000 ? +(r.cnt / (dur / 60000)).toFixed(1) : r.cnt,
      ports: ports.slice(0, 10).map(([p, c]) => ({ port: p, count: c })),
      portCount: ports.length,
      byProto: protoMap.get(r.src_ip) || {},
      scanPorts: scanMap.get(r.src_ip) || 0,
      isNew: newIpCutoff != null && r.first_ts >= newIpCutoff,
    };
  });
}

function getClientDetail(ip, f) {
  const g = { ...f, ip };
  const { where, params } = buildWhere(g);
  const summary = db.prepare(
    `SELECT COUNT(*) AS cnt, MIN(ts) AS first_ts, MAX(ts) AS last_ts
     FROM access ${where}`
  ).get(...params);
  const ports = db.prepare(
    `SELECT dst_port, proto, COUNT(*) AS c, MIN(ts) AS first_ts, MAX(ts) AS last_ts
     FROM access ${where} GROUP BY dst_port, proto ORDER BY c DESC`
  ).all(...params);
  const rec = getRecords({ ...g, size: 50 });
  return {
    ip: String(ip).toLowerCase(),
    count: summary.cnt,
    firstTs: summary.first_ts,
    lastTs: summary.last_ts,
    durationMs: summary.cnt ? Math.max(0, summary.last_ts - summary.first_ts) : 0,
    ports: ports.map(p => ({ port: p.dst_port, proto: p.proto, count: p.c, firstTs: p.first_ts, lastTs: p.last_ts })),
    recent: rec.rows,
  };
}

function getOverview(f) {
  const from24 = Date.now() - 24 * 3600 * 1000;
  const g = { ...f };
  const { where, params } = buildWhere(g);
  const total = db.prepare(`SELECT COUNT(*) AS c, COUNT(DISTINCT src_ip) AS u FROM access ${where}`).get(...params);
  const byProtoRows = db.prepare(`SELECT proto, COUNT(*) AS c FROM access ${where} GROUP BY proto`).all(...params);
  const byProto = {};
  for (const r of byProtoRows) byProto[r.proto] = r.c;
  const last = db.prepare('SELECT MAX(ts) AS m FROM access').get().m;
  const c24 = db.prepare('SELECT COUNT(*) AS c, COUNT(DISTINCT src_ip) AS u FROM access WHERE ts >= ?').get(from24);
  // 24h 小时级趋势
  const trendRows = db.prepare(
    `SELECT (ts / 3600000) * 3600000 AS b, COUNT(*) AS c FROM access
     WHERE ts >= ? GROUP BY b ORDER BY b`
  ).all(from24);
  // Top 端口（排除 icmp 的 0 端口）与 Top 客户端
  const topPorts = db.prepare(
    `SELECT dst_port AS port, COUNT(*) AS c FROM access
     WHERE ts >= ? AND dst_port > 0 GROUP BY dst_port ORDER BY c DESC LIMIT 10`
  ).all(from24);
  const topClients = db.prepare(
    `SELECT src_ip AS ip, COUNT(*) AS c FROM access
     WHERE ts >= ? GROUP BY src_ip ORDER BY c DESC LIMIT 10`
  ).all(from24);
  return {
    totalPackets: total.c,
    totalClients: total.u,
    byProto,
    packets24h: c24.c,
    clients24h: c24.u,
    lastTs: last || null,
    trend: trendRows.map(r => ({ t: r.b, c: r.c })),
    topPorts,
    topClients,
  };
}

// 扫描嫌疑：windowMs 内 distinct 端口数 >= threshold（排除 icmp 端口0）
function findScanSuspects(windowMs, threshold) {
  const from = Date.now() - windowMs;
  return db.prepare(
    `SELECT src_ip AS ip, COUNT(DISTINCT dst_port) AS ports, COUNT(*) AS packets
     FROM access WHERE ts >= ? AND dst_port > 0
     GROUP BY src_ip HAVING ports >= ? ORDER BY ports DESC`
  ).all(from, threshold);
}

function getAllKnownIps() {
  return db.prepare('SELECT DISTINCT src_ip AS ip FROM access').all().map(r => r.ip);
}

// ---- 告警 ----
function insertAlert(ts, type, ip, detail) {
  db.prepare('INSERT INTO alerts (ts, type, ip, detail) VALUES (?, ?, ?, ?)').run(ts, type, ip, detail);
}

function getAlerts(limit = 50) {
  return db.prepare('SELECT ts, type, ip, detail FROM alerts ORDER BY id DESC LIMIT ?').all(Math.min(200, limit));
}

function cleanup(retentionDays) {
  const cutoff = Date.now() - retentionDays * 86400 * 1000;
  const info = db.prepare('DELETE FROM access WHERE ts < ?').run(cutoff);
  db.exec('PRAGMA incremental_vacuum');
  return info.changes;
}

function cleanupAlerts(retentionDays) {
  const cutoff = Date.now() - retentionDays * 86400 * 1000;
  const info = db.prepare('DELETE FROM alerts WHERE ts < ?').run(cutoff);
  return info.changes;
}

function close() {
  try { db.close(); } catch (_e) { /* ignore */ }
}

// ---- 用户 ----
function countUsers() {
  return db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
}
function getUser(name) {
  return db.prepare('SELECT name, pass_hash, role, created_ts FROM users WHERE name = ?').get(name) || null;
}
function listUsers() {
  return db.prepare('SELECT name, role, created_ts FROM users ORDER BY created_ts, name').all();
}
function insertUser(name, passHash, role) {
  db.prepare('INSERT INTO users (name, pass_hash, role, created_ts) VALUES (?, ?, ?, ?)').run(name, passHash, role, Date.now());
}
function updateUserPassword(name, passHash) {
  return db.prepare('UPDATE users SET pass_hash = ? WHERE name = ?').run(passHash, name).changes;
}
function deleteUser(name) {
  return db.prepare('DELETE FROM users WHERE name = ?').run(name).changes;
}
function countAdmins() {
  return db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").get().c;
}

module.exports = {
  open, insertBatch, getRecords, getClients, getClientDetail, getOverview,
  findScanSuspects, getAllKnownIps, insertAlert, getAlerts, cleanup, cleanupAlerts, close,
  countUsers, getUser, listUsers, insertUser, updateUserPassword, deleteUser, countAdmins,
  get driverName() { return driverName; },
};
