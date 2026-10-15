'use strict';

const crypto = require('crypto');

const COOKIE_NAME = 'ipv_session';

function hmac(secret, s) {
  return crypto.createHmac('sha256', secret).update(s).digest('hex');
}

function b64u(buf) {
  return Buffer.from(buf).toString('base64url');
}

// 会话 token: exp.b64u({u:user,r:role}).hmac —— 携带登录身份
function makeSession(secret, ttlMs, data = {}) {
  const exp = Date.now() + ttlMs;
  const body = b64u(JSON.stringify({ u: String(data.user || ''), r: String(data.role || 'viewer') }));
  const base = `${exp}.${body}`;
  return `${base}.${hmac(secret, base)}`;
}

// 有效返回 {user, role, exp}，无效返回 null
function verifySession(secret, token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [expStr, body, sig] = parts;
  if (!/^\d+$/.test(expStr)) return null;
  if (Date.now() > Number(expStr)) return null;
  const expect = hmac(secret, `${expStr}.${body}`);
  if (sig.length !== expect.length) return false;
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
    const data = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!data || typeof data.u !== 'string') return null;
    return { user: data.u, role: data.r === 'admin' ? 'admin' : 'viewer', exp: Number(expStr) };
  } catch (_e) {
    return null;
  }
}

// 密码 scrypt 哈希：salt:hash（hex），用户密码不再明文落盘
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 32).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (typeof stored !== 'string' || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  try {
    const calc = crypto.scryptSync(String(password), salt, 32).toString('hex');
    return calc.length === hash.length && crypto.timingSafeEqual(Buffer.from(calc), Buffer.from(hash));
  } catch (_e) {
    return false;
  }
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function cookieHeader(token, maxAgeSec) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}`;
}

// 登录失败限速：同一来源 IP 连续失败 5 次锁定 10 分钟
class LoginThrottle {
  constructor(maxFails = 5, lockMs = 10 * 60 * 1000) {
    this.maxFails = maxFails;
    this.lockMs = lockMs;
    this.map = new Map();
  }
  check(key) {
    const e = this.map.get(key);
    if (e && e.lockedUntil > Date.now()) return { locked: true, retryAfterSec: Math.ceil((e.lockedUntil - Date.now()) / 1000) };
    return { locked: false };
  }
  fail(key) {
    const e = this.map.get(key) || { fails: 0, lockedUntil: 0 };
    e.fails += 1;
    if (e.fails >= this.maxFails) e.lockedUntil = Date.now() + this.lockMs;
    this.map.set(key, e);
  }
  ok(key) { this.map.delete(key); }
}

module.exports = { COOKIE_NAME, makeSession, verifySession, parseCookies, cookieHeader, LoginThrottle, hashPassword, verifyPassword };
