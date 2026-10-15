'use strict';

const { app, BrowserWindow, dialog } = require('electron');
const { spawn } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');
const fs = require('fs');

let coreProc = null;
let win = null;

let logFile = null;
try {
  logFile = path.join(app.getPath('userData'), 'app-debug.log');
} catch (_e) { /* ignore */ }

function debugLog(msg) {
  const line = `[${new Date().toISOString()}] ${msg}`;
  if (!logFile) return;
  try { fs.appendFileSync(logFile, line + '\n'); } catch (_e) { /* 安装版无写权限时静默 */ }
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

function waitForHttp(port, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    (function poll() {
      const req = http.get({ host: '127.0.0.1', port, path: '/login.html', timeout: 1500 }, (res) => {
        res.resume();
        resolve();
      });
      req.on('timeout', () => req.destroy());
      req.on('error', () => {
        if (Date.now() > deadline) return reject(new Error('内核服务启动超时（端口 ' + port + '）'));
        setTimeout(poll, 300);
      });
    })();
  });
}

function killCore() {
  if (coreProc) {
    try { coreProc.kill(); } catch (_e) { /* ignore */ }
    coreProc = null;
  }
}

app.whenReady().then(async () => {
  try {
    debugLog(`userData=${app.getPath('userData')}`);
    const port = await getFreePort();
    const corePath = path.join(process.resourcesPath, 'lailu-core.exe');
    debugLog(`corePath=${corePath} exists=${fs.existsSync(corePath)}`);
    // 桌面版：只绑 127.0.0.1 且免登录（数据不出本机）；数据目录指向 %APPDATA%（安装版 Program Files 只读）
    coreProc = spawn(corePath, ['--port', String(port), '--host', '127.0.0.1', '--no-auth'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      cwd: app.getPath('userData'),
      env: { ...process.env, LAILU_HOME: app.getPath('userData') },
    });
    coreProc.stdout.on('data', (d) => debugLog('core.stdout: ' + String(d).trim()));
    coreProc.stderr.on('data', (d) => debugLog('core.stderr: ' + String(d).trim()));
    coreProc.on('error', (e) => debugLog('core.spawn-error: ' + e.message));
    coreProc.on('exit', (code, sig) => debugLog(`core.exit code=${code} sig=${sig}`));
    debugLog(`core spawned pid=${coreProc.pid}`);
    await waitForHttp(port);
    debugLog('core http ready, opening window');
    win = new BrowserWindow({
      width: 1280,
      height: 840,
      autoHideMenuBar: true,
      title: '来路 · 服务器来访监控',
      webPreferences: { contextIsolation: true, nodeIntegration: false },
    });
    win.on('page-title-updated', (e) => e.preventDefault());
    await win.loadURL(`http://127.0.0.1:${port}/`);
    win.on('closed', killCore);
  } catch (e) {
    dialog.showErrorBox('来路 启动失败', String((e && e.message) || e));
    killCore();
    app.quit();
  }
});

app.on('window-all-closed', () => { killCore(); app.quit(); });
app.on('before-quit', killCore);
