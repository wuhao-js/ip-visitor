'use strict';

const { app, BrowserWindow, dialog } = require('electron');
const { spawn } = require('child_process');
const http = require('http');
const net = require('net');
const path = require('path');

let coreProc = null;
let win = null;

const dbg = [];
function debugLog(msg) {
  dbg.push(`[${new Date().toISOString()}] ${msg}`);
  try {
    require('fs').writeFileSync(path.join(process.resourcesPath, 'app-debug.log'), dbg.join('\n') + '\n');
  } catch (_e) { /* ignore */
  }
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
    const port = await getFreePort();
    const corePath = path.join(process.resourcesPath, 'ip-visitor-core.exe');
    debugLog(`resourcesPath=${process.resourcesPath}`);
    debugLog(`corePath=${corePath} exists=${require('fs').existsSync(corePath)}`);
    coreProc = spawn(corePath, ['--port', String(port), '--host', '127.0.0.1'], {
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
      cwd: path.dirname(corePath),
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
      title: 'ip-visitor 服务器来访IP监控',
      webPreferences: { contextIsolation: true, nodeIntegration: false },
    });
    win.on('page-title-updated', (e) => e.preventDefault());
    await win.loadURL(`http://127.0.0.1:${port}/`);
    win.on('closed', killCore);
  } catch (e) {
    dialog.showErrorBox('ip-visitor 启动失败', String((e && e.message) || e));
    killCore();
    app.quit();
  }
});

app.on('window-all-closed', () => { killCore(); app.quit(); });
app.on('before-quit', killCore);
