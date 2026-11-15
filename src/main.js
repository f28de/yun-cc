import { spawn } from 'node:child_process';
import { existsSync, unlinkSync } from 'node:fs';
import { promises as fsp } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PATHS } from './config.js';
import { atomicWrite, randomToken } from './util.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUNTIME = path.join(PATHS.base, 'runtime.json');
const LOCK = path.join(PATHS.base, 'app.lock');
const RESTART_STATE = path.join(PATHS.base, 'restart-state.json');
const RESTART_REQUEST = path.join(PATHS.base, 'restart.request');
const PROFILE = path.join(PATHS.base, 'webview-profile');
const EDGE = [
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
  'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
];
const SESSION_EXPIRED_EXIT = 75;
const LIMIT = 5;
const WINDOW_MS = 60000;

const findEdge = () => EDGE.find((p) => existsSync(p)) || null;

function pickFreePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

function openWindow(url) {
  const edge = findEdge();
  if (!edge) {
    console.error('[FreeCloudConsole] 未找到 Microsoft Edge / WebView2 运行时，无法打开界面');
    return null;
  }
  // A dedicated user-data-dir isolates the app window from the user's browser.
  const child = spawn(edge, [
    `--app=${url}`,
    `--user-data-dir=${PROFILE}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--disable-background-networking',
    '--disable-sync',
    '--window-size=1280,820',
  ], { detached: true, stdio: 'ignore', windowsHide: false });
  child.unref();
  return child;
}

/** TCP-only liveness probe, so single-instance detection needs no HTTP surface. */
function tcpAlive(port, timeoutMs = 900) {
  return new Promise((resolve) => {
    const sock = net.connect({ host: '127.0.0.1', port });
    let settled = false;
    const done = (v) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve(v);
    };
    sock.setTimeout(timeoutMs);
    sock.once('connect', () => done(true));
    sock.once('timeout', () => done(false));
    sock.once('error', () => done(false));
  });
}

/** A live instance = pid + startedAt + loopback-only declaration + open port. */
async function probeExisting() {
  try {
    const info = JSON.parse(await fsp.readFile(RUNTIME, 'utf8'));
    if (!Number.isInteger(info.port) || !Number.isInteger(info.pid) || !info.startedAt) return null;
    if (info.listen !== '127.0.0.1') return null;
    return (await tcpAlive(info.port)) ? info : null;
  } catch {
    return null; // stale runtime.json is never trusted
  }
}

/** Atomic startup lock. Reclaims stale locks; briefly waits out a handover. */
async function acquireLock() {
  await fsp.mkdir(PATHS.base, { recursive: true });
  for (let i = 0; i < 25; i += 1) {
    try {
      const h = await fsp.open(LOCK, 'wx');
      await h.writeFile(JSON.stringify({ pid: process.pid, at: Date.now() }));
      await h.close();
      return true;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      let fresh = false;
      try {
        const s = JSON.parse(await fsp.readFile(LOCK, 'utf8'));
        fresh = Date.now() - Number(s.at) <= 30000;
      } catch { /* unreadable lock => treat as stale */ }
      if (fresh) {
        // During --restart the previous watchdog is still releasing its lock.
        await new Promise((r) => setTimeout(r, 100));
        continue;
      }
      await fsp.unlink(LOCK).catch(() => {});
    }
  }
  return false;
}

/** Persistent C21 counter: survives a watchdog restart, never silently resets. */
async function claimSlot() {
  const now = Date.now();
  let timestamps = [];
  try {
    const s = JSON.parse(await fsp.readFile(RESTART_STATE, 'utf8'));
    if (Array.isArray(s.timestamps)) {
      timestamps = s.timestamps.filter((t) => Number.isFinite(t) && now - t < WINDOW_MS);
    }
  } catch { /* first run */ }
  if (timestamps.length >= LIMIT) {
    await atomicWrite(RESTART_STATE, JSON.stringify({ timestamps, exhausted: true, at: now }), 0o600);
    return false;
  }
  timestamps.push(now);
  await atomicWrite(RESTART_STATE, JSON.stringify({ timestamps, exhausted: false, at: now }), 0o600);
  return true;
}

async function selftest() {
  const out = { node: process.version, platform: process.platform, checks: {} };
  out.checks.edgeOrWebView2 = Boolean(findEdge());
  out.checks.loopbackBind = await new Promise((r) => {
    const s = net.createServer();
    s.once('error', () => r(false));
    s.listen(0, '127.0.0.1', () => s.close(() => r(true)));
  });
  const { createDpapiVault } = await import('./secrets.js');
  out.checks.dpapiRoundtrip = await createDpapiVault().isAvailable();
  const { assertUpstream, maskSecret } = await import('./util.js');
  out.checks.ssrfMetadataBlocked = false;
  try { assertUpstream('https://169.254.169.254/latest/meta-data/'); } catch {
    out.checks.ssrfMetadataBlocked = true;
  }
  out.checks.ssrfPlainHttpBlocked = false;
  try { assertUpstream('http://api.cloudflare.com/x'); } catch {
    out.checks.ssrfPlainHttpBlocked = true;
  }
  out.checks.maskNeverUsesPlaintextSuffix = !maskSecret('SUPERSECRET1234').includes('1234')
    && /^\*\*\*[0-9A-F]{4}$/.test(maskSecret('SUPERSECRET1234'));
  // Fail closed: EVERY check must pass. Skipping dpapiRoundtrip here would let
  // a broken credential store report a green self-test.
  out.ok = Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out, null, 2));
  return out;
}

const releaseLock = () => { try { unlinkSync(LOCK); } catch { /* noop */ } };

if (process.argv.includes('--selftest')) {
  selftest().then((r) => process.exit(r.ok ? 0 : 1));
} else {
  if (process.argv.includes('--restart')) {
    const old = await probeExisting();
    if (old) {
      if (typeof old.restartNonce !== 'string' || !old.restartNonce) {
        // Fail closed: never terminate a bare PID. Windows recycles PIDs and
        // a stale runtime.json could otherwise point at an unrelated process.
        console.error('[FreeCloudConsole] 运行信息缺少实例标识，拒绝按 PID 结束进程。');
        console.error('请先在界面中退出应用，或直接结束 FreeCloudConsole 的 node.exe 进程。');
        process.exit(1);
      }
      // Ask the LIVE watchdog to shut itself down. It verifies the nonce from
      // its own runtime.json before acting, so no process is killed by PID.
      await atomicWrite(
        RESTART_REQUEST,
        JSON.stringify({ nonce: old.restartNonce, at: Date.now() }),
        0o600,
      );
      for (let i = 0; i < 80; i += 1) {
        if (!(await probeExisting())) break;
        await new Promise((r) => setTimeout(r, 100));
      }
      if (await probeExisting()) {
        await fsp.unlink(RESTART_REQUEST).catch(() => {});
        console.error('[FreeCloudConsole] 旧实例未在限定时间内退出，已放弃重启（未结束任何进程）。');
        process.exit(1);
      }
    }
  }

  const existing = await probeExisting();
  if (existing) {
    // Never open a token-less window: it could not authenticate and would
    // leave the user in a dead-end. Give an explicit, actionable instruction.
    console.log(`[FreeCloudConsole] 应用已在后台运行：${existing.url}（PID ${existing.pid}）`);
    console.log('若界面窗口已关闭，请运行：start.cmd --restart  （结束旧实例并重新打开界面）');
    process.exit(0);
  }

  if (!(await acquireLock())) {
    console.error('[FreeCloudConsole] 另一个实例正在启动，请稍后重试');
    process.exit(1);
  }

  const port = await pickFreePort();
  // Owned by THIS watchdog; core echoes it into runtime.json so a sibling
  // `start.cmd --restart` can prove it is talking to this exact instance.
  const INSTANCE_NONCE = randomToken(16);
  await fsp.unlink(RESTART_REQUEST).catch(() => {}); // never inherit a stale request
  let child = null;
  let shuttingDown = false;
  let restarts = 0;
  let openedOnce = false;

  function failClosed(reason) {
    shuttingDown = true;
    console.error(`[FreeCloudConsole] FAIL-CLOSED: ${reason}`);
    console.error('已停止拉起、bootstrap 不重开、旧会话全部失效。请手动重新启动应用。');
    try { child?.kill(); } catch { /* noop */ }
    releaseLock();
    process.exit(1);
  }

  function startCore() {
    child = spawn(process.execPath, [path.join(HERE, 'core.js')], {
      env: {
        ...process.env,
        FCC_PORT: String(port),
        FCC_SUPERVISED: '1',
        FCC_INSTANCE_NONCE: INSTANCE_NONCE,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let buf = '';
    child.stdout.on('data', (d) => {
      buf += d.toString();
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        if (line.startsWith('FCC_READY ')) {
          const info = JSON.parse(line.slice('FCC_READY '.length));
          if (!openedOnce) {
            openedOnce = true;
            claimSlot().then((ok) => {
              if (!ok) return failClosed('窗口重开次数达上限 (C21)');
              openWindow(info.url);
            });
          }
          // A restarted core NEVER auto-opens a window and NEVER re-runs
          // bootstrap for the old UI. Re-auth requires an explicit user action.
        } else if (line.trim()) {
          process.stdout.write(`${line}\n`);
        }
      }
    });
    child.stderr.on('data', (d) => process.stderr.write(d));
    child.on('exit', (code) => {
      if (shuttingDown) return;
      if (code === 0) {
        shuttingDown = true;
        releaseLock();
        process.exit(0);
      }
      const kind = code === SESSION_EXPIRED_EXIT ? '会话到期(75)' : `异常退出(${code})`;
      console.error(`[FreeCloudConsole] core ${kind}；仅拉起后台服务，不自动重开界面。`);
      console.error('请在界面看到「会话已结束」后运行 start.cmd --restart 重新认证。');
      restarts += 1;
      if (restarts > LIMIT) return failClosed('拉起次数达上限 (C21)');
      claimSlot().then((ok) => {
        if (!ok) return failClosed('拉起次数达上限 (C21，持久化计数)');
        setTimeout(startCore, Math.min(30000, 1000 * 2 ** Math.min(restarts, 5)));
      });
    });
  }

  // The watchdog IS the top-level process: if it exits, the app is gone.
  // Autostart only launches it once per user login - there is no crash-restart
  // wrapper around the watchdog itself, so the C21 counter cannot be reset.
  const bye = () => {
    shuttingDown = true;
    try { child?.kill(); } catch { /* noop */ }
    releaseLock();
    process.exit(0);
  };
  process.on('SIGINT', bye);
  process.on('SIGTERM', bye);
  process.on('exit', releaseLock);

  // Explicit restart handshake. A sibling `start.cmd --restart` writes a
  // request bearing the nonce from runtime.json; the RUNNING watchdog verifies
  // it and shuts ITSELF down. No process is ever terminated by a bare PID.
  const restartWatcher = setInterval(async () => {
    let req;
    try {
      req = JSON.parse(await fsp.readFile(RESTART_REQUEST, 'utf8'));
    } catch {
      return; // no request (or a partially written one) -> try again shortly
    }
    await fsp.unlink(RESTART_REQUEST).catch(() => {});
    if (!req || req.nonce !== INSTANCE_NONCE) return; // forged / stale: ignore
    console.log('[FreeCloudConsole] 收到显式重启请求，正在结束当前实例…');
    bye();
  }, 400);
  restartWatcher.unref?.();

  startCore();
}
