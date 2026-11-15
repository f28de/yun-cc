import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig, PATHS, defaultAiUpstreams } from './config.js';
import { readJson, atomicWrite, LOOPBACK, iso, randomToken } from './util.js';
import { createTelemetry } from './telemetry.js';
import { createSessionStore } from './auth.js';
import { createDpapiVault, ensureDirAcl } from './secrets.js';
import { createDdnsEngine } from './ddns.js';
import { createAiGateway } from './ai-gateway.js';
import { createApp } from './server.js';

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
export const SESSION_EXPIRED_EXIT = 75;

export function pickFreePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, LOOPBACK, () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

function listen(server, port) {
  return new Promise((resolve, reject) => {
    const onErr = (e) => { server.removeListener('listening', onOk); reject(e); };
    const onOk = () => { server.removeListener('error', onErr); resolve(); };
    server.once('error', onErr);
    server.once('listening', onOk);
    server.listen(port, LOOPBACK);
  });
}

export async function bootstrap(opts = {}) {
  const config = opts.config || await loadConfig();

  // C12 hard gate: refuse to start if anything tries to bind beyond loopback.
  if (config.listen && config.listen.host !== LOOPBACK) throw new Error('C12: non-loopback listen rejected');
  if (process.env.FCC_LISTEN_HOST && process.env.FCC_LISTEN_HOST !== LOOPBACK) {
    throw new Error('C12: non-loopback env rejected');
  }
  if (!Array.isArray(config.aiUpstreams) || config.aiUpstreams.length === 0) {
    config.aiUpstreams = defaultAiUpstreams();
  }
  if (!Array.isArray(config.ddnsRecords)) config.ddnsRecords = [];

  const vault = opts.vault || createDpapiVault();
  const telemetry = createTelemetry({
    maxEvents: Number(config.ui?.eventBuffer) || 200,
    sink: opts.sink ?? console.log,
  });
  const log = telemetry.log;

  if (vault.kind === 'dpapi') {
    try { await ensureDirAcl(PATHS.base); } catch (e) {
      log('warn', 'security.vault-acl', { message: e.message });
    }
  }
  const vaultAvailable = await vault.isAvailable();
  if (!vaultAvailable) log('error', 'security.credential_store_unavailable', {});

  // Local relay key: decrypt ONCE, keep a Buffer resident, zero on revoke/exit.
  // No PowerShell invocation on the request path.
  let keyBuf = null;
  let keyCreatedAt = null;
  const refreshKey = async () => {
    if (keyBuf) { keyBuf.fill(0); keyBuf = null; }
    const meta = await vault.getLocalKeyMeta();
    keyBuf = meta.key ? Buffer.from(meta.key, 'utf8') : null;
    keyCreatedAt = meta.createdAt || null;
  };
  await refreshKey().catch((e) => log('warn', 'security.local-key-unavailable', { message: e.message }));

  const state = await readJson(PATHS.state, {});
  const saveState = async (patch) => {
    Object.assign(state, patch);
    await atomicWrite(PATHS.state, JSON.stringify(state));
  };

  const session = createSessionStore({
    requireSecFetch: opts.requireSecFetch !== false,
  });
  const ddns = createDdnsEngine({
    config, vault, emit: telemetry.emit, log, state, saveState, probe: opts.probe,
  });
  const ai = createAiGateway({ config, vault, emit: telemetry.emit, log });
  const activity = { last: Date.now() };
  const startedAt = Date.now();
  const ABS_TTL = 8 * 60 * 60 * 1000;
  const IDLE_TTL = Number(config.session?.idleTimeoutSec ?? 900) * 1000;

  /** Single source of truth for the session policy reported by /api/status. */
  const getSessionPolicy = () => {
    const idleAt = IDLE_TTL > 0 ? activity.last + IDLE_TTL : Number.POSITIVE_INFINITY;
    return {
      idleTimeoutSec: IDLE_TTL / 1000,
      absoluteTtlSec: ABS_TTL / 1000,
      expiresAt: iso(Math.min(startedAt + ABS_TTL, idleAt)),
      lastActivityAt: iso(activity.last),
    };
  };

  let port = opts.port || await pickFreePort();
  let server;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    server = createApp({
      config, vault, ddns, ai, telemetry, session, vaultAvailable, port,
      onShutdown: opts.onShutdown || (() => {}),
      onActivity: () => { activity.last = Date.now(); },
      getSessionPolicy,
      getLocalKey: async () => (keyBuf ? keyBuf.toString('utf8') : null),
      getLocalKeyMeta: async () => ({
        key: keyBuf ? keyBuf.toString('utf8') : null,
        createdAt: keyCreatedAt,
      }),
      setLocalKey: async (key) => { await vault.setLocalKey(key); await refreshKey(); },
      removeLocalKey: async () => {
        await vault.removeLocalKey();
        if (keyBuf) keyBuf.fill(0);
        keyBuf = null;
        keyCreatedAt = null;
      },
    });
    try {
      await listen(server, port);
      break;
    } catch (e) {
      if (e.code === 'EADDRINUSE' && attempt < 2) { port = await pickFreePort(); continue; }
      throw e;
    }
  }
  const addr = server.address();
  if (!addr || addr.address !== LOOPBACK) {
    server.close();
    throw new Error('C12 violation: bound to a non-loopback address');
  }
  const actualPort = addr.port;
  const url = `http://${LOOPBACK}:${actualPort}/`;

  // Any credential block that fails decryption disables its automatic tasks.
  await vault.list();
  for (const id of (vault.failedIds ? vault.failedIds() : [])) {
    log('warn', 'security.credential_store_unavailable', { id });
    telemetry.noteAnomaly('credential_store_unavailable', id);
    for (const r of config.ddnsRecords) if (r.providerId === id) r.enabled = false;
    for (const u of config.aiUpstreams) if (u.providerId === id) u.enabled = false;
  }

  ddns.start();
  const hb = setInterval(() => telemetry.heartbeat(), 25000);
  let expired = false;
  const expire = async () => {
    if (expired) return;
    expired = true;
    telemetry.audit('session_expired', 'success', 'idle_or_absolute_ttl');
    telemetry.emit('security-alert', {
      at: iso(), severity: 'warn', kind: 'session_expired',
      detail: '会话已结束（空闲或绝对 TTL），请重新打开应用重新认证',
    });
    session.expire();
    if (keyBuf) { keyBuf.fill(0); keyBuf = null; }
    ddns.stop();
    if (opts.supervised) {
      try { server.close(); } catch { /* ignore */ }
      process.exit(SESSION_EXPIRED_EXIT);
    }
  };
  const ttl = setInterval(() => {
    if (Date.now() - startedAt > ABS_TTL) { expire(); return; }
    if (IDLE_TTL > 0 && Date.now() - activity.last > IDLE_TTL) expire();
  }, 15000);
  hb.unref?.();
  ttl.unref?.();

  const close = async () => {
    ddns.stop();
    clearInterval(hb);
    clearInterval(ttl);
    telemetry.close();
    if (keyBuf) { keyBuf.fill(0); keyBuf = null; }
    await session.destroy();
    await new Promise((r) => server.close(r));
  };

  return { server, port: actualPort, url, session, telemetry, config, vault, ddns, ai, close };
}

if (isMain) {
  let app;
  (async () => {
    const supervised = process.env.FCC_SUPERVISED === '1';
    app = await bootstrap({
      port: Number(process.env.FCC_PORT) || undefined,
      // Session token stays in memory only; never written to disk.
      supervised,
      onShutdown: async () => { if (app) await app.close(); process.exit(0); },
    });
    await atomicWrite(
      path.join(PATHS.base, 'runtime.json'),
      JSON.stringify({
        port: app.port, url: app.url, pid: process.pid,
        startedAt: iso(), listen: LOOPBACK,
        restartNonce: process.env.FCC_INSTANCE_NONCE || randomToken(16),
      }),
      0o600,
    );
    process.stdout.write(`FCC_READY ${JSON.stringify({ port: app.port, url: app.url })}\n`);
    const stop = async () => { await app.close(); process.exit(0); };
    process.on('SIGTERM', stop);
    process.on('SIGINT', stop);
  })().catch((e) => {
    console.error('FCC_BOOT_FAILED', e.message);
    process.exit(1);
  });
}
