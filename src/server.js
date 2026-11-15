import http from 'node:http';
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { LOOPBACK, iso, safeEqual, redact, fingerprint } from './util.js';
import { saveConfig, sanitizeConfig, templateForUpstream, rebuildUpstream } from './config.js';
import { VENDOR_META, createDnsProvider, missingSecretFields } from './providers/dns-index.js';
import { VaultDecryptError } from './secrets.js';
import { applyAutoStart, autoStartState } from './autostart.js';

const UI_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'ui');
const VERSION = '0.1.0';
const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/app.css': ['app.css', 'text/css; charset=utf-8'],
  '/app.js': ['app.js', 'application/javascript; charset=utf-8'],
};
const RELAY_PATH = '/v1/chat/completions';

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store, max-age=0',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Content-Security-Policy':
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    + "connect-src 'self'; font-src 'self'; form-action 'none'; frame-ancestors 'none'; "
    + "base-uri 'none'; object-src 'none'; frame-src 'none'",
};

const newId = (prefix) => `${prefix}_${randomBytes(5).toString('hex')}`;
const DOMAIN_RE = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;
const MASK = '***';
const clamp = (v, lo, hi, fallback) => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : fallback;
};

function send(res, code, obj, extra = {}) {
  if (res.headersSent) return;
  res.writeHead(code, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json; charset=utf-8',
    ...extra,
  });
  res.end(JSON.stringify(redact(obj)));
}

/** Used ONLY for the one-time local API key display. Never logged. */
function sendRaw(res, code, obj, extra = {}) {
  if (res.headersSent) return;
  res.writeHead(code, {
    ...SECURITY_HEADERS,
    'Content-Type': 'application/json; charset=utf-8',
    ...extra,
  });
  res.end(JSON.stringify(obj));
}

function sendText(res, code, text, type, extra = {}) {
  if (res.headersSent) return;
  res.writeHead(code, { ...SECURITY_HEADERS, 'Content-Type': type, ...extra });
  res.end(text);
}

async function readBody(req, maxBytes) {
  const declared = Number(req.headers['content-length'] || 0);
  if (declared > maxBytes) {
    const e = new Error('payload too large'); e.status = 413; throw e;
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      const e = new Error('payload too large'); e.status = 413; throw e;
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  try { return JSON.parse(raw); } catch {
    const e = new Error('invalid JSON'); e.status = 400; throw e;
  }
}

const errorCode = (err) => String(err?.message || 'error')
  .replace(/[A-Za-z0-9+/=]{24,}/g, '[redacted]')
  .slice(0, 160);

const SESSION_INVALID = { errorCode: 'SESSION_INVALID', message: '会话已失效，请重新认证' };

export function createApp(ctx) {
  const {
    config, vault, ddns, ai, telemetry, session, vaultAvailable = false,
    onShutdown = () => {}, port = 0, getLocalKey = async () => null,
    setLocalKey = async () => {}, removeLocalKey = async () => {},
  } = ctx;
  const providerTests = new Map();

  const allowedHost = () => `${LOOPBACK}:${port}`;
  const allowedOrigin = () => `http://${allowedHost()}`;

  /** TC28: reject vendor/credential mismatches at write time. */
  async function requireBoundCredential(providerId, vendor) {
    if (!providerId) return;
    const entry = await vault.get(providerId);
    const err = new Error(!entry ? '凭据条目不存在' : '凭据厂商与目标厂商不匹配');
    if (!entry || entry.meta?.vendor !== vendor) { err.status = 400; throw err; }
  }

  function securitySnapshot() {
    // OS state is the source of truth; config.autostart is only a preference.
    const auto = autoStartState();
    // core.js owns the real idle/absolute TTL timers. Never report a stale
    // hard-coded "0" that would contradict the enforced policy.
    const policy = ctx.getSessionPolicy ? ctx.getSessionPolicy() : {
      idleTimeoutSec: 0, absoluteTtlSec: 0, expiresAt: null, lastActivityAt: null,
    };
    return {
      credentialsEncrypted: vault.kind === 'dpapi' && vaultAvailable,
      encryptionScheme: vault.kind === 'dpapi' && vaultAvailable ? 'Windows DPAPI / CurrentUser' : null,
      credentialStore: vault.kind === 'dpapi' && vaultAvailable ? 'dpapi' : 'none',
      loopbackOnly: true,
      listenPort: port,
      listenAddresses: [allowedHost()],
      autoStart: auto.enabled,
      autoStartSupported: auto.supported,
      externalConnections: telemetry.externalConnections,
      outboundAnomalies: telemetry.anomalies,
      auditRecent: telemetry.auditRecent(3),
      session: {
        locked: false,
        idleTimeoutSec: policy.idleTimeoutSec,
        absoluteTtlSec: policy.absoluteTtlSec,
        expiresAt: policy.expiresAt,
        lastActivityAt: policy.lastActivityAt,
        bootstrapConsumed: session.bootstrapConsumed,
      },
      lastSecurityCheckAt: iso(),
    };
  }

  async function buildStatus() {
    const list = await vault.list();
    const usage = ai.usageSummary();
    const lk = ctx.getLocalKeyMeta ? await ctx.getLocalKeyMeta() : { key: null, createdAt: null };
    const lkFp = lk.key ? fingerprint(lk.key).slice(-4).toUpperCase() : null;
    const ddnsStatus = ddns.statusSummary();
    const resetAt = new Date();
    resetAt.setUTCHours(24, 0, 0, 0);
    return {
      schemaVersion: 1,
      version: VERSION,
      serverTime: iso(),
      generatedAt: Date.now(),
      health: {
        ddnsEngine: !config.ddns.enabled ? 'stopped' : ddnsStatus.healthy ? 'running' : 'degraded',
        ddnsIp: ddnsStatus.lastIp,
        aiGateway: !config.ai.enabled ? 'stopped' : ai.healthy() ? 'running' : 'degraded',
        daemon: 'running',
        uptimeSec: telemetry.uptimeSec(),
      },
      providers: list.map((p) => {
        const test = providerTests.get(p.id) || {};
        return {
          id: p.id,
          vendor: p.vendor,
          displayName: p.displayName,
          enabled: p.enabled,
          status: p.decryptFailed ? 'decrypt_failed' : (test.status || 'untested'),
          lastTestedAt: test.lastTestedAt || null,
          latencyMs: test.latencyMs ?? null,
          credentialFingerprint: p.credentialFingerprint,
          credentialMasked: p.credentialMasked,
          credentialCreatedAt: p.credentialCreatedAt,
          credentialCount: p.credentialCount,
          decryptFailed: Boolean(p.decryptFailed),
          errorCode: p.decryptFailed ? 'CREDENTIAL_STORE_UNAVAILABLE' : (test.errorCode || null),
        };
      }),
      quota: Object.entries(usage.upstreams).map(([providerId, u]) => ({
        providerId,
        vendor: (config.aiUpstreams.find((x) => x.id === providerId) || {}).vendor || 'unknown',
        metric: 'requests',
        used: u.requests,
        limit: u.cap,
        unit: 'request',
        ratio: u.cap > 0 ? Math.min(1, u.requests / u.cap) : 0,
        circuitOpen: Boolean(u.cooling),
        circuitReason: u.cooling ? 'circuit_open' : 'none',
        resetAt: resetAt.toISOString(),
      })),
      ai: {
        enabled: config.ai.enabled,
        localKey: {
          state: lk.key ? 'active' : 'absent',
          fingerprint: lkFp,
          masked: lkFp ? `${MASK}${lkFp}` : null,
          createdAt: lk.createdAt || null,
        },
      },
      security: {
        ...securitySnapshot(),
        localKeyEnabled: Boolean(lk.key),
      },
      events: telemetry.recent(8),
    };
  }

  async function serveStatic(req, res, urlPath) {
    const entry = STATIC[urlPath];
    if (!entry) return send(res, 404, { error: 'not found' });
    try {
      const content = await fsp.readFile(path.join(UI_DIR, entry[0]));
      const extra = {};
      if (urlPath === '/') {
        const ticket = session.ticketForNavigation(req);
        if (ticket) extra['Set-Cookie'] = ticket;
      }
      sendText(res, 200, content, entry[1], extra);
    } catch {
      send(res, 500, { error: 'ui asset missing' });
    }
  }

  const server = http.createServer(async (req, res) => {
    let url;
    try { url = new URL(req.url, allowedOrigin()); } catch { return send(res, 400, { error: 'bad request' }); }
    const pathname = url.pathname;
    const method = req.method.toUpperCase();
    const isLocalKeyPath = pathname === '/api/local-key' || pathname === '/api/ai/local-key';

    // ---- Gate 1: Host / DNS-rebinding (outermost, before any auth) ----
    if (String(req.headers.host || '') !== allowedHost()) {
      return send(res, 403, { errorCode: 'HOST_REJECTED', message: 'host rejected' });
    }
    // ---- Gate 2: Origin (absent is allowed for same-origin EventSource) ----
    if (req.headers.origin && req.headers.origin !== allowedOrigin()) {
      return send(res, 403, { errorCode: 'ORIGIN_REJECTED', message: 'origin rejected' });
    }
    if (method === 'OPTIONS') {
      return send(res, 403, { errorCode: 'CORS_DISABLED', message: 'CORS disabled' });
    }
    // ---- Gate 3: CSRF custom header ----
    const isMutation = !['GET', 'HEAD'].includes(method);
    // Canonical header is X-Local-CSRF; X-FCC-CSRF is an accepted alias so the
    // published acceptance contract and the implementation never diverge.
    const csrfOk = req.headers['x-local-csrf'] === '1' || req.headers['x-fcc-csrf'] === '1';
    if (isMutation && !csrfOk) {
      return send(res, 403, { errorCode: 'CSRF_HEADER_MISSING', message: 'missing CSRF header' });
    }

    try {
      // ---- Two-step bootstrap (ticket comes from the navigation cookie) ----
      if (pathname === '/__bootstrap' && method === 'POST') {
        const result = await session.consumeTicket(req);
        if (!result.ok) {
          telemetry.log('warn', 'security.bootstrap-rejected', { reason: result.reason });
          telemetry.audit('session_bootstrap', 'denied', result.reason);
          const consumed = result.reason === 'bootstrap_closed';
          const [status, code, message] = consumed
            ? [410, 'BOOTSTRAP_CONSUMED', '启动端点已关闭，请重启应用重新认证']
            : [403, 'BOOTSTRAP_REJECTED', '启动凭证校验失败，请重新打开应用'];
          return send(res, status, { errorCode: code, message, reason: result.reason });
        }
        telemetry.audit('session_bootstrap', 'success');
        return send(res, 200, { ok: true, listenPort: port }, { 'Set-Cookie': result.cookies });
      }

      // ---- Public, secret-free assets ----
      if (pathname === '/health' && method === 'GET') {
        // Fixed status only: no version, config, credential or uptime fields.
        return send(res, 200, { ok: true });
      }
      if (STATIC[pathname] && method === 'GET') return serveStatic(req, res, pathname);

      // ---- Gate 4: WebUI session OR independent relay key ----
      const isRelay = pathname === RELAY_PATH && method === 'POST';
      if (!isRelay && !session.isValid(req)) {
        session.noteFailedAttempt();
        return send(res, 401, SESSION_INVALID);
      }
      ctx.onActivity?.();

      // ---- SSE (only CSRF-header exemption; all outer gates still apply) ----
      if (pathname === '/api/events' && method === 'GET') {
        res.writeHead(200, {
          ...SECURITY_HEADERS,
          'Content-Type': 'text/event-stream; charset=utf-8',
          'X-Accel-Buffering': 'no',
          Connection: 'keep-alive',
        });
        const unsubscribe = telemetry.subscribe(res);
        req.on('close', unsubscribe);
        return;
      }

      if (pathname === '/api/status' && method === 'GET') return send(res, 200, await buildStatus());
      if (pathname === '/api/vendors' && method === 'GET') return send(res, 200, VENDOR_META);
      if (pathname === '/api/providers' && method === 'GET') return send(res, 200, await vault.list());
      if (pathname === '/api/ddns/records' && method === 'GET') return send(res, 200, config.ddnsRecords);
      if (pathname === '/api/ai/upstreams' && method === 'GET') return send(res, 200, config.aiUpstreams);
      if (pathname === '/api/logs' && method === 'GET') {
        return send(res, 200, telemetry.all(Number(url.searchParams.get('limit') || 100)));
      }
      if (pathname === '/api/audit' && method === 'GET') {
        return send(res, 200, telemetry.auditPage(
          clamp(url.searchParams.get('page') || 1, 1, 100000, 1),
          clamp(url.searchParams.get('size') || 20, 1, 200, 20),
        ));
      }
      if (isLocalKeyPath && method === 'GET') {
        const meta = ctx.getLocalKeyMeta
          ? await ctx.getLocalKeyMeta()
          : { key: await getLocalKey(), createdAt: null };
        const fp = meta.key ? fingerprint(meta.key).slice(-4).toUpperCase() : null;
        return send(res, 200, {
          generated: Boolean(meta.key),
          state: meta.key ? 'active' : 'absent',
          credentialFingerprint: fp,
          credentialMasked: fp ? `${MASK}${fp}` : null,
          fingerprint: fp,
          masked: fp ? `${MASK}${fp}` : null,
          createdAt: meta.createdAt || null,
        });
      }

      if (pathname === '/api/config/export' && method === 'GET') {
        // The parameter is IGNORED. There is no code path that exports a secret.
        if (url.searchParams.get('includeCredentials') === 'true') {
          telemetry.audit('export_credentials_requested', 'denied');
        }
        const providers = (await vault.list()).map((p) => ({
          id: p.id, vendor: p.vendor, displayName: p.displayName,
          enabled: p.enabled, credentialFingerprint: p.credentialFingerprint,
          credentials: MASK,
        }));
        telemetry.audit('export_config', 'success');
        return send(res, 200, {
          schemaVersion: 1,
          exportedAt: iso(),
          credentialsIncluded: false,
          config: sanitizeConfig(config),
          providers,
          notice: '凭据永不导出；导入后需在「云厂商凭据」页重新录入',
        });
      }

      if (!isMutation) return send(res, 404, { error: 'not found' });
      const body = await readBody(req, config.ai.maxBodyBytes);

      // ---- OpenAI-compatible relay: SEPARATE local API key, default closed ----
      if (isRelay) {
        if (!config.ai.enabled) return send(res, 503, { error: { message: 'AI gateway disabled' } });
        const expected = await getLocalKey();
        const hdr = req.headers.authorization;
        const provided = typeof hdr === 'string' && hdr.startsWith('Bearer ') ? hdr.slice(7).trim() : '';
        if (!expected || !provided || !safeEqual(provided, expected)) {
          // Relay auth has its OWN failure budget. Never let relay probes
          // throttle the WebUI session (the two auth paths are independent).
          telemetry.log('warn', 'security.relay-auth-failed', {
            reason: expected ? 'key_invalid' : 'key_absent',
          });
          const absent = !expected;
          return send(res, 401, {
            error: {
              message: absent ? '本机中转密钥未生成，端点已关闭' : '本机中转密钥无效',
              type: 'auth_error',
            },
            errorCode: absent ? 'LOCAL_KEY_REQUIRED' : 'LOCAL_KEY_INVALID',
          });
        }
        await ai.handle(body, res, { requestId: newId('req') });
        return;
      }

      // ---- Local API key lifecycle ----
      if (isLocalKeyPath && method === 'POST') {
        const key = randomBytes(32).toString('base64url');
        await setLocalKey(key);
        telemetry.audit('local_key_generated', 'success');
        const fp = fingerprint(key).slice(-4).toUpperCase();
        // The ONLY response that ever contains the raw key. Never logged,
        // never returned again, never stored in the frontend.
        return sendRaw(res, 201, {
          ok: true,
          key,
          oneTimeKey: key,
          fingerprint: fp,
          masked: `${MASK}${fp}`,
          createdAt: iso(),
          notice: '仅显示这一次，请立即复制保存；关闭后无法再次查看',
        });
      }
      if (isLocalKeyPath && method === 'DELETE') {
        if (body.confirmName !== 'REVOKE_LOCAL_KEY') {
          return send(res, 400, { error: 'confirmName 不匹配' });
        }
        await removeLocalKey();
        telemetry.audit('local_key_revoked', 'success');
        return send(res, 200, { ok: true, state: 'absent' });
      }

      // ---- Provider / credential management ----
      if (pathname === '/api/providers' && method === 'POST') {
        const { vendor, displayName, enabled = true, note = null, purpose = 'both', credentials = {} } = body;
        if (!VENDOR_META[vendor]) return send(res, 400, { error: 'unsupported vendor' });
        // TC28: an offline demo vendor must NEVER accept a pasted real secret.
        if (VENDOR_META[vendor].offline && Object.keys(credentials).length > 0) {
          telemetry.audit('offline_vendor_credentials', 'denied', vendor);
          return send(res, 400, {
            errorCode: 'OFFLINE_VENDOR_NO_CREDENTIALS',
            message: '离线演示厂商不接受任何凭据，请勿粘贴真实密钥',
          });
        }
        const missing = missingSecretFields(vendor, credentials);
        if (vendor !== 'mock' && missing.length) {
          return send(res, 400, { error: '缺少必填凭据字段', fields: missing });
        }
        const id = newId('p');
        const meta = { vendor, displayName: String(displayName || VENDOR_META[vendor].label), enabled: Boolean(enabled), note, purpose };
        await vault.put(id, meta, credentials);
        config.providers = [...(config.providers || []), { id, ...meta }];
        await saveConfig(config);
        telemetry.audit('provider_added', 'success', id);
        return send(res, 201, { id, ...meta, credentials: MASK });
      }

      const testMatch = pathname.match(/^\/api\/providers\/([^/]+)\/test$/);
      if (testMatch && method === 'POST') {
        const entry = await vault.get(testMatch[1]);
        if (!entry) return send(res, 404, { error: 'provider not found' });
        const started = Date.now();
        try {
          const p = createDnsProvider(entry.meta.vendor, entry.secrets);
          const r = await p.test();
          const info = {
            status: r.ok ? 'connected' : 'invalid_credentials',
            lastTestedAt: iso(), latencyMs: Date.now() - started,
            errorCode: r.ok ? null : 'TEST_FAILED',
          };
          providerTests.set(testMatch[1], info);
          telemetry.audit('provider_test', r.ok ? 'success' : 'failure', testMatch[1]);
          return send(res, 200, { ok: r.ok, latencyMs: info.latencyMs, errorCode: info.errorCode });
        } catch (err) {
          providerTests.set(testMatch[1], {
            status: 'error', lastTestedAt: iso(), latencyMs: Date.now() - started,
            errorCode: err instanceof VaultDecryptError ? 'CREDENTIAL_STORE_UNAVAILABLE' : 'TEST_EXCEPTION',
          });
          telemetry.log('warn', 'provider.test', { id: testMatch[1], message: errorCode(err) });
          return send(res, 200, { ok: false, errorCode: 'TEST_EXCEPTION' });
        }
      }

      const rotateMatch = pathname.match(/^\/api\/providers\/([^/]+)\/rotate$/);
      if (rotateMatch && method === 'POST') {
        const id = rotateMatch[1];
        const entry = await vault.get(id);
        if (!entry) return send(res, 404, { error: 'provider not found' });
        if (VENDOR_META[entry.meta.vendor]?.offline && Object.keys(body.credentials || {}).length > 0) {
          return send(res, 400, {
            errorCode: 'OFFLINE_VENDOR_NO_CREDENTIALS',
            message: '离线演示厂商不接受任何凭据，请勿粘贴真实密钥',
          });
        }
        const missing = missingSecretFields(entry.meta.vendor, body.credentials || {});
        if (entry.meta.vendor !== 'mock' && missing.length) {
          return send(res, 400, { error: '缺少必填凭据字段', fields: missing });
        }
        await vault.put(id, entry.meta, body.credentials || {});
        telemetry.audit('provider_rotated', 'success', id);
        return send(res, 200, { ok: true, credentials: MASK });
      }

      const credDel = pathname.match(/^\/api\/providers\/([^/]+)\/credentials$/);
      if (credDel && method === 'DELETE') {
        const entry = await vault.get(credDel[1]);
        if (!entry) return send(res, 404, { error: 'provider not found' });
        if (body.confirmName !== entry.meta.displayName) {
          return send(res, 400, { error: 'confirmName 不匹配' });
        }
        await vault.put(credDel[1], { ...entry.meta, enabled: false }, {});
        telemetry.audit('credentials_cleared', 'success', credDel[1]);
        return send(res, 200, { ok: true });
      }

      const providerPatch = pathname.match(/^\/api\/providers\/([^/]+)$/);
      if (providerPatch && method === 'PATCH') {
        const entry = await vault.get(providerPatch[1]);
        if (!entry) return send(res, 404, { error: 'provider not found' });
        await vault.put(providerPatch[1], { ...entry.meta, enabled: Boolean(body.enabled) }, entry.secrets);
        return send(res, 200, { ok: true });
      }
      if (providerPatch && method === 'DELETE') {
        const entry = await vault.get(providerPatch[1]);
        if (body.confirmName !== entry?.meta?.displayName) {
          return send(res, 400, { error: 'confirmName 不匹配' });
        }
        await vault.remove(providerPatch[1]);
        config.providers = (config.providers || []).filter((p) => p.id !== providerPatch[1]);
        await saveConfig(config);
        telemetry.audit('provider_removed', 'success', providerPatch[1]);
        return send(res, 200, { ok: true });
      }

      // ---- DDNS records ----
      if (pathname === '/api/ddns/records' && method === 'POST') {
        const { domain, name = '@', type = 'A', ttl = 60, vendor = 'mock', providerId = null, zoneId = null } = body;
        if (!DOMAIN_RE.test(String(domain || ''))) return send(res, 400, { error: 'invalid domain' });
        if (!['A', 'AAAA'].includes(type)) return send(res, 400, { error: 'invalid record type' });
        if (vendor !== 'mock' && !providerId) return send(res, 400, { error: 'providerId required' });
        try { await requireBoundCredential(providerId, vendor); } catch (e) {
          return send(res, 400, { error: e.message });
        }
        const rec = {
          id: newId('rec'), domain, name, type,
          ttl: clamp(ttl, 30, 86400, 60), vendor, providerId, zoneId, enabled: true,
        };
        config.ddnsRecords.push(rec);
        await saveConfig(config);
        return send(res, 201, rec);
      }
      const recDel = pathname.match(/^\/api\/ddns\/records\/([^/]+)$/);
      if (recDel && method === 'DELETE') {
        config.ddnsRecords = config.ddnsRecords.filter((r) => r.id !== recDel[1]);
        await saveConfig(config);
        return send(res, 200, { ok: true });
      }
      if (pathname === '/api/ddns/sync' && method === 'POST') {
        return send(res, 200, await ddns.syncOnce({ force: Boolean(body.force), manual: true }));
      }

      // ---- AI upstreams; endpoints ALWAYS come from server-side templates ----
      if (pathname === '/api/ai/upstreams' && method === 'POST') {
        const t = templateForUpstream(body.vendor);
        if (!t) return send(res, 400, { error: 'unsupported vendor' });
        try { await requireBoundCredential(body.providerId, body.vendor); } catch (e) {
          return send(res, 400, { error: e.message });
        }
        const upstream = rebuildUpstream(body, newId('up'));
        upstream.id = newId('up'); // never let an import-shaped payload choose ids
        config.aiUpstreams.push(upstream);
        await saveConfig(config);
        return send(res, 201, upstream);
      }
      if (pathname === '/api/ai/upstreams/order' && method === 'PUT') {
        if (!Array.isArray(body.order)) return send(res, 400, { error: 'order must be an array' });
        for (const item of body.order) {
          const u = config.aiUpstreams.find((x) => x.id === item.providerId);
          if (u) u.priority = clamp(item.priority, 0, 9999, u.priority);
        }
        await saveConfig(config);
        return send(res, 200, config.aiUpstreams);
      }
      const upPatch = pathname.match(/^\/api\/ai\/upstreams\/([^/]+)$/);
      if (upPatch && method === 'PATCH') {
        const u = config.aiUpstreams.find((x) => x.id === upPatch[1]);
        if (!u) return send(res, 404, { error: 'upstream not found' });
        if (typeof body.enabled === 'boolean') u.enabled = body.enabled;
        if (body.priority !== undefined) u.priority = clamp(body.priority, 0, 9999, u.priority);
        await saveConfig(config);
        return send(res, 200, u);
      }

      // ---- Settings / session / import / shutdown ----
      if (pathname === '/api/settings' && method === 'PATCH') {
        const b = body || {};
        if (typeof b.ddnsEnabled === 'boolean') config.ddns.enabled = b.ddnsEnabled;
        if (b.ddnsIntervalSec !== undefined) config.ddns.intervalSec = clamp(b.ddnsIntervalSec, 30, 86400, config.ddns.intervalSec);
        if (b.minAgree !== undefined) config.ddns.minAgree = clamp(b.minAgree, 1, 4, config.ddns.minAgree);
        if (typeof b.aiEnabled === 'boolean') config.ai.enabled = b.aiEnabled;
        if (b.dailyRequestCap !== undefined) config.ai.dailyRequestCap = clamp(b.dailyRequestCap, 1, 1000000, config.ai.dailyRequestCap);
        if (b.logLevel !== undefined && ['info', 'warn', 'error'].includes(b.logLevel)) config.logLevel = b.logLevel;
        if (typeof b.autoStart === 'boolean') {
          // Apply the OS-level entry FIRST. On failure nothing is persisted,
          // so the UI preference and the machine state can never diverge.
          try {
            await applyAutoStart(b.autoStart);
          } catch (e) {
            telemetry.audit('autostart_changed', 'denied', e.message);
            return send(res, 500, {
              errorCode: 'AUTOSTART_FAILED',
              message: '无法写入开机自启项，配置未变更（请检查用户 Startup 目录权限）',
            });
          }
          config.autostart = b.autoStart;
          config.autoStart = b.autoStart;
          telemetry.audit('autostart_changed', 'success', b.autoStart ? 'enabled' : 'disabled');
        }
        await saveConfig(config);
        telemetry.audit('settings_changed', 'success');
        return send(res, 200, { ok: true, autoStart: autoStartState().enabled });
      }

      if (pathname === '/api/session/logout' && method === 'POST') {
        telemetry.audit('session_logout', 'success');
        await session.destroy();
        send(res, 200, { ok: true }, { 'Set-Cookie': session.clearCookieHeader() });
        setTimeout(() => { server.close(); onShutdown(); }, 50);
        return;
      }

      if (pathname === '/api/config/import' && method === 'POST') {
        let payload;
        try { payload = JSON.parse(String(body.payload || '{}')); } catch {
          return send(res, 400, { error: 'payload is not JSON' });
        }
        const imported = payload.config || payload;
        // Only non-secret fields are imported; credentials must be re-entered.
        // C-SSRF: NEVER trust an imported endpoint. Rebuild every upstream
        // from the server-side template, otherwise an allowlisted IP-echo host
        // could receive a cloud credential in its Authorization header.
        if (Array.isArray(imported.aiUpstreams)) {
          const rebuilt = [];
          for (const raw of imported.aiUpstreams.slice(0, 64)) {
            const u = rebuildUpstream(raw, newId('up'));
            if (!u) {
              telemetry.audit('config_imported', 'denied', 'unknown_upstream_vendor');
              return send(res, 400, {
                errorCode: 'IMPORT_UPSTREAM_REJECTED',
                message: '存在未知上游厂商，已拒绝整份导入',
              });
            }
            rebuilt.push(u);
          }
          config.aiUpstreams = rebuilt;
        }
        if (Array.isArray(imported.ddnsRecords)) {
          const records = [];
          for (const r of imported.ddnsRecords.slice(0, 64)) {
            if (!r || typeof r !== 'object' || !DOMAIN_RE.test(String(r.domain || ''))) {
              telemetry.audit('config_imported', 'denied', 'invalid_ddns_record');
              return send(res, 400, {
                errorCode: 'IMPORT_RECORD_REJECTED', message: '存在非法 DDNS 记录，已拒绝整份导入',
              });
            }
            if (!VENDOR_META[r.vendor]) {
              telemetry.audit('config_imported', 'denied', 'unknown_ddns_vendor');
              return send(res, 400, {
                errorCode: 'IMPORT_RECORD_REJECTED', message: '存在未知 DNS 厂商，已拒绝整份导入',
              });
            }
            records.push({
              id: /^[A-Za-z0-9._-]{1,128}$/.test(String(r.id || '')) ? String(r.id) : newId('rec'),
              domain: String(r.domain),
              name: String(r.name || '@').slice(0, 128),
              type: ['A', 'AAAA'].includes(r.type) ? r.type : 'A',
              ttl: clamp(r.ttl, 30, 86400, 60),
              vendor: r.vendor,
              providerId: typeof r.providerId === 'string'
                && /^[A-Za-z0-9._-]{1,128}$/.test(r.providerId) ? r.providerId : null,
              zoneId: typeof r.zoneId === 'string' ? r.zoneId.slice(0, 128) : null,
              enabled: Boolean(r.enabled),
            });
          }
          config.ddnsRecords = records;
        }
        await saveConfig(config);
        telemetry.audit('config_imported', 'success', 'credentials=false;endpoints=server-templates');
        return send(res, 200, { ok: true, credentialsImported: false });
      }

      if (pathname === '/api/shutdown' && method === 'POST') {
        telemetry.audit('shutdown', 'success');
        send(res, 200, { ok: true });
        setTimeout(() => { server.close(); onShutdown(); }, 50);
        return;
      }

      return send(res, 404, { error: 'not found' });
    } catch (err) {
      const isVault = err instanceof VaultDecryptError;
      telemetry.log('error', isVault ? 'security.credential_store_unavailable' : 'server.request-error', {
        path: pathname, message: errorCode(err),
      });
      return send(res, err.status || (isVault ? 503 : 500), {
        errorCode: isVault ? 'CREDENTIAL_STORE_UNAVAILABLE' : (err.status ? 'BAD_REQUEST' : 'INTERNAL_ERROR'),
        message: err.status ? err.message : 'internal error',
      });
    }
  });

  server.on('clientError', (err, socket) => {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });

  return server;
}
