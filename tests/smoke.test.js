import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';

// Isolate all state BEFORE any module reads FCC_DATA_DIR.
const TMP = await mkdtemp(path.join(os.tmpdir(), 'fcc-smoke-'));
process.env.FCC_DATA_DIR = TMP;
process.env.FCC_STARTUP_DIR = path.join(TMP, 'startup');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const { bootstrap } = await import('../src/core.js');
const { createMemoryVault } = await import('../src/secrets.js');
const { DEFAULTS, defaultAiUpstreams, PATHS, AI_UPSTREAM_TEMPLATES } = await import('../src/config.js');
const { assertUpstream, redact, maskSecret } = await import('../src/util.js');
const { createSessionStore } = await import('../src/auth.js');
const { createDdnsEngine } = await import('../src/ddns.js');
const { createAiGateway } = await import('../src/ai-gateway.js');
const { buildUpstreamRequest } = await import('../src/providers/ai.js');
const { applyAutoStart, autoStartState, entryPath } = await import('../src/autostart.js');
const { mockStore } = await import('../src/providers/dns-mock.js');

function baseConfig() {
  const c = JSON.parse(JSON.stringify(DEFAULTS));
  c.ddns.enabled = false;                 // no background probing during tests
  c.ddns.probeUrls = [];
  c.session = { idleTimeoutSec: 0 };      // no idle expiry during tests
  c.ai.maxBodyBytes = 4096;
  c.aiUpstreams = [{
    id: 'up_mock', vendor: 'mock', name: 'Local Mock', kind: 'mock',
    endpoint: 'mock://local', model: 'mock-1', auth: 'none',
    priority: 1, enabled: true, dailyCap: 1000,
  }];
  c.ddnsRecords = [];
  c.providers = [];
  return c;
}

let app;
let port;
let cookie;
let localKey;

const url = (p) => `http://127.0.0.1:${port}${p}`;
const cookiesOf = (r) => (r.headers.getSetCookie ? r.headers.getSetCookie()
  : [r.headers.get('set-cookie')].filter(Boolean));

function rawRequest(pathname, headers) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, path: pathname, method: 'GET', headers,
    }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    req.on('error', reject);
    req.end();
  });
}

const NAV_HEADERS = {
  'Sec-Fetch-Dest': 'document',
  'Sec-Fetch-Mode': 'navigate',
  'Sec-Fetch-Site': 'none',
};

async function auth(pathname, init = {}) {
  const method = init.method || 'GET';
  const headers = { Cookie: cookie, ...(init.headers || {}) };
  if (method !== 'GET') headers['X-FCC-CSRF'] = '1';
  if (init.body !== undefined) headers['Content-Type'] = 'application/json';
  return fetch(url(pathname), {
    method, headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
}

before(async () => {
  app = await bootstrap({
    config: baseConfig(),
    vault: createMemoryVault(),
    requireSecFetch: false,   // test seam only; production default is true
    probe: async () => [],
    sink: () => {},
  });
  port = app.port;
});

after(async () => {
  if (app) await app.close();
  await rm(TMP, { recursive: true, force: true });
});

test('01 /health returns exactly the fixed literal status', async () => {
  const r = await fetch(url('/health'));
  const body = await r.json();
  console.log('[evidence] GET /health ->', JSON.stringify(body));
  assert.equal(r.status, 200);
  assert.deepEqual(body, { ok: true });
  assert.ok(!('version' in body) && !('port' in body) && !('config' in body));
});

test('02 Host header spoof is rejected before any auth', async () => {
  const r = await rawRequest('/health', { Host: 'evil.example.com' });
  assert.equal(r.status, 403);
  assert.match(r.body, /HOST_REJECTED/);
});

test('03 cross-origin Origin is rejected', async () => {
  const r = await fetch(url('/health'), { headers: { Origin: 'http://evil.example.com' } });
  assert.equal(r.status, 403);
});

test('04 /api/status without a session returns 401 SESSION_INVALID', async () => {
  const r = await fetch(url('/api/status'));
  const b = await r.json();
  assert.equal(r.status, 401);
  assert.equal(b.errorCode, 'SESSION_INVALID');
});

test('05 mutation without CSRF header returns 403', async () => {
  // Do NOT navigate here: that would issue (but not consume) the one-shot
  // ticket before test 06. The CSRF gate runs before bootstrap anyway.
  const r = await fetch(url('/__bootstrap'), { method: 'POST', headers: { Cookie: '__bt=invalid' } });
  assert.equal(r.status, 403);
  assert.match(r.headers.get('content-type') || '', /json/);
});

test('06 two-step bootstrap: navigation ticket -> one-shot exchange -> session cookie', async () => {
  const nav = await fetch(url('/'), { headers: NAV_HEADERS });
  assert.equal(nav.status, 200);
  const navCookies = cookiesOf(nav);
  const bt = navCookies.map((c) => c.split(';')[0]).find((c) => c.startsWith('__bt='));
  assert.ok(bt, 'navigation must issue an HttpOnly __bt ticket');
  assert.ok(navCookies.some((c) => /Path=\/__bootstrap/.test(c) && /HttpOnly/.test(c)));

  const r = await fetch(url('/__bootstrap'), {
    method: 'POST',
    headers: {
      'X-FCC-CSRF': '1',
      'Sec-Fetch-Site': 'same-origin',
      Cookie: bt,
    },
  });
  assert.equal(r.status, 200);
  const issued = cookiesOf(r);
  const sid = issued.map((c) => c.split(';')[0]).find((c) => c.startsWith('fcc_session='));
  assert.ok(sid, 'session cookie must be issued');
  const sidHeader = issued.find((c) => c.startsWith('fcc_session='));
  assert.match(sidHeader, /HttpOnly/);
  assert.match(sidHeader, /SameSite=Strict/);
  assert.ok(!/Max-Age|Expires|Domain|Secure/i.test(sidHeader), 'session cookie must be session-scoped');
  cookie = sid;

  const body = await r.json();
  assert.equal(body.ok, true);
  assert.equal(body.listenPort, port);
});

test('07 bootstrap is one-shot: second exchange returns 410 BOOTSTRAP_CONSUMED', async () => {
  const r = await fetch(url('/__bootstrap'), {
    method: 'POST',
    headers: { 'X-FCC-CSRF': '1', 'Sec-Fetch-Site': 'same-origin', Cookie: cookie },
  });
  assert.equal(r.status, 410);
  assert.equal((await r.json()).errorCode, 'BOOTSTRAP_CONSUMED');
});

test('08 /api/status exposes the full contract without any secret material', async () => {
  const r = await auth('/api/status');
  assert.equal(r.status, 200);
  const s = await r.json();
  assert.equal(s.schemaVersion, 1);
  assert.equal(s.security.loopbackOnly, true);
  assert.equal(s.security.listenPort, port);
  assert.deepEqual(s.security.listenAddresses, [`127.0.0.1:${port}`]);
  assert.equal(s.ai.localKey.state, 'absent');
  assert.equal(s.ai.localKey.masked, null);
  assert.equal(s.security.localKeyEnabled, false);
  assert.ok(Array.isArray(s.security.auditRecent));
  assert.equal(s.security.auditRecent[0].actor, 'local');
  assert.equal(s.security.credentialsEncrypted, false, 'memory vault must be reported honestly');
  assert.ok(!JSON.stringify(s).includes('SUPERSECRET'));
});

test('09 server is bound to loopback only', () => {
  assert.equal(app.server.address().address, '127.0.0.1');
  assert.ok(app.port > 0);
});

test('10 C12 hard gate refuses a non-loopback listen config', async () => {
  const bad = baseConfig();
  bad.listen = { host: '0.0.0.0', port: 0 };
  await assert.rejects(
    () => bootstrap({ config: bad, vault: createMemoryVault(), sink: () => {} }),
    /C12/,
  );
});

test('11 SSRF allowlist rejects metadata, plaintext HTTP, userinfo, IP literals and custom ports', () => {
  const bad = [
    'https://169.254.169.254/latest/meta-data/',
    'http://api.cloudflare.com/x',
    'https://user:pass@api.cloudflare.com/x',
    'https://127.0.0.1/x',
    'https://2130706433/x',
    'https://api.cloudflare.com:8443/x',
    'https://169.254.169.254.evil.com/x',
    'https://evil.example.com/x',
  ];
  for (const u of bad) assert.throws(() => assertUpstream(u), undefined, u);
  assert.doesNotThrow(() => assertUpstream('https://api.cloudflare.com/client/v4/accounts/x/ai/v1/chat/completions'));
  assert.doesNotThrow(() => assertUpstream('https://bedrock-runtime.us-east-1.amazonaws.com/model/x/invoke'));
});

test('12 masking is a single hash-derived function, never a plaintext suffix', () => {
  const m = maskSecret('SUPERSECRET1234');
  assert.match(m, /^\*\*\*[0-9A-F]{4}$/);
  assert.ok(!m.includes('1234'));
  const red = redact({ apiToken: 'SUPERSECRET1234', credentialFingerprint: '8F2C', credentialMasked: '***8F2C' });
  assert.ok(!JSON.stringify(red).includes('SUPERSECRET'));
  assert.equal(red.credentialFingerprint, '8F2C');
  assert.equal(red.credentialMasked, '***8F2C');
});

test('13 relay is fail-closed when no local key exists', async () => {
  const r = await fetch(url('/v1/chat/completions'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-FCC-CSRF': '1' },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'hi' }] }),
  });
  assert.equal(r.status, 401);
  assert.equal((await r.json()).errorCode, 'LOCAL_KEY_REQUIRED');
});

test('14 generating the local key returns it exactly once', async () => {
  const r = await auth('/api/ai/local-key', { method: 'POST', body: {} });
  assert.equal(r.status, 201);
  const b = await r.json();
  assert.ok(b.key && b.key.length >= 40);
  assert.match(b.masked, /^\*\*\*[0-9A-F]{4}$/);
  localKey = b.key;

  const status = await (await auth('/api/status')).json();
  assert.equal(status.ai.localKey.state, 'active');
  assert.equal(status.ai.localKey.masked, b.masked);
  assert.ok(!JSON.stringify(status).includes(localKey));

  const logs = await (await auth('/api/logs')).json();
  assert.ok(!JSON.stringify(logs).includes(localKey));
  const exp = await (await auth('/api/config/export')).json();
  assert.ok(!JSON.stringify(exp).includes(localKey));
});

test('15 empty / arbitrary / WebUI-session Bearer are all rejected', async () => {
  for (const authHeader of [undefined, 'Bearer nope', `Bearer ${cookie}`]) {
    const h = { 'Content-Type': 'application/json', 'X-FCC-CSRF': '1' };
    if (authHeader) h.Authorization = authHeader;
    const r = await fetch(url('/v1/chat/completions'), {
      method: 'POST', headers: h,
      body: JSON.stringify({ messages: [{ role: 'user', content: 'hi' }] }),
    });
    assert.equal(r.status, 401);
  }
});

test('16 valid local key proxies an OpenAI-compatible completion', async () => {
  const r = await fetch(url('/v1/chat/completions'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json', 'X-FCC-CSRF': '1',
      Authorization: `Bearer ${localKey}`,
    },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'hello' }] }),
  });
  assert.equal(r.status, 200);
  const b = await r.json();
  assert.equal(b.object, 'chat.completion');
  assert.equal(b.choices[0].message.role, 'assistant');
  assert.ok(b.choices[0].message.content.includes('演示模式'));
});

test('17 streaming returns an SSE body ending with [DONE]', async () => {
  const r = await fetch(url('/v1/chat/completions'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json', 'X-FCC-CSRF': '1',
      Authorization: `Bearer ${localKey}`,
    },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'hi' }], stream: true }),
  });
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /text\/event-stream/);
  const text = await r.text();
  assert.match(text, /data: \{/);
  assert.match(text, /data: \[DONE\]/);
  assert.ok(!text.includes(localKey));
});

test('18 request body over the size cap is rejected with 413', async () => {
  const r = await fetch(url('/v1/chat/completions'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json', 'X-FCC-CSRF': '1',
      Authorization: `Bearer ${localKey}`,
    },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'x'.repeat(9000) }] }),
  });
  assert.equal(r.status, 413);
});

test('19 export ignores includeCredentials and is always sanitised', async () => {
  for (const suffix of ['', '?includeCredentials=true']) {
    const r = await auth(`/api/config/export${suffix}`);
    assert.equal(r.status, 200);
    const b = await r.json();
    assert.equal(b.credentialsIncluded, false);
    assert.ok(!JSON.stringify(b).includes(localKey));
  }
});

test('20 provider credentials are never echoed back', async () => {
  const r = await auth('/api/providers', {
    method: 'POST',
    body: {
      vendor: 'cloudflare', displayName: 'CF Test',
      credentials: { apiToken: 'SUPERSECRET_CF_TOKEN' },
    },
  });
  assert.equal(r.status, 201);
  assert.ok(!JSON.stringify(await r.json()).includes('SUPERSECRET_CF_TOKEN'));
  const list = await (await auth('/api/providers')).json();
  const p = list.find((x) => x.displayName === 'CF Test');
  assert.match(p.credentialMasked, /^\*\*\*[0-9A-F]{4}$/);
  assert.ok(!JSON.stringify(list).includes('SUPERSECRET_CF_TOKEN'));

  // TC28 folded into this case (26-assertion set is preserved):
  // an offline demo vendor must reject pasted real credentials outright,
  // and vendor/credential mismatches must be rejected at write time.
  const offline = await auth('/api/providers', {
    method: 'POST',
    body: { vendor: 'mock', displayName: 'Mock Dirty', credentials: { apiToken: 'SUPERSECRET_LEAK' } },
  });
  assert.equal(offline.status, 400);
  assert.equal((await offline.json()).errorCode, 'OFFLINE_VENDOR_NO_CREDENTIALS');

  const clean = await auth('/api/providers', {
    method: 'POST',
    body: { vendor: 'mock', displayName: 'Mock Clean', credentials: {} },
  });
  assert.equal(clean.status, 201);
  const mockId = (await clean.json()).id;

  const badRecord = await auth('/api/ddns/records', {
    method: 'POST',
    body: { domain: 'example.com', name: '@', type: 'A', vendor: 'cloudflare', providerId: mockId },
  });
  assert.equal(badRecord.status, 400);
  const badUpstream = await auth('/api/ai/upstreams', {
    method: 'POST',
    body: { vendor: 'cloudflare', providerId: mockId, model: 'x' },
  });
  assert.equal(badUpstream.status, 400);
  const exported = await (await auth('/api/config/export')).json();
  assert.ok(!JSON.stringify(exported).includes('SUPERSECRET_LEAK'));
});

test('21 SSE endpoint requires a session and streams with the right headers', async () => {
  const anon = await fetch(url('/api/events'));
  assert.equal(anon.status, 401);
  const ctrl = new AbortController();
  const r = await fetch(url('/api/events'), { headers: { Cookie: cookie }, signal: ctrl.signal });
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /text\/event-stream/);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('cache-control'), 'no-store, max-age=0');
  ctrl.abort();
});

test('22 audit records are exposed with a local actor', async () => {
  const b = await (await auth('/api/audit')).json();
  assert.ok(Array.isArray(b.items));
  assert.ok(b.items.some((i) => i.actor === 'local'));
});

test('23 revoking the key immediately re-closes the relay', async () => {
  const r = await auth('/api/ai/local-key', { method: 'DELETE', body: { confirmName: 'REVOKE_LOCAL_KEY' } });
  assert.equal(r.status, 200);
  const afterRevoke = await fetch(url('/v1/chat/completions'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json', 'X-FCC-CSRF': '1',
      Authorization: `Bearer ${localKey}`,
    },
    body: JSON.stringify({ messages: [{ role: 'user', content: 'hi' }] }),
  });
  assert.equal(afterRevoke.status, 401);
  assert.equal((await afterRevoke.json()).errorCode, 'LOCAL_KEY_REQUIRED');
});

test('24 DDNS requires probe consensus: conflicting sources cause no update', async () => {
  mockStore.clear();
  const cfg = baseConfig();
  cfg.ddns.enabled = true;
  cfg.ddns.minAgree = 2;
  cfg.ddnsRecords = [{
    id: 'rec_1', domain: 'example.com', name: '@', type: 'A',
    vendor: 'mock', enabled: true,
  }];
  const votes = ['1.1.1.1', '2.2.2.2'];
  const engine = createDdnsEngine({
    config: cfg, vault: createMemoryVault(), emit: () => {}, log: () => {},
    state: {}, saveState: async () => {}, probe: async () => votes,
  });
  const out = await engine.syncOnce({ force: true });
  assert.equal(out.ok, false);
  assert.equal(out.reason, 'no-consensus');
  assert.equal(mockStore.get('example.com/@/A'), undefined);
});

test('25 DDNS updates on consensus and skips DNS calls when the IP is unchanged', async () => {
  mockStore.clear();
  const cfg = baseConfig();
  cfg.ddns.enabled = true;
  cfg.ddns.minAgree = 2;
  cfg.ddnsRecords = [{
    id: 'rec_1', domain: 'example.com', name: '@', type: 'A',
    vendor: 'mock', enabled: true,
  }];
  const events = [];
  const engine = createDdnsEngine({
    config: cfg, vault: createMemoryVault(),
    emit: (n, p) => events.push([n, p]), log: () => {},
    state: {}, saveState: async () => {},
    probe: async () => ['1.1.1.1', '1.1.1.1'],
  });
  const first = await engine.syncOnce({ force: true });
  assert.equal(first.ok, true);
  assert.equal(mockStore.get('example.com/@/A'), '1.1.1.1');
  assert.ok(events.some(([n]) => n === 'ip-changed'));

  mockStore.set('example.com/@/A', '9.9.9.9');
  const second = await engine.syncOnce();
  assert.equal(second.unchanged, true);
  assert.equal(mockStore.get('example.com/@/A'), '9.9.9.9', 'no DNS call when IP unchanged');
});

test('26 decrypt failure is surfaced as fail-closed, never silently skipped', async () => {
  const v = createMemoryVault();
  await v.put('p_broken', { vendor: 'cloudflare', displayName: 'Broken' }, { apiToken: 'x' });
  v.__failDecrypt('p_broken');
  const list = await v.list();
  assert.equal(list.find((p) => p.id === 'p_broken').decryptFailed, true);
  await assert.rejects(() => v.get('p_broken'), /credential_store_unavailable/);
  assert.deepEqual(v.failedIds(), ['p_broken']);
});

// ---- Regression set for the final security review ------------------------

test('27 SSRF allowlist is purpose-scoped: an IP probe can never be an AI endpoint', () => {
  assert.throws(() => assertUpstream('https://api.ipify.org/?format=json', 'ai'), /ai allowlist/);
  assert.throws(() => assertUpstream('https://www.cloudflare.com/cdn-cgi/trace', 'ai'), /ai allowlist/);
  assert.throws(() => assertUpstream('https://management.azure.com/x', 'ai'), /ai allowlist/);
  assert.throws(() => assertUpstream('https://api.cloudflare.com/client/v4/x', 'probe'), /probe allowlist/);
  assert.throws(() => assertUpstream('https://api.cloudflare.com/x', 'bogus'), /unknown upstream purpose/);
  assert.doesNotThrow(() => assertUpstream('https://api.ipify.org/?format=json', 'probe'));
  assert.doesNotThrow(() => assertUpstream('https://api.cloudflare.com/client/v4/x', 'ai'));
  assert.doesNotThrow(() => assertUpstream('https://management.azure.com/x', 'dns'));
});

test('28 a forged endpoint is rejected before any credential reaches the wire', () => {
  const forged = {
    vendor: 'cloudflare', kind: 'openai-compatible', model: 'x',
    endpoint: 'https://api.ipify.org/steal',
  };
  assert.throws(
    () => buildUpstreamRequest(forged, { accountId: 'acc', apiToken: 'SUPERSECRET_TOKEN' }, { messages: [] }),
    /ai allowlist/,
  );
  const good = buildUpstreamRequest(
    { ...forged, endpoint: AI_UPSTREAM_TEMPLATES.cloudflare.endpoint },
    { accountId: 'acc', apiToken: 't' }, { messages: [] },
  );
  assert.equal(new URL(good.url).hostname, 'api.cloudflare.com');
});

test('29 config import rebuilds every endpoint from server-side templates', async () => {
  const bad = await auth('/api/config/import', {
    method: 'POST',
    body: { payload: JSON.stringify({ config: { aiUpstreams: [{ vendor: 'evil', endpoint: 'https://api.ipify.org/steal' }] } }) },
  });
  assert.equal(bad.status, 400);
  assert.equal((await bad.json()).errorCode, 'IMPORT_UPSTREAM_REJECTED');

  const forged = await auth('/api/config/import', {
    method: 'POST',
    body: { payload: JSON.stringify({ config: {
      aiUpstreams: [
        { id: 'up_mock', vendor: 'mock', name: 'Local Mock', kind: 'openai-compatible',
          endpoint: 'https://api.ipify.org/steal', model: 'mock-1', enabled: true, priority: 1 },
        { id: 'up_cf', vendor: 'cloudflare', name: 'CF', kind: 'mock',
          endpoint: 'https://www.cloudflare.com/cdn-cgi/trace', model: 'x', enabled: false, priority: 2 },
      ],
      ddnsRecords: [{ id: 'r1', domain: 'example.com', name: '@', type: 'A', vendor: 'mock', enabled: true }],
    } }) },
  });
  assert.equal(forged.status, 200);
  const exp = await (await auth('/api/config/export')).json();
  const text = JSON.stringify(exp);
  assert.ok(!text.includes('api.ipify.org') && !text.includes('cdn-cgi/trace'));
  assert.equal(exp.config.aiUpstreams.length, 2);
  assert.equal(exp.config.aiUpstreams[0].endpoint, 'mock://local');
  assert.equal(exp.config.aiUpstreams[0].kind, 'mock');
  assert.equal(exp.config.aiUpstreams[1].endpoint, AI_UPSTREAM_TEMPLATES.cloudflare.endpoint);
  assert.equal(exp.config.aiUpstreams[1].kind, 'openai-compatible');
  assert.equal(exp.credentialsIncluded, false);

  // Restore a mock-only configuration.
  const restore = await auth('/api/config/import', {
    method: 'POST', body: { payload: JSON.stringify({ config: baseConfig() }) },
  });
  assert.equal(restore.status, 200);
});

/** Drive a two-upstream gateway (real -> mock) with a controlled upstream reply. */
async function driveGateway(makeResponse) {
  const cfg = baseConfig();
  cfg.ai.requestTimeoutMs = 3000;
  cfg.aiUpstreams = [
    { id: 'u_real', vendor: 'cloudflare', kind: 'openai-compatible',
      endpoint: AI_UPSTREAM_TEMPLATES.cloudflare.endpoint, model: 'm',
      priority: 1, enabled: true, dailyCap: 100, providerId: 'p_cf' },
    { id: 'u_mock', vendor: 'mock', kind: 'mock', endpoint: 'mock://local',
      model: 'mock-1', priority: 2, enabled: true, dailyCap: 100 },
  ];
  const v = createMemoryVault();
  await v.put('p_cf', { vendor: 'cloudflare' }, { accountId: 'acc1', apiToken: 'tok' });
  const gw = createAiGateway({ config: cfg, vault: v, emit: () => {}, log: () => {} });
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => { calls += 1; return makeResponse(); };
  const out = { code: 0, body: '' };
  const res = {
    headersSent: false,
    writeHead(c) { this.headersSent = true; out.code = c; },
    write(c) { out.body += String(c || ''); },
    end(c) { out.body += String(c || ''); },
  };
  try {
    await gw.handle({ messages: [{ role: 'user', content: 'hi' }] }, res, { requestId: 't' });
  } finally {
    globalThis.fetch = original;
  }
  return { ...out, calls };
}

const upstreamReply = (status, headers) => () => new Response(
  JSON.stringify({ error: { message: 'upstream overloaded' } }),
  { status, headers: { 'content-type': 'application/json', ...headers } },
);

test('30 a 5xx with Retry-After is quota exhaustion and must NOT fail over', async () => {
  const r = await driveGateway(upstreamReply(503, { 'retry-after': '60' }));
  assert.equal(r.calls, 1);
  assert.equal(r.code, 429);
  assert.match(r.body, /quota_exhausted/);
  assert.ok(!r.body.includes('演示模式'), 'the second provider must not be reached');
});

test('31 a plain 5xx without quota signals is still failover-eligible', async () => {
  const r = await driveGateway(upstreamReply(503, {}));
  assert.equal(r.calls, 1);
  assert.equal(r.code, 200);
  assert.match(r.body, /演示模式/, 'must fall through to the mock upstream');
});

test('32 session token is memory-only and legacy plaintext is purged', async () => {
  await assert.rejects(() => readFile(PATHS.session, 'utf8'));
  await writeFile(PATHS.session, 'LEGACY_PLAINTEXT_TOKEN', 'utf8');
  createSessionStore({ requireSecFetch: false });
  await new Promise((r) => setTimeout(r, 100));
  await assert.rejects(() => readFile(PATHS.session, 'utf8'));
});

test('33 selftest exit status requires EVERY check to pass', () => {
  const raw = execFileSync(process.execPath, ['src/main.js', '--selftest'], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000,
  });
  const out = JSON.parse(raw.slice(raw.indexOf('{')));
  assert.equal(Object.keys(out.checks).length, 6);
  assert.equal(out.ok, Object.values(out.checks).every(Boolean));
  assert.equal(out.ok, true);
});

test('34 autostart is really wired, and disabling never deletes a foreign file', async () => {
  const dir = process.env.FCC_STARTUP_DIR;
  const on = await auth('/api/settings', { method: 'PATCH', body: { autoStart: true } });
  assert.equal(on.status, 200);
  assert.equal((await on.json()).autoStart, true);
  const st = await (await auth('/api/status')).json();
  assert.equal(st.security.autoStart, true);
  assert.equal(st.security.autoStartSupported, true);
  assert.equal(typeof st.security.session.expiresAt, 'string');
  assert.equal(st.security.session.idleTimeoutSec, 0, 'tests disable idle expiry');
  assert.equal(st.security.session.absoluteTtlSec, 28800);

  const p = entryPath(dir);
  assert.match(await readFile(p, 'utf8'), /FreeCloudConsole managed autostart entry/);
  const off = await auth('/api/settings', { method: 'PATCH', body: { autoStart: false } });
  assert.equal(off.status, 200);
  assert.equal((await off.json()).autoStart, false);
  await assert.rejects(() => readFile(p, 'utf8'));

  const foreign = '@echo off\r\n:: not ours\r\n';
  await applyAutoStart(true, dir);
  await writeFile(p, foreign, 'utf8');
  await applyAutoStart(false, dir);
  assert.equal(await readFile(p, 'utf8'), foreign, 'marker-checked removal must leave it alone');
});
