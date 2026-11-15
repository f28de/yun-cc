import { assertUpstream } from '../util.js';

/** Read a response body with a hard byte cap (prevents memory exhaustion). */
async function readLimited(res, maxBytes) {
  const declared = Number(res.headers.get('content-length') || 0);
  if (declared > maxBytes) throw new Error('upstream response too large');
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new Error('upstream response too large');
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
}

/**
 * HTTPS-only request helper with SSRF allowlist, redirect rejection,
 * timeout, and a response size cap. Never logs request bodies.
 */
export async function httpRequest(url, {
  method = 'GET',
  headers = {},
  body,
  timeoutMs = 15000,
  maxBytes = 2 * 1024 * 1024,
  purpose = 'dns', // DNS adapters are the default consumer of this helper
} = {}) {
  assertUpstream(url, purpose);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method,
      headers,
      body,
      signal: ctrl.signal,
      redirect: 'error', // a redirect must never bypass the host allowlist
      cache: 'no-store',
    });
    const text = await readLimited(res, maxBytes);
    return { status: res.status, ok: res.ok, headers: res.headers, text, body: res.body };
  } finally {
    clearTimeout(timer);
  }
}

export async function httpJson(url, options = {}) {
  const res = await httpRequest(url, options);
  let data = null;
  try { data = JSON.parse(res.text); } catch { /* non-JSON upstream */ }
  return { ...res, data };
}

export function okOrThrow(res, label) {
  if (!res.ok) throw new Error(`${label} failed: HTTP ${res.status}`);
  return res;
}
