import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import path from 'node:path';

export const LOOPBACK = '127.0.0.1';

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

export function fingerprint(value) {
  return createHash('sha256').update(String(value)).digest('hex').slice(0, 8);
}

export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

const SENSITIVE_KEY = /(secret|token|password|passwd|passphrase|api[_-]?key|access[_-]?key|credential|authorization|cookie|private|session|prompt|rawbody|rawerror|baseurl|targetip)/i;

// Fields whose NAMES contain a sensitive-looking word but whose VALUES are
// intentionally safe to display (fingerprints, timestamps, booleans, enums).
const REDACT_EXEMPT = /^(credentialFingerprint|credentialMasked|credentialCreatedAt|credentialsEncrypted|credentialsIncluded|credentialsImported|credentialStore|credentialCount|decryptFailed|session|errorCode|lastTestedAt|expiresAt|outboundAnomalies)$/i;

/** Single server-side masking implementation. Frontend never has `raw`. */
export function maskSecret(v) {
  if (v === null || v === undefined) return v;
  const s = String(v);
  // Idempotent: an already-masked placeholder must stay exactly "***".
  if (/^\*{3}$/.test(s) || /^\*\*\*[0-9A-F]{4}$/.test(s)) return s;
  // Hash first, then take 4 hex chars. Never expose a suffix of the plaintext.
  // Fingerprints identify a credential; they never authenticate anything.
  return `***${fingerprint(v).slice(-4).toUpperCase()}`;
}
const mask = maskSecret;

/** Recursively redact any object before it is logged or sent to the UI. */
export function redact(value, depth = 0) {
  if (depth > 8) return '[depth-limit]';
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      const maskIt = !REDACT_EXEMPT.test(k) && SENSITIVE_KEY.test(k);
      out[k] = maskIt ? mask(v) : redact(v, depth + 1);
    }
    return out;
  }
  return value;
}

export function redactText(text) {
  return String(text)
    .replace(/(Bearer\s+)[A-Za-z0-9._\-]+/gi, '$1****')
    .replace(/\bsk-[A-Za-z0-9]{8,}/g, '****')
    .replace(/("(?:secret(?:Id|Key)?|api[_-]?key|token|password|authorization)"\s*:\s*")[^"]*"/gi, '$1****"')
    .replace(/([?&](?:key|token|sig|signature)=)[^&\s]+/gi, '$1****');
}

export async function atomicWrite(file, data, mode = 0o600) {
  await fsp.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  try {
    await fsp.writeFile(tmp, data, { mode });
    await fsp.chmod(tmp, mode).catch(() => {});
    await fsp.rename(tmp, file);
  } finally {
    await fsp.unlink(tmp).catch(() => {});
  }
}

export async function readJson(file, fallback) {
  try {
    return JSON.parse(await fsp.readFile(file, 'utf8'));
  } catch {
    return fallback;
  }
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export const iso = (ts = Date.now()) => new Date(ts).toISOString();

/**
 * SSRF guard, SCOPED BY PURPOSE.
 *
 * A single global allowlist is unsafe: an AI upstream whose endpoint points
 * at an allowlisted public-IP echo host would receive the cloud credential
 * in its Authorization header. Every real request path must therefore declare
 * its purpose, so probes can never be used as AI endpoints (or vice versa).
 *
 *  - 'ai'    : model inference endpoints (requests carry credentials)
 *  - 'dns'   : DNS vendor control planes (requests carry credentials)
 *  - 'probe' : public-IP echo services (must NEVER receive credentials)
 *  - 'any'   : union, for diagnostics/test-only callers; never a request path
 */
const HOST_GROUPS = Object.freeze({
  ai: {
    exact: new Set(['api.cloudflare.com', 'hunyuan.tencentcloudapi.com']),
    patterns: [
      /^[a-z0-9-]+\.openai\.azure\.com$/,
      /^[a-z0-9-]+\.cognitiveservices\.azure\.com$/,
      /^[a-z0-9-]+\.services\.ai\.azure\.com$/,
      /^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$/,
    ],
  },
  dns: {
    exact: new Set([
      'api.cloudflare.com',
      'dnspod.tencentcloudapi.com',
      'route53.amazonaws.com',
      'management.azure.com',
      'login.microsoftonline.com',
    ]),
    patterns: [],
  },
  probe: {
    exact: new Set([
      'api.ipify.org',
      'ipv4.icanhazip.com',
      'ipv6.icanhazip.com',
      'checkip.amazonaws.com',
      'www.cloudflare.com',
      'ifconfig.me',
      'dns.google',
    ]),
    patterns: [],
  },
});

export function isAllowedHost(hostname, purpose = 'any') {
  const h = String(hostname).toLowerCase().replace(/\.$/, '');
  const groups = purpose === 'any' ? Object.values(HOST_GROUPS) : [HOST_GROUPS[purpose]];
  if (groups.some((g) => !g)) return false; // unknown purpose => fail closed
  return groups.some((g) => g.exact.has(h) || g.patterns.some((re) => re.test(h)));
}

export function assertUpstream(rawUrl, purpose = 'any') {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new Error('invalid upstream URL');
  }
  if (u.protocol !== 'https:') throw new Error('upstream must use https');
  if (u.username || u.password) throw new Error('userinfo in upstream URL is forbidden');
  if (u.port && u.port !== '443') throw new Error('custom upstream port is forbidden');
  if (u.search) {
    for (const key of u.searchParams.keys()) {
      if (SENSITIVE_KEY.test(key)) throw new Error('credentials in upstream query are forbidden');
    }
  }
  const h = u.hostname.toLowerCase().replace(/\.$/, '');
  const isIpLiteral = /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith('[');
  if (isIpLiteral || h === 'localhost' || h.endsWith('.local')) {
    throw new Error('IP-literal / local upstream is forbidden');
  }
  if (h === '169.254.169.254' || h.endsWith('.internal') || h.endsWith('.localhost')) {
    throw new Error('metadata / internal upstream is forbidden');
  }
  if (!HOST_GROUPS[purpose] && purpose !== 'any') {
    throw new Error(`unknown upstream purpose: ${purpose}`);
  }
  if (!isAllowedHost(h, purpose)) throw new Error(`upstream host not in ${purpose} allowlist: ${h}`);
  return u;
}

/** Minimal logger: everything is redacted before it reaches disk or stdout. */
export function createLogger(sink = console.log) {
  return (level, event, detail = {}) => {
    const line = JSON.stringify({
      t: iso(),
      level,
      event,
      detail: redact(detail),
    });
    sink(redactText(line));
  };
}
