import path from 'node:path';
import os from 'node:os';
import { readJson, atomicWrite, LOOPBACK, redact } from './util.js';

const dataRoot = process.env.FCC_DATA_DIR || path.join(
  process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'),
  'FreeCloudConsole',
);

export const PATHS = Object.freeze({
  base: dataRoot,
  config: path.join(dataRoot, 'config.json'),
  vault: path.join(dataRoot, 'vault.bin'),
  state: path.join(dataRoot, 'state.json'),
  session: path.join(dataRoot, 'session.token'), // legacy plaintext artifact; deleted on startup, never written
  log: path.join(dataRoot, 'events.log'),
});

export const DEFAULTS = Object.freeze({
  // The listen host is hard-coded and intentionally NOT configurable.
  ddns: {
    enabled: true,
    intervalSec: 300,
    minAgree: 2,
    maxBackoffSec: 900,
    ipv6: false,
    probeUrls: [
      'https://api.ipify.org?format=json',
      'https://ipv4.icanhazip.com',
      'https://checkip.amazonaws.com',
      'https://www.cloudflare.com/cdn-cgi/trace',
    ],
  },
  ai: {
    enabled: true,
    requestTimeoutMs: 60000,
    maxBodyBytes: 1048576,
    circuitFailures: 3,
    cooldownSec: 60,
    dailyRequestCap: 1000,
    streamIdleTimeoutMs: 120000,
  },
  ui: { eventBuffer: 200, refreshFallbackSec: 30 },
  logLevel: 'info',
  autostart: false,
  // Non-secret metadata only. All credentials live in the encrypted vault.
  providers: [],
  ddnsRecords: [],
  aiUpstreams: [],
});

/** Secrets must never be written into config.json, even by mistake. */
const FORBIDDEN_TOP_LEVEL = /^(secret|token|password|credential|key)/i;

export function sanitizeConfig(config) {
  const out = {};
  for (const [k, v] of Object.entries(config)) {
    if (FORBIDDEN_TOP_LEVEL.test(k)) continue;
    out[k] = redact(v);
  }
  return out;
}

export async function loadConfig() {
  const disk = await readJson(PATHS.config, {});
  const merged = {
    ...structuredClone(DEFAULTS),
    ...disk,
    ddns: { ...DEFAULTS.ddns, ...(disk.ddns || {}) },
    ai: { ...DEFAULTS.ai, ...(disk.ai || {}) },
    ui: { ...DEFAULTS.ui, ...(disk.ui || {}) },
  };
  // Security invariant: never allow binding to anything except loopback.
  merged.listen = { host: LOOPBACK, port: 0 };
  // A hand-edited config.json must not be able to install a forged endpoint.
  if (Array.isArray(disk.aiUpstreams)) {
    merged.aiUpstreams = disk.aiUpstreams
      .map((u, i) => rebuildUpstream(u, `up_restored_${i}`))
      .filter(Boolean);
  }
  return merged;
}

export async function saveConfig(config) {
  const clean = sanitizeConfig(config);
  delete clean.listen;
  await atomicWrite(PATHS.config, JSON.stringify(clean, null, 2));
  return clean;
}

/**
 * Authoritative server-side upstream templates. A client may enable, reorder
 * or cap an upstream, but can NEVER supply its own endpoint / kind / auth.
 * This is also the allowlist used when rebuilding an imported configuration.
 */
export const AI_UPSTREAM_TEMPLATES = Object.freeze({
  cloudflare: Object.freeze({
    kind: 'openai-compatible',
    endpoint: 'https://api.cloudflare.com/client/v4/accounts/{accountId}/ai/v1/chat/completions',
    model: '@cf/meta/llama-3.1-8b-instruct', auth: 'bearer',
  }),
  azure: Object.freeze({
    kind: 'azure-openai',
    endpoint: 'https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version=2024-10-21',
    model: 'gpt-4o-mini', auth: 'azure-api-key',
  }),
  tencent: Object.freeze({
    kind: 'tencent-tc3',
    endpoint: 'https://hunyuan.tencentcloudapi.com/',
    model: 'hunyuan-lite', auth: 'tc3-hmac-sha256',
  }),
  aws: Object.freeze({
    kind: 'aws-bedrock',
    endpoint: 'bedrock',
    model: 'amazon.titan-text-express-v1', auth: 'sigv4',
  }),
  mock: Object.freeze({
    kind: 'mock', endpoint: 'mock://local', model: 'mock-1', auth: 'none',
  }),
});

export function templateForUpstream(vendor) {
  return AI_UPSTREAM_TEMPLATES[vendor] || null;
}

/** Rebuild an upstream from the trusted template, keeping only safe fields. */
export function rebuildUpstream(raw, fallbackId) {
  const t = templateForUpstream(raw?.vendor);
  if (!t) return null;
  const n = (v, lo, hi, dflt) => (Number.isFinite(Number(v))
    ? Math.min(hi, Math.max(lo, Number(v))) : dflt);
  const ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
  return {
    id: ID_RE.test(String(raw.id || '')) ? String(raw.id) : fallbackId,
    vendor: raw.vendor,
    name: String(raw.name || raw.vendor).slice(0, 128),
    kind: t.kind,
    endpoint: t.endpoint,
    model: String(raw.model || t.model).slice(0, 128),
    auth: t.auth,
    providerId: typeof raw.providerId === 'string' && ID_RE.test(raw.providerId)
      ? raw.providerId : null,
    priority: n(raw.priority, 0, 9999, 100),
    enabled: Boolean(raw.enabled),
    dailyCap: n(raw.dailyCap, 1, 1000000, 1000),
  };
}

export function defaultAiUpstreams() {
  return [
    {
      id: 'cf-workers-ai',
      name: 'Cloudflare Workers AI',
      vendor: 'cloudflare',
      kind: 'openai-compatible',
      endpoint: 'https://api.cloudflare.com/client/v4/accounts/{accountId}/ai/v1/chat/completions',
      model: '@cf/meta/llama-3.1-8b-instruct',
      auth: 'bearer',
      priority: 10,
      enabled: true,
      dailyCap: 1000,
    },
    {
      id: 'azure-openai',
      name: 'Azure OpenAI',
      vendor: 'azure',
      kind: 'azure-openai',
      endpoint: 'https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions?api-version=2024-10-21',
      model: 'gpt-4o-mini',
      auth: 'azure-api-key',
      priority: 20,
      enabled: false,
      dailyCap: 1000,
    },
    {
      id: 'tencent-hunyuan',
      name: 'Tencent Hunyuan',
      vendor: 'tencent',
      kind: 'tencent-tc3',
      endpoint: 'https://hunyuan.tencentcloudapi.com/',
      model: 'hunyuan-lite',
      auth: 'tc3-hmac-sha256',
      priority: 30,
      enabled: false,
      dailyCap: 1000,
    },
    {
      id: 'local-mock',
      name: 'Local Mock (offline demo)',
      vendor: 'mock',
      kind: 'mock',
      endpoint: 'mock://local',
      model: 'mock-1',
      auth: 'none',
      priority: 999,
      enabled: true,
      dailyCap: 100000,
    },
  ];
}
