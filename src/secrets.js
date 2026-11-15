import { execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import path from 'node:path';
import { PATHS } from './config.js';
import { atomicWrite, fingerprint } from './util.js';

/**
 * Windows DPAPI (CurrentUser) credential vault.
 *
 * P0 invariants:
 *  - ONE CIPHERTEXT BLOCK PER PROVIDER, with DPAPI entropy bound to the
 *    provider id. Copying a block into another slot fails decryption
 *    ("block swap" attack) instead of silently loading the wrong secret.
 *  - Plaintext travels only through an anonymous pipe as base64. It never
 *    appears in a command line, config file, URL, log, response, or export.
 *  - Decryption failure is FAIL-CLOSED: a typed error is thrown, the id is
 *    recorded, and automatic tasks for that provider are disabled.
 *  - No plaintext fallback. Tests inject MemoryVault instead.
 */

const SAFE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const PREFIX = 'vault-';
const SUFFIX = '.bin';
export const LOCAL_KEY_ID = '__local_api_key';

export class VaultDecryptError extends Error {
  constructor(id, cause) {
    super(`credential_store_unavailable:${id}`);
    this.name = 'VaultDecryptError';
    this.id = id;
    this.cause = cause;
  }
}

function powershellExe() {
  const root = process.env.SystemRoot || 'C:\\Windows';
  return path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

/**
 * Domain-separation label ONLY. It is deterministic and derivable; it does
 * NOT add secrecy. Confidentiality comes solely from the DPAPI user master key.
 * A distinct namespace for the local relay key avoids collisions with ids.
 */
function entropyFor(id) {
  const label = id === LOCAL_KEY_ID ? 'local_api_key' : `credential|${id}`;
  return createHash('sha256').update(`FreeCloudConsole/v1|${label}`, 'utf8').digest();
}

/** Directory ACL must be in place BEFORE any ciphertext is written. Fail closed. */
export async function ensureDirAcl(dir) {
  await fsp.mkdir(dir, { recursive: true });
  await fsp.chmod(dir, 0o700).catch(() => {});
  if (process.platform !== 'win32') return;
  const user = `${process.env.USERDOMAIN || '.'}\\${process.env.USERNAME || ''}`;
  try {
    execFileSync('icacls', [dir, '/inheritance:r', '/grant:r', `${user}:(OI)(CI)F`], {
      windowsHide: true, stdio: 'ignore', timeout: 10000,
    });
  } catch {
    throw new Error('VAULT_ACL_FAILED: 无法设置凭据目录 ACL，已拒绝写入密文');
  }
}

function blockFile(dir, id) {
  if (!SAFE_ID.test(id)) throw new Error('invalid vault id');
  return path.join(dir, `${PREFIX}${id}${SUFFIX}`);
}

function psScript(mode, entropyB64) {
  // mode and entropy are server-generated literals (base64 charset only).
  return [
    "$ErrorActionPreference='Stop'",
    'Add-Type -AssemblyName System.Security',
    `$entropy=[Convert]::FromBase64String('${entropyB64}')`,
    '$scope=[System.Security.Cryptography.DataProtectionScope]::CurrentUser',
    '$text=[Console]::In.ReadToEnd()',
    `if('${mode}' -eq 'protect'){`,
    '  $bytes=[Convert]::FromBase64String($text)',
    '  $enc=[System.Security.Cryptography.ProtectedData]::Protect($bytes,$entropy,$scope)',
    '  [Console]::Out.Write([Convert]::ToBase64String($enc))',
    '}else{',
    '  $enc=[Convert]::FromBase64String($text)',
    '  $bytes=[System.Security.Cryptography.ProtectedData]::Unprotect($enc,$entropy,$scope)',
    '  [Console]::Out.Write([Convert]::ToBase64String($bytes))',
    '}',
  ].join('\n');
}

function invokeDpapi(mode, inputBase64, entropy) {
  const encoded = Buffer.from(psScript(mode, entropy.toString('base64')), 'utf16le').toString('base64');
  return execFileSync(
    powershellExe(),
    ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
    {
      input: inputBase64,
      encoding: 'utf8',
      timeout: 15000,
      windowsHide: true,
      maxBuffer: 8 * 1024 * 1024,
      stdio: ['pipe', 'pipe', 'pipe'],
    },
  ).trim();
}

function shortFp(value) {
  return fingerprint(value).slice(-4).toUpperCase();
}

export function createDpapiVault(dir = PATHS.base) {
  const failedIds = new Set();

  async function readBlock(id) {
    const file = blockFile(dir, id);
    let cipher;
    try {
      cipher = await fsp.readFile(file);
    } catch (err) {
      if (err.code === 'ENOENT') return null;
      throw err;
    }
    let plainB64;
    try {
      plainB64 = invokeDpapi('unprotect', cipher.toString('base64'), entropyFor(id));
    } catch (cause) {
      failedIds.add(id);
      throw new VaultDecryptError(id, cause);
    }
    const buf = Buffer.from(plainB64, 'base64');
    try {
      const obj = JSON.parse(buf.toString('utf8'));
      if (!obj || typeof obj !== 'object') throw new Error('bad vault block');
      failedIds.delete(id);
      return obj;
    } finally {
      buf.fill(0);
    }
  }

  async function writeBlock(id, obj) {
    await ensureDirAcl(dir);
    const plain = Buffer.from(JSON.stringify(obj), 'utf8');
    try {
      const cipherB64 = invokeDpapi('protect', plain.toString('base64'), entropyFor(id));
      const file = blockFile(dir, id);
      await atomicWrite(file, Buffer.from(cipherB64, 'base64'), 0o600);
      await fsp.chmod(file, 0o600).catch(() => {});
      await fsp.access(file);
    } finally {
      plain.fill(0);
    }
    failedIds.delete(id);
  }

  async function ids() {
    let entries = [];
    try { entries = await fsp.readdir(dir); } catch { return []; }
    return entries
      .filter((f) => f.startsWith(PREFIX) && f.endsWith(SUFFIX))
      .map((f) => f.slice(PREFIX.length, -SUFFIX.length))
      .filter((id) => SAFE_ID.test(id) && !id.startsWith('__'));
  }

  function publicEntry(id, entry, decryptFailed = false) {
    const fp = Object.values(entry?.secrets || {})[0];
    const hex = fp ? shortFp(fp) : null;
    return {
      id,
      vendor: entry?.meta?.vendor || 'unknown',
      displayName: entry?.meta?.displayName || id,
      enabled: decryptFailed ? false : entry?.meta?.enabled !== false,
      note: entry?.meta?.note ?? null,
      purpose: entry?.meta?.purpose ?? 'both',
      credentialCount: Object.keys(entry?.secrets || {}).length,
      fingerprints: Object.fromEntries(
        Object.entries(entry?.secrets || {}).map(([k, v]) => [k, shortFp(v)]),
      ),
      credentialFingerprint: hex,
      credentialMasked: hex ? `***${hex}` : null,
      credentialCreatedAt: entry?.updatedAt ? new Date(entry.updatedAt).toISOString() : null,
      decryptFailed,
    };
  }

  return {
    kind: 'dpapi',

    async isAvailable() {
      try {
        const entropy = randomBytes(32);
        const probe = Buffer.from('fcc-probe', 'utf8').toString('base64');
        const enc = invokeDpapi('protect', probe, entropy);
        const dec = invokeDpapi('unprotect', enc, entropy);
        return dec === probe;
      } catch {
        return false;
      }
    },

    failedIds() { return [...failedIds]; },

    async list() {
      const out = [];
      for (const id of await ids()) {
        try {
          const entry = await readBlock(id);
          if (entry) out.push(publicEntry(id, entry));
        } catch (err) {
          if (err instanceof VaultDecryptError) {
            out.push(publicEntry(id, null, true));
          } else {
            throw err;
          }
        }
      }
      return out;
    },

    async get(id) { return readBlock(id); },

    async put(id, meta, secrets) {
      await writeBlock(id, { version: 1, meta, secrets, updatedAt: Date.now() });
    },

    async remove(id) {
      await fsp.unlink(blockFile(dir, id)).catch(() => {});
      failedIds.delete(id);
    },

    async getLocalKey() {
      const b = await readBlock(LOCAL_KEY_ID);
      return b?.key || null;
    },

    async getLocalKeyMeta() {
      const b = await readBlock(LOCAL_KEY_ID);
      return {
        key: b?.key || null,
        createdAt: b?.key && b?.updatedAt ? new Date(b.updatedAt).toISOString() : null,
      };
    },

    async setLocalKey(key) {
      await writeBlock(LOCAL_KEY_ID, { version: 1, key, updatedAt: Date.now() });
    },

    async removeLocalKey() {
      await this.remove(LOCAL_KEY_ID);
    },

    async raw() {
      const all = {};
      for (const id of await ids()) all[id] = await readBlock(id);
      return all;
    },
  };
}

/** Test-only in-memory vault with the exact same surface. */
export function createMemoryVault() {
  const blocks = new Map();
  const failedIds = new Set();

  const publicEntry = (id, entry) => {
    const fp = Object.values(entry?.secrets || {})[0];
    const hex = fp ? shortFp(fp) : null;
    return {
      id,
      vendor: entry?.meta?.vendor || 'unknown',
      displayName: entry?.meta?.displayName || id,
      enabled: entry?.meta?.enabled !== false,
      note: entry?.meta?.note ?? null,
      purpose: entry?.meta?.purpose ?? 'both',
      credentialCount: Object.keys(entry?.secrets || {}).length,
      fingerprints: Object.fromEntries(
        Object.entries(entry?.secrets || {}).map(([k, v]) => [k, shortFp(v)]),
      ),
      credentialFingerprint: hex,
      credentialMasked: hex ? `***${hex}` : null,
      credentialCreatedAt: entry?.updatedAt ? new Date(entry.updatedAt).toISOString() : null,
      decryptFailed: failedIds.has(id),
    };
  };

  return {
    kind: 'memory',
    async isAvailable() { return true; },
    failedIds() { return [...failedIds]; },
    async list() {
      return [...blocks.entries()]
        .filter(([id]) => !id.startsWith('__'))
        .map(([id, entry]) => publicEntry(id, entry));
    },
    async get(id) {
      if (failedIds.has(id)) throw new VaultDecryptError(id);
      return blocks.get(id) || null;
    },
    async put(id, meta, secrets) {
      blocks.set(id, { version: 1, meta, secrets, updatedAt: Date.now() });
      failedIds.delete(id);
    },
    async remove(id) { blocks.delete(id); failedIds.delete(id); },
    async getLocalKey() { return blocks.get(LOCAL_KEY_ID)?.key || null; },
    async getLocalKeyMeta() {
      const b = blocks.get(LOCAL_KEY_ID);
      return {
        key: b?.key || null,
        createdAt: b?.key && b?.updatedAt ? new Date(b.updatedAt).toISOString() : null,
      };
    },
    async setLocalKey(key) { blocks.set(LOCAL_KEY_ID, { key, updatedAt: Date.now() }); },
    async removeLocalKey() { blocks.delete(LOCAL_KEY_ID); },
    async raw() { return Object.fromEntries(blocks); },
    __failDecrypt(id) { failedIds.add(id); },
  };
}
