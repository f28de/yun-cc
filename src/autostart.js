import path from 'node:path';
import os from 'node:os';
import { existsSync, readFileSync } from 'node:fs';
import { promises as fsp } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * User-level autostart for Windows 11.
 *
 * Design constraints (security-first):
 *  - No elevation, no registry Run key, no COM, no PowerShell, no subprocess.
 *    A single managed .cmd is placed in the per-user Startup folder.
 *  - Removal only ever deletes OUR OWN entry (marker-checked), never an
 *    unrelated file that happens to share the name.
 *  - The launcher is built exclusively from installation/runtime paths,
 *    never from user input. Unsafe cmd metacharacters are rejected outright.
 *  - FCC_STARTUP_DIR redirects the target for tests / portable installs.
 */

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
export const MANAGED_MARKER = ':: FreeCloudConsole managed autostart entry - do not edit';
const ENTRY_NAME = 'FreeCloudConsole.cmd';
// %, &, |, ^, <, >, quotes and newlines are all meaningful inside a .cmd.
const UNSAFE_CMD_CHARS = /["\r\n&|^%<>]/;

export function isSupported() {
  return process.platform === 'win32';
}

export function startupDir() {
  if (process.env.FCC_STARTUP_DIR) return process.env.FCC_STARTUP_DIR;
  const appdata = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
  return path.join(appdata, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup');
}

export function entryPath(dir = startupDir()) {
  return path.join(dir, ENTRY_NAME);
}

function launcherText() {
  const nodeExe = process.execPath;
  const mainJs = path.join(ROOT, 'src', 'main.js');
  for (const value of [ROOT, nodeExe]) {
    if (UNSAFE_CMD_CHARS.test(value)) {
      throw new Error('AUTOSTART_UNSAFE_PATH: 安装路径包含 .cmd 不安全字符，已拒绝写入自启项');
    }
  }
  return [
    '@echo off',
    MANAGED_MARKER,
    `cd /d "${ROOT}"`,
    // Prefer whatever node.exe is on the login PATH (survives Node upgrades).
    // Fall back to the exact runtime that created this entry, so a version
    // manager that is not on the login PATH cannot break autostart.
    'where node.exe >nul 2>nul',
    'if errorlevel 1 (',
    `  start "" /min "${nodeExe}" "${mainJs}"`,
    ') else (',
    `  start "" /min node.exe "${mainJs}"`,
    ')',
    '',
  ].join('\r\n');
}

/** Synchronous: status polling must never spawn a process. */
export function autoStartState(dir = startupDir()) {
  if (!isSupported()) return { supported: false, enabled: false };
  try {
    const p = entryPath(dir);
    if (!existsSync(p)) return { supported: true, enabled: false };
    return { supported: true, enabled: readFileSync(p, 'utf8').includes(MANAGED_MARKER) };
  } catch {
    return { supported: true, enabled: false };
  }
}

export async function applyAutoStart(enabled, dir = startupDir()) {
  if (!isSupported()) {
    if (enabled) throw new Error('autostart is only supported on Windows');
    return { supported: false, enabled: false };
  }
  const p = entryPath(dir);
  if (enabled) {
    const text = launcherText(); // validate BEFORE creating anything
    await fsp.mkdir(dir, { recursive: true });
    await fsp.writeFile(p, text, { encoding: 'utf8', mode: 0o600, flag: 'w' });
    return { supported: true, enabled: true, path: p };
  }
  if (autoStartState(dir).enabled) await fsp.unlink(p);
  return { supported: true, enabled: false, path: p };
}

// CLI: node src/autostart.js enable|disable|status
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const action = process.argv[2];
  (async () => {
    if (action === 'status') {
      console.log(JSON.stringify({ ...autoStartState(), path: entryPath() }));
    } else if (action === 'enable' || action === 'disable') {
      const r = await applyAutoStart(action === 'enable');
      console.log(JSON.stringify({ ...r, path: entryPath() }));
    } else {
      console.error('usage: node src/autostart.js enable|disable|status');
      process.exitCode = 2;
    }
  })().catch((e) => {
    console.error('AUTOSTART_FAILED', e.message);
    process.exitCode = 1;
  });
}
