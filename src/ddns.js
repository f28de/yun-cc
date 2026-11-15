import { assertUpstream, iso, sleep } from './util.js';
import { httpRequest } from './providers/http.js';
import { createDnsProvider } from './providers/dns-index.js';

const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/;
const IPV6_RE = /\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b/;

export function extractIp(text) {
  const s = String(text || '');
  return s.match(IPV4_RE)?.[0] || s.match(IPV6_RE)?.[0] || null;
}

/** Reject private / loopback / link-local / reserved addresses. */
export function isPublicIp(ip) {
  if (!ip) return false;
  if (ip.includes(':')) {
    const h = ip.toLowerCase();
    return !(h.startsWith('::1') || h.startsWith('fc') || h.startsWith('fd')
      || h.startsWith('fe80') || h.startsWith('::ffff:127.') || h === '::');
  }
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => n > 255)) return false;
  const [a, b] = p;
  if (a === 0 || a === 10 || a === 127 || a >= 224 || a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  return true;
}

async function defaultProbe(urls, timeoutMs = 8000) {
  const results = await Promise.allSettled(urls.map(async (url) => {
    assertUpstream(url, 'probe');
    const r = await httpRequest(url, { timeoutMs, maxBytes: 64 * 1024, purpose: 'probe' });
    if (!r.ok) throw new Error(`probe HTTP ${r.status}`);
    return extractIp(r.text);
  }));
  return results.filter((r) => r.status === 'fulfilled' && isPublicIp(r.value)).map((r) => r.value);
}

function consensus(votes, minAgree) {
  const counts = new Map();
  for (const v of votes) counts.set(v, (counts.get(v) || 0) + 1);
  let winner = null;
  let winnerCount = 0;
  for (const [ip, n] of counts) {
    if (n > winnerCount) { winner = ip; winnerCount = n; }
  }
  const others = votes.length - winnerCount;
  if (!winner || winnerCount < minAgree || winnerCount <= others) return null;
  return { ip: winner, votes: winnerCount, total: votes.length };
}

/**
 * DDNS engine. IP probing is injected via `probe` so tests can use a local
 * fake source without weakening the production SSRF allowlist.
 */
export function createDdnsEngine({
  config,
  vault,
  emit,
  log,
  state,
  saveState,
  probe = defaultProbe,
}) {
  let timer = null;
  let stopped = false;
  let consecutiveFailures = 0;
  let inFlight = false;
  const status = {
    lastIp: state?.lastIp || null,
    lastCheck: null,
    lastSync: null,
    nextCheck: null,
    healthy: true,
    message: '等待首次检测',
    records: {},
  };

  async function providerFor(record) {
    // C8/TC28: the vault entry is authoritative. Never let a client-supplied
    // record.vendor select a network adapter for credentials of another vendor.
    if (record.vendor === 'mock') return createDnsProvider('mock');
    const entry = await vault.get(record.providerId);
    if (!entry) throw new Error(`未找到凭据：${record.providerId}`);
    const bound = entry.meta?.vendor;
    if (bound !== record.vendor) throw new Error('DDNS 记录厂商与凭据厂商不匹配');
    return createDnsProvider(bound, entry.secrets);
  }

  async function syncOnce({ force = false, manual = false } = {}) {
    if (inFlight || stopped) return { skipped: true };
    inFlight = true;
    try {
      const cfg = config.ddns;
      const votes = await probe(cfg.probeUrls, 8000);
      status.lastCheck = Date.now();
      const agree = consensus(votes, cfg.minAgree);
      if (!agree) {
        status.healthy = false;
        status.message = `探测源未达成共识 (${votes.length} 源, 需至少 ${cfg.minAgree} 一致)`;
        emit('security-alert', { type: 'ip-no-consensus', votes: votes.length });
        log('warn', 'ddns.no-consensus', { votes: votes.length, minAgree: cfg.minAgree });
        consecutiveFailures += 1;
        return { ok: false, reason: 'no-consensus' };
      }

      if (!force && agree.ip === status.lastIp) {
        status.healthy = true;
        status.message = `IP 未变化 ${agree.ip}（跳过 DNS 调用）`;
        emit('health', { ddns: statusSummary() });
        return { ok: true, unchanged: true, ip: agree.ip };
      }

      emit('ip-changed', { ip: agree.ip, votes: agree.votes, total: agree.total });
      log('info', 'ddns.ip-changed', { ip: agree.ip, votes: agree.votes });

      const targets = (config.ddnsRecords || []).filter((r) => r.enabled !== false);
      const results = await Promise.allSettled(targets.map(async (r) => {
        const p = await providerFor(r);
        const current = await p.current(r).catch(() => ({ value: null }));
        if (!force && current.value === agree.ip) {
          return { id: r.id, skipped: true, ip: agree.ip };
        }
        const out = await p.update(r, agree.ip);
        return { id: r.id, ...out };
      }));

      let failed = 0;
      results.forEach((res, i) => {
        const r = targets[i];
        const ok = res.status === 'fulfilled';
        if (!ok) failed += 1;
        status.records[r.id] = {
          ok,
          ip: agree.ip,
          at: Date.now(),
          detail: ok ? (res.value.detail || 'ok') : 'error',
        };
        emit('ddns-result', {
          id: r.id,
          name: `${r.name}.${r.domain}`,
          vendor: r.vendor,
          ok,
          skipped: ok && res.value.skipped === true,
          // Error details are sanitised: never echo upstream response bodies.
          error: ok ? null : (res.reason?.message || 'update failed').slice(0, 160),
        });
      });

      status.lastIp = agree.ip;
      status.lastSync = Date.now();
      status.healthy = failed === 0;
      status.message = failed
        ? `${failed}/${targets.length} 条记录更新失败`
        : `已同步 ${targets.length} 条记录 -> ${agree.ip}`;
      consecutiveFailures = failed ? consecutiveFailures + 1 : 0;
      await saveState({ lastIp: status.lastIp, lastSync: status.lastSync });
      emit('health', { ddns: statusSummary() });
      log(failed ? 'warn' : 'info', 'ddns.sync', {
        ip: agree.ip, total: targets.length, failed, manual,
      });
      return { ok: failed === 0, ip: agree.ip, failed };
    } catch (err) {
      consecutiveFailures += 1;
      status.healthy = false;
      status.message = '检测异常，将退避重试';
      log('warn', 'ddns.error', { message: String(err.message).slice(0, 160) });
      return { ok: false, reason: 'error' };
    } finally {
      inFlight = false;
    }
  }

  function statusSummary() {
    return {
      enabled: config.ddns.enabled,
      healthy: status.healthy,
      lastIp: status.lastIp,
      lastCheck: status.lastCheck,
      lastSync: status.lastSync,
      nextCheck: status.nextCheck,
      message: status.message,
      consecutiveFailures,
      intervalSec: config.ddns.intervalSec,
      records: status.records,
    };
  }

  async function loop() {
    if (stopped) return;
    const result = await syncOnce();
    const cfg = config.ddns;
    let delay = cfg.intervalSec * 1000;
    if (result?.ok === false && consecutiveFailures > 0) {
      delay = Math.min(
        cfg.maxBackoffSec * 1000,
        Math.min(2 ** (consecutiveFailures - 1), 8) * 1000,
      );
    }
    status.nextCheck = Date.now() + delay;
    emit('health', { ddns: statusSummary() });
    if (!stopped) timer = setTimeout(loop, delay);
  }

  return {
    statusSummary,
    syncOnce,
    start() {
      if (!config.ddns.enabled || timer) return;
      stopped = false;
      loop();
    },
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      timer = null;
    },
    get inFlight() { return inFlight; },
  };
}
