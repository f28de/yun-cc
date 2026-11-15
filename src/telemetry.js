import { redact, redactText, iso } from './util.js';

/**
 * Single SSE fan-out + bounded in-memory event ring.
 * Everything is redacted before it is stored, streamed, or printed.
 */
export function createTelemetry({ maxEvents = 200, sink = console.log } = {}) {
  const clients = new Set();
  const events = [];
  const anomalies = [];
  let seq = 0;
  const startedAt = Date.now();

  const nextId = () => `evt_${(++seq).toString().padStart(6, '0')}`;

  function writeFrame(res, name, payload) {
    if (res.writableEnded || res.destroyed) return;
    try {
      res.write(`id: ${nextId()}\nevent: ${name}\ndata: ${JSON.stringify(redact(payload))}\nretry: 3000\n\n`);
    } catch { /* client gone */ }
  }

  function emit(name, payload) {
    const frame = { at: iso(), ...redact(payload) };
    for (const res of clients) writeFrame(res, name, frame);
    return frame;
  }

  function push(level, source, message, code = null) {
    const evt = {
      id: nextId(),
      at: iso(),
      level,
      source,
      message: redactText(String(message)).slice(0, 240),
      code,
    };
    events.push(evt);
    if (events.length > maxEvents) events.shift();
    return evt;
  }

  function log(level, event, detail = {}) {
    const clean = redact(detail);
    sink(redactText(JSON.stringify({ t: iso(), level, event, detail: clean })));
    const source = event.startsWith('ddns') ? 'ddns'
      : event.startsWith('ai') ? 'ai'
        : event.startsWith('security') ? 'security'
          : event.startsWith('provider') ? 'provider' : 'system';
    const lvl = level === 'warn' ? 'warn' : level === 'error' ? 'error' : 'info';
    const brief = Object.entries(clean)
      .map(([k, v]) => `${k}=${typeof v === 'object' ? '[obj]' : String(v).slice(0, 60)}`)
      .join(' ');
    const evt = push(lvl, source, `[${event}] ${brief}`, event);
    for (const res of clients) writeFrame(res, 'log', evt);
    return evt;
  }

  function noteAnomaly(kind, detail) {
    const item = { target: kind, reason: redactText(String(detail)).slice(0, 160), at: iso() };
    anomalies.push(item);
    if (anomalies.length > 50) anomalies.shift();
    log('warn', 'security.anomaly', { kind, detail: item.reason });
    emit('security-alert', {
      at: iso(), severity: 'critical', kind, detail: item.reason,
      externalConnections: anomalies.length,
    });
  }

  /** Auditable actions: success / failure / denied. Never contains a secret. */
  function audit(action, result, detail = '') {
    const evt = log(
      result === 'denied' ? 'warn' : 'info',
      `audit.${action}`,
      { result, action, detail: redactText(String(detail)).slice(0, 120) },
    );
    evt.source = 'audit';
    evt.action = action;
    evt.result = result;
    evt.actor = 'local';
    for (const res of clients) writeFrame(res, 'log', evt);
    return evt;
  }

  const auditEvents = () => events.filter((e) => e.source === 'audit');

  return {
    emit,
    log,
    noteAnomaly,
    audit,
    auditRecent(n = 3) {
      return auditEvents().slice(-n).map(({ at, action, result, actor }) => ({
        at, actor: actor || 'local', action: action || 'unknown', result: result || 'success',
      }));
    },
    auditPage(page = 1, size = 20) {
      const list = auditEvents();
      const start = Math.max(0, (page - 1) * size);
      return { page, size, total: list.length, items: list.slice(start, start + size) };
    },
    get anomalies() { return anomalies.slice(); },
    get externalConnections() { return anomalies.length; },
    recent(n = 8) { return events.slice(-n).map((e) => ({ ...e })); },
    all(n = 100) { return events.slice(-n).map((e) => ({ ...e })); },
    uptimeSec() { return Math.floor((Date.now() - startedAt) / 1000); },
    subscribe(res) {
      clients.add(res);
      res.write('retry: 3000\n\n');
      return () => clients.delete(res);
    },
    heartbeat() {
      for (const res of clients) {
        if (!res.writableEnded && !res.destroyed) {
          try { res.write(': ping\n\n'); } catch { /* noop */ }
        }
      }
    },
    get clientCount() { return clients.size; },
    close() { clients.clear(); },
  };
}
