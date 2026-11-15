import { assertUpstream, iso } from './util.js';
import { buildUpstreamRequest, normalizeUpstreamResponse } from './providers/ai.js';

const today = () => new Date().toISOString().slice(0, 10);

/** Produce an OpenAI-compatible mock completion, including an SSE stream. */
function mockResponse(body, model) {
  const text = `【演示模式】已收到 ${Array.isArray(body.messages) ? body.messages.length : 0} 条消息，未产生任何真实外联。请到「云厂商凭据」页填写凭据后启用真实上游。`;
  return {
    id: `chatcmpl-mock-${Date.now()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: model || 'mock-1',
    choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: 'stop' }],
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  };
}

function sseChunk(res, obj) {
  res.write(`data: ${JSON.stringify(obj)}\n\n`);
}
function sseDone(res) {
  res.write('data: [DONE]\n\n');
}

export function createAiGateway({ config, vault, emit, log }) {
  const stats = {
    date: today(),
    perUpstream: {},
    failures: {},
    cooldownUntil: {},
    totalRequests: 0,
    totalFailures: 0,
  };

  function rollDay() {
    if (stats.date !== today()) {
      stats.date = today();
      stats.perUpstream = {};
    }
  }

  function usageFor(id) {
    rollDay();
    if (!stats.perUpstream[id]) stats.perUpstream[id] = { requests: 0, tokens: 0, errors: 0 };
    return stats.perUpstream[id];
  }

  function eligible(u) {
    if (u.enabled === false) return false;
    if ((stats.cooldownUntil[u.id] || 0) > Date.now()) return false;
    const cap = Number(u.dailyCap || config.ai.dailyRequestCap);
    if (usageFor(u.id).requests >= cap) return false;
    return true;
  }

  async function secretsFor(u) {
    // C8/TC28: mock upstreams never receive a credential blob, and a network
    // upstream can only use credentials bound to the SAME vendor.
    if (u.kind === 'mock') return {};
    const id = u.providerId || `ai-${u.vendor}`;
    const entry = await vault.get(id);
    if (!entry) throw new Error(`未找到凭据：${id}`);
    if (entry.meta?.vendor !== u.vendor) throw new Error('上游厂商与凭据厂商不匹配');
    return entry.secrets;
  }

  function usageSummary() {
    rollDay();
    return {
      date: stats.date,
      totalRequests: stats.totalRequests,
      totalFailures: stats.totalFailures,
      upstreams: Object.fromEntries(
        (config.aiUpstreams || []).map((u) => [u.id, {
          ...usageFor(u.id),
          cap: Number(u.dailyCap || config.ai.dailyRequestCap),
          cooling: (stats.cooldownUntil[u.id] || 0) > Date.now(),
        }]),
      ),
    };
  }

  function healthy() {
    return (config.aiUpstreams || []).some((u) => eligible(u));
  }

  /** Handle /v1/chat/completions. `res` is a Node ServerResponse. */
  async function handle(body, res, { requestId }) {
    rollDay();
    stats.totalRequests += 1;
    if (!body || !Array.isArray(body.messages) || body.messages.length === 0) {
      return json(res, 400, { error: { message: 'messages must be a non-empty array', type: 'invalid_request' } });
    }

    const candidates = [...(config.aiUpstreams || [])]
      .filter(eligible)
      .sort((a, b) => Number(a.priority) - Number(b.priority));

    if (candidates.length === 0) {
      return json(res, 503, {
        error: { message: '所有上游均不可用（额度耗尽、熔断或未配置）', type: 'quota_exhausted' },
      });
    }

    for (const u of candidates) {
      const use = usageFor(u.id);
      try {
        const secrets = await secretsFor(u);
        const built = buildUpstreamRequest(u, secrets, body);
        const ok = await forward(u, built, body, res, requestId);
        if (ok) {
          use.requests += 1;
          delete stats.cooldownUntil[u.id];
          stats.failures[u.id] = 0;
          emit('ai-usage', {
            upstreamId: u.id, vendor: u.vendor, requests: use.requests,
            total: stats.totalRequests, stream: Boolean(body.stream),
          });
          log('info', 'ai.request', { upstream: u.id, stream: Boolean(body.stream) });
          return;
        }
        // `ok === false` means the response was already committed; stop here.
        return;
      } catch (err) {
        use.errors += 1;
        stats.failures[u.id] = (stats.failures[u.id] || 0) + 1;
        stats.totalFailures += 1;
        const msg = String(err.message || 'upstream error').slice(0, 160);
        log('warn', 'ai.upstream-fail', { upstream: u.id, message: msg });
        emit('ai-usage', { upstreamId: u.id, failed: true, message: msg });

        // C16: quota/rate-limit exhaustion must STOP the request. Never silently
        // fail over to another provider (that would constitute quota evasion).
        // err.bodyQuotaHint comes from STRUCTURED signals only (Retry-After,
        // X-RateLimit-*, JSON error.code/type) - never from free-form body text.
        // A 5xx carrying any of them is still quota exhaustion, not a transient
        // 5xx, so it must NOT be treated as failover-eligible.
        const quotaHit = err.status === 429 || err.status === 402
          || err.bodyQuotaHint === true
          || /quota|rate.?limit|额度|限流/i.test(msg);
        if (quotaHit) {
          stats.cooldownUntil[u.id] = Date.now() + config.ai.cooldownSec * 1000;
          log('warn', 'security.quota-exhausted', { upstream: u.id });
          emit('security-alert', {
            at: iso(), severity: 'warn', kind: 'quota_exhausted', upstreamId: u.id,
            detail: '额度到量，已停止调用且未切换到其他上游',
          });
          if (!res.headersSent) {
            json(res, 429, {
              error: {
                message: '额度已到上限，已停止调用（未切换到其他上游）',
                type: 'quota_exhausted',
              },
            });
          }
          return;
        }

        if (stats.failures[u.id] >= config.ai.circuitFailures) {
          stats.cooldownUntil[u.id] = Date.now() + config.ai.cooldownSec * 1000;
          log('warn', 'ai.circuit-open', { upstream: u.id });
        }
        // Try the next upstream (non-committed failures only).
      }
    }

    if (!res.headersSent) {
      json(res, 502, { error: { message: '全部上游调用失败（详情已记录于本地日志，不含上游响应正文）', type: 'upstream_error' } });
    }
  }

  async function forward(u, built, body, res, requestId) {
    const stream = Boolean(body.stream);

    if (built.kind === 'mock') {
      if (stream) {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-store',
          Connection: 'keep-alive',
          'X-Accel-Buffering': 'no',
        });
        const obj = mockResponse(body, u.model);
        const delta = {
          id: obj.id, object: 'chat.completion.chunk', created: obj.created, model: obj.model,
          choices: [{ index: 0, delta: { role: 'assistant', content: obj.choices[0].message.content }, finish_reason: null }],
        };
        sseChunk(res, delta);
        sseChunk(res, {
          id: obj.id, object: 'chat.completion.chunk', created: obj.created, model: obj.model,
          choices: [{ index: 0, delta: {}, finish_reason: 'stop' }],
        });
        sseDone(res);
        res.end();
      } else {
        json(res, 200, mockResponse(body, u.model));
      }
      return true;
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), config.ai.requestTimeoutMs);
    let upstreamRes;
    try {
      assertUpstream(built.url, 'ai'); // second gate, right before the socket opens
      upstreamRes = await fetch(built.url, {
        method: 'POST',
        headers: built.headers,
        body: built.payload,
        signal: ctrl.signal,
        redirect: 'error',
        cache: 'no-store',
      });
    } catch (err) {
      clearTimeout(timer);
      throw new Error(`上游连接失败: ${err.name}`);
    }

    if (!upstreamRes.ok) {
      clearTimeout(timer);
      // Structured signals ONLY. Upstream-controlled body text must never be
      // used to decide routing, or an attacker could inject keywords to force
      // or suppress failover (quota evasion). Read at most 4KB, never log it,
      // and zero the buffer immediately after classification.
      const rateLimited = upstreamRes.headers.has('retry-after')
        || [...upstreamRes.headers.keys()].some((h) => h.startsWith('x-ratelimit'));
      let structuredCode = '';
      if (upstreamRes.status >= 500 && upstreamRes.body) {
        const reader = upstreamRes.body.getReader();
        try {
          const { value } = await reader.read();
          await reader.cancel().catch(() => {});
          if (value) {
            const buf = Buffer.from(value.slice(0, 4096));
            try {
              const parsed = JSON.parse(buf.toString('utf8'));
              structuredCode = String(parsed?.error?.code || parsed?.error?.type || '').toLowerCase();
            } catch { /* non-JSON: ignore */ } finally {
              buf.fill(0);
            }
          }
        } catch { /* unreadable: ignore */ }
      } else {
        await upstreamRes.body?.cancel().catch(() => {});
      }
      const err = new Error(`上游返回 HTTP ${upstreamRes.status}`);
      err.status = upstreamRes.status;
      err.bodyQuotaHint = rateLimited
        || /quota|rate_limit|insufficient_quota|billing|credit/i.test(structuredCode);
      throw err;
    }

    if (stream && (built.kind === 'openai-compatible' || built.kind === 'azure-openai')) {
      clearTimeout(timer);
      res.writeHead(200, {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-store',
        Connection: 'keep-alive',
        'X-Accel-Buffering': 'no',
      });
      // Stream through without buffering the full response.
      const reader = upstreamRes.body.getReader();
      let idle = setTimeout(() => ctrl.abort(), config.ai.streamIdleTimeoutMs);
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          clearTimeout(idle);
          idle = setTimeout(() => ctrl.abort(), config.ai.streamIdleTimeoutMs);
          res.write(Buffer.from(value));
        }
      } catch {
        // Aborted or client disconnected: do not leak upstream bodies into errors.
      } finally {
        clearTimeout(idle);
        await reader.cancel().catch(() => {});
        res.end();
      }
      return true;
    }

    // Non-stream (or a protocol that needs normalisation).
    const text = await readCapped(upstreamRes, 4 * 1024 * 1024);
    clearTimeout(timer);
    let data;
    try { data = JSON.parse(text); } catch { throw new Error('上游响应非 JSON'); }
    const normalised = normalizeUpstreamResponse(built.kind, data, u.model);
    if (!normalised) throw new Error('上游响应无法解析');

    if (stream) {
      res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store' });
      const chunk = {
        id: normalised.id, object: 'chat.completion.chunk', created: normalised.created, model: normalised.model,
        choices: [{ index: 0, delta: { role: 'assistant', content: normalised.choices?.[0]?.message?.content || '' }, finish_reason: 'stop' }],
      };
      sseChunk(res, chunk);
      sseDone(res);
      res.end();
    } else {
      json(res, 200, normalised);
    }
    return true;
  }

  async function readCapped(res, maxBytes) {
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error('上游响应过大');
      }
      chunks.push(value);
    }
    return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
  }

  function json(res, code, obj) {
    if (res.headersSent) return;
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(obj));
  }

  return {
    handle,
    usageSummary,
    healthy,
    statusSummary: () => ({ enabled: config.ai.enabled, healthy: healthy(), ...usageSummary() }),
  };
}
