'use strict';

/* Zero dependencies, zero innerHTML, zero localStorage/sessionStorage.
   All dynamic content is written through textContent only. */

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];
const IDLE_MS = 15 * 60 * 1000;

let vendorMeta = {};
let lastStatus = null;
let eventSource = null;
let idleTimer = null;

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

function toast(message, tone) {
  const t = $('#toast');
  t.textContent = String(message);
  t.hidden = false;
  if (tone) t.dataset.tone = tone;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 4200);
}

function showLock(reason) {
  const l = $('#lock');
  if (!l.hidden) return;
  l.hidden = false;
  l.dataset.lockReason = reason;
  document.body.dataset.state = 'locked';
  $('#lock-title').textContent = reason === 'idle'
    ? '会话已结束（长时间无操作）' : '会话已结束';
  $('#lock-body').textContent = reason === 'idle'
    ? '长时间无操作，服务端已销毁会话。后台 DDNS 与中转服务仍由守护进程拉起；请重新打开应用完成重新认证。'
    : '服务端会话已失效。请重新打开应用完成重新认证；本窗口不能再发起任何请求。';
  if (eventSource) { eventSource.close(); eventSource = null; }
}

function armIdle() {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(() => showLock('idle'), IDLE_MS);
}

async function api(path, options = {}) {
  const method = options.method || 'GET';
  const headers = {};
  if (method !== 'GET') {
    headers['X-FCC-CSRF'] = '1';
    headers['X-Local-CSRF'] = '1';
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    cache: 'no-store',
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  if (res.status === 401) { showLock('session-invalid'); throw new Error('SESSION_INVALID'); }
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (!res.ok) {
    const e = new Error(data?.message || data?.errorCode || `HTTP ${res.status}`);
    e.code = data?.errorCode || null;
    throw e;
  }
  return data;
}

function toneOf(state) {
  if (['running', 'connected', 'ok', 'active'].includes(state)) return 'ok';
  if (['degraded', 'untested', 'warn', 'absent'].includes(state)) return 'warn';
  if (['stopped', 'error', 'decrypt_failed', 'invalid_credentials'].includes(state)) return 'danger';
  return 'idle';
}

function row(title, sub, actions) {
  const wrap = el('div', 'row');
  const main = el('div', 'row-main');
  main.append(el('div', 'row-title', title), el('div', 'row-sub', sub));
  wrap.append(main);
  if (actions?.length) {
    const box = el('div', 'row-actions');
    actions.forEach((a) => box.append(a));
    wrap.append(box);
  }
  return wrap;
}
function miniBtn(label, onClick, danger) {
  const b = el('button', `btn btn-mini${danger ? ' btn-danger' : ''}`, label);
  b.type = 'button';
  b.addEventListener('click', onClick);
  return b;
}

/* ---------------- pages ---------------- */

const titles = {
  overview: ['总览', '多云免费额度、DDNS 与 AI 中转的一处收口'],
  providers: ['云厂商凭据', 'Windows DPAPI 加密托管 · 永不回显 · 永不导出'],
  ddns: ['DDNS 记录', '多探测源共识 · 变化触发 · 指数退避'],
  ai: ['AI 中转', 'OpenAI 兼容本地端点 · 故障转移 · 额度熔断'],
  settings: ['设置与安全', '仅本机监听 · 用户态运行 · 审计只读'],
};

function switchPage(name) {
  $$('.nav-item').forEach((b) => b.classList.toggle('is-active', b.dataset.nav === name));
  $$('.page').forEach((p) => p.classList.toggle('is-active', p.dataset.page === name));
  $('#page-title').textContent = titles[name][0];
  $('#page-sub').textContent = titles[name][1];
  loadPage(name).catch((e) => toast(e.message, 'danger'));
}

async function loadPage(name) {
  if (name === 'overview' || name === 'settings') return refreshStatus();
  if (name === 'providers') return Promise.all([loadProviders(), loadVendorMeta()]);
  if (name === 'ddns') return loadRecords();
  if (name === 'ai') return loadUpstreams();
  return undefined;
}

let vendorWired = false;
async function loadVendorMeta() {
  vendorMeta = await api('/api/vendors');
  const selects = [$('#p-vendor'), $('#r-vendor'), $('#u-vendor')];
  selects.forEach((s) => clear(s));
  Object.entries(vendorMeta).forEach(([key, meta]) => {
    const o = el('option', null, meta.label);
    o.value = key;
    selects[0]?.append(o);
  });
  ['cloudflare', 'tencent', 'aws', 'azure', 'mock'].forEach((v) => {
    const o = el('option', null, vendorMeta[v]?.label || v);
    o.value = v;
    selects[1]?.append(o.cloneNode(true));
    selects[2]?.append(o.cloneNode(true));
  });
  if (!vendorWired) {
    vendorWired = true;
    selects[0].addEventListener('change', renderCredentialFields);
  }
  renderCredentialFields();
}

function renderCredentialFields() {
  const box = $('#p-fields');
  clear(box);
  const meta = vendorMeta[$('#p-vendor').value];
  if (!meta) return;
  (meta.fields || []).forEach((f) => {
    const label = el('label', null, f.label + (f.optional ? '（可选）' : ''));
    const input = document.createElement('input');
    input.type = f.secret ? 'password' : 'text';
    input.dataset.field = 'credential';
    input.dataset.masked = f.secret ? 'true' : 'false';
    input.dataset.key = f.key;
    input.autocomplete = 'off';
    input.placeholder = f.hint || '';
    if (f.secret) input.setAttribute('data-masked', 'true');
    label.append(input);
    box.append(label);
  });
  if (!(meta.fields || []).length) box.append(el('p', 'muted', '演示厂商无需凭据。'));
}

async function loadProviders() {
  const list = await api('/api/providers');
  const box = $('#p-list');
  clear(box);
  box.dataset.state = list.length ? 'ready' : 'empty';
  if (!list.length) { box.append(el('div', 'muted', '尚未配置任何凭据。可先添加「本地演示 (Mock)」验证流程。')); return; }
  list.forEach((p) => {
    const actions = [
      miniBtn('测试连通', async () => {
        try {
          const r = await api(`/api/providers/${p.id}/test`, { method: 'POST', body: {} });
          toast(r.ok ? `连接成功 (${r.latencyMs}ms)` : `连接失败：${r.errorCode || 'TEST_FAILED'}`, r.ok ? 'ok' : 'danger');
          await loadProviders();
        } catch (e) { toast(e.message, 'danger'); }
      }),
      miniBtn(p.enabled ? '停用' : '启用', async () => {
        try { await api(`/api/providers/${p.id}`, { method: 'PATCH', body: { enabled: !p.enabled } }); await loadProviders(); }
        catch (e) { toast(e.message, 'danger'); }
      }),
      miniBtn('轮换', async () => {
        const fresh = {};
        (vendorMeta[p.vendor]?.fields || []).forEach((f) => {
          const v = window.prompt(`输入新的 ${f.label}（留空则取消）`);
          if (v) fresh[f.key] = v;
        });
        if (!Object.keys(fresh).length) return;
        try { await api(`/api/providers/${p.id}/rotate`, { method: 'POST', body: { credentials: fresh } }); toast('凭据已轮换', 'ok'); await loadProviders(); }
        catch (e) { toast(e.message, 'danger'); }
      }),
      miniBtn('删除', async () => {
        if (window.confirm(`确认删除「${p.displayName}」及其凭据？此操作不可撤销。`)) {
          try { await api(`/api/providers/${p.id}`, { method: 'DELETE', body: { confirmName: p.displayName } }); await loadProviders(); }
          catch (e) { toast(e.message, 'danger'); }
        }
      }, true),
    ];
    box.append(row(
      `${p.displayName}  ${p.credentialMasked || '***----'}`,
      `${p.vendor} · 凭据 ${p.credentialCount} 项 · ${p.enabled ? '已启用' : '已停用'}${p.decryptFailed ? ' · 解密失败已禁用' : ''}`,
      actions,
    ));
  });
}

async function loadRecords() {
  const list = await api('/api/ddns/records');
  const box = $('#r-list');
  clear(box);
  box.dataset.state = list.length ? 'ready' : 'empty';
  if (!list.length) { box.append(el('div', 'muted', '暂无解析记录。可先添加一条 Mock 记录验证同步流程。')); return; }
  list.forEach((r) => {
    box.append(row(`${r.name}.${r.domain}`, `${r.type} · ${r.vendor} · TTL ${r.ttl}`, [
      miniBtn('删除', async () => {
        if (!window.confirm(`删除记录 ${r.name}.${r.domain}？`)) return;
        try { await api(`/api/ddns/records/${r.id}`, { method: 'DELETE', body: {} }); await loadRecords(); }
        catch (e) { toast(e.message, 'danger'); }
      }, true),
    ]));
  });
  const providers = await api('/api/providers');
  const sel = $('#r-provider');
  clear(sel);
  const none = el('option', null, '（本地演示无需凭据）'); none.value = ''; sel.append(none);
  providers.forEach((p) => { const o = el('option', null, `${p.displayName} ${p.credentialMasked || ''}`); o.value = p.id; sel.append(o); });
}

async function loadUpstreams() {
  const [list, providers] = await Promise.all([api('/api/ai/upstreams'), api('/api/providers')]);
  const box = $('#ai-upstreams');
  clear(box);
  box.dataset.state = list.length ? 'ready' : 'empty';
  list.forEach((u) => {
    box.append(row(`${u.name} (#${u.priority})`, `${u.vendor} · ${u.model} · 日上限 ${u.dailyCap}${u.enabled ? '' : ' · 已停用'}`, [
      miniBtn(u.enabled ? '停用' : '启用', async () => {
        try { await api(`/api/ai/upstreams/${u.id}`, { method: 'PATCH', body: { enabled: !u.enabled } }); await loadUpstreams(); }
        catch (e) { toast(e.message, 'danger'); }
      }),
    ]));
  });
  const sel = $('#u-provider');
  clear(sel);
  const none = el('option', null, '（演示上游无需凭据）'); none.value = ''; sel.append(none);
  providers.forEach((p) => { const o = el('option', null, p.displayName); o.value = p.id; sel.append(o); });
  $('#ai-endpoint').textContent = `${location.origin}/v1/chat/completions`;
}

async function refreshStatus() {
  const s = await api('/api/status');
  lastStatus = s;
  document.body.dataset.state = 'ready';

  const ddns = s.health.ddnsEngine;
  $('#ov-ddns').textContent = { running: '运行中', degraded: '降级', stopped: '已停止' }[ddns] || ddns;
  $('#ov-ddns').dataset.tone = toneOf(ddns);
  $('#ov-ddns-sub').textContent = `当前公网 IP：${s.health.ddnsIp || '未检测'}`;
  $('#ov-ai').textContent = { running: '运行中', degraded: '降级', stopped: '已停止' }[s.health.aiGateway] || s.health.aiGateway;
  $('#ov-ai').dataset.tone = toneOf(s.health.aiGateway);
  $('#ov-ai-sub').textContent = `本机中转密钥：${s.ai?.localKey?.state === 'active' ? '已启用' : '默认关闭'}`;
  $('#ov-daemon').textContent = '运行中';
  $('#ov-daemon').dataset.tone = 'ok';
  $('#ov-daemon-sub').textContent = `已运行 ${s.health.uptimeSec} 秒`;

  const pb = $('#ov-providers');
  clear(pb);
  pb.dataset.state = s.providers.length ? 'ready' : 'empty';
  if (!s.providers.length) pb.append(el('div', 'muted', '未配置云厂商凭据'));
  s.providers.forEach((p) => {
    const dot = el('span', 'dot'); dot.dataset.tone = toneOf(p.status);
    const main = el('div', 'row-main');
    main.append(el('div', 'row-title', `${p.displayName} ${p.credentialMasked || ''}`),
      el('div', 'row-sub', `${p.vendor} · ${p.status}${p.lastTestedAt ? ` · ${p.lastTestedAt}` : ''}`));
    const wrap = el('div', 'row'); wrap.append(dot, main); pb.append(wrap);
  });

  const qb = $('#ov-quota');
  clear(qb);
  qb.dataset.state = s.quota.length ? 'ready' : 'empty';
  if (!s.quota.length) qb.append(el('div', 'muted', '暂无上游额度数据'));
  s.quota.forEach((q) => {
    const wrap = el('div', 'row');
    const main = el('div', 'row-main');
    main.append(el('div', 'row-title', `${q.vendor} · ${q.used}/${q.limit} 请求${q.circuitOpen ? ' · 熔断中' : ''}`),
      el('div', 'row-sub', `重置于 ${q.resetAt}`));
    // Native <progress> avoids inline style attributes (blocked by CSP).
    const prog = document.createElement('progress');
    prog.max = Math.max(1, q.limit);
    prog.value = q.used;
    prog.dataset.tone = q.ratio > 0.9 ? 'danger' : q.ratio > 0.7 ? 'warn' : 'ok';
    wrap.append(main, prog);
    qb.append(wrap);
  });

  const ev = $('#ov-events');
  clear(ev);
  s.events.slice(-8).reverse().forEach((e) => ev.append(logLine(e)));

  const au = $('#ov-audit');
  clear(au);
  (s.security.auditRecent || []).forEach((a) => au.append(logLine({
    at: a.at, level: a.result === 'denied' ? 'warn' : 'info',
    message: `${a.actor} · ${a.action} · ${a.result}`,
  })));

  const setBadge = (node, state, text) => { node.dataset.state = state; node.textContent = text; };
  setBadge($('#badge-vault'), s.security.credentialsEncrypted ? 'ok' : 'danger',
    s.security.credentialsEncrypted ? '凭据加密：DPAPI 已启用' : '凭据加密：不可用');
  setBadge($('#badge-loopback'), s.security.loopbackOnly ? 'ok' : 'danger',
    s.security.loopbackOnly ? `仅本机 :${s.security.listenPort}` : '监听范围：异常');
  setBadge($('#badge-localkey'), s.ai?.localKey?.state === 'active' ? 'warn' : 'ok',
    s.ai?.localKey?.state === 'active' ? '本机中转密钥：已启用' : '本机中转密钥：默认关闭');

  $('#side-port').textContent = `端口：${s.security.listenPort}`;
  $('#sec-store').textContent = s.security.encryptionScheme || '不可用';
  $('#sec-listen').textContent = (s.security.listenAddresses || []).join(', ');
  $('#sec-port').textContent = String(s.security.listenPort);
  $('#sec-anomalies').textContent = String(s.security.externalConnections || 0);
  $('#sec-key').textContent = s.ai?.localKey?.masked || '未生成（端点关闭）';
  $('#s-interval').value = '';
  $('#s-agree').value = '';
  $('#s-autostart').checked = Boolean(s.security.autoStart);
  $('#lk-state').textContent = `状态：${s.ai?.localKey?.state === 'active' ? '已启用' : '未生成（端点默认关闭）'}`;
  $('#lk-state').dataset.state = s.ai?.localKey?.state || 'absent';
  $('#lk-meta').textContent = `指纹：${s.ai?.localKey?.masked || '—'} · 创建于 ${s.ai?.localKey?.createdAt || '—'}`;

  const ddnsState = await api('/api/ddns/records').catch(() => []);
  $('#ddns-ip').textContent = ddnsIp(s);
  $('#ddns-msg').textContent = ddnsState.length ? `${ddnsState.length} 条记录受管` : '尚未配置记录';
}

function ddnsIp(s) { return s.health?.ddnsIp || '未检测'; }
function logLine(e) {
  const line = el('div', 'log-line');
  line.dataset.level = e.level || 'info';
  line.append(el('span', 'log-time', (e.at || '').slice(11, 19)), el('span', 'log-msg', e.message || ''));
  return line;
}

/* ---------------- SSE ---------------- */

function connectEvents() {
  eventSource = new EventSource('/api/events');
  const onLog = (e) => {
    try {
      const data = JSON.parse(e.data);
      const box = $('#ov-events');
      box.prepend(logLine(data));
      while (box.childElementCount > 40) box.removeChild(box.lastChild);
    } catch { /* malformed frame ignored */ }
  };
  ['log', 'health', 'ip-changed', 'ddns-result', 'ai-usage', 'security-alert'].forEach((n) => {
    eventSource.addEventListener(n, onLog);
  });
  eventSource.onerror = async () => {
    try {
      const r = await fetch('/api/status', { credentials: 'same-origin', cache: 'no-store' });
      if (r.status === 401) showLock('session-invalid');
    } catch { /* transient network error: EventSource will retry */ }
  };
}

/* ---------------- form wiring ---------------- */

function wire() {
  $$('.nav-item').forEach((b) => b.addEventListener('click', () => switchPage(b.dataset.nav)));

  $('#form-provider').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const credentials = {};
    $$('#p-fields input').forEach((i) => { if (i.value) credentials[i.dataset.key] = i.value; });
    try {
      await api('/api/providers', {
        method: 'POST',
        body: {
          vendor: $('#p-vendor').value,
          displayName: $('#p-name').value || vendorMeta[$('#p-vendor').value]?.label,
          note: $('#p-note').value || null,
          credentials,
        },
      });
      $('#p-name').value = ''; $('#p-note').value = '';
      $$('#p-fields input').forEach((i) => { i.value = ''; });
      toast('凭据已加密保存', 'ok');
      await loadProviders();
    } catch (e) { toast(e.message, 'danger'); }
  });

  $('#ddns-sync').addEventListener('click', async () => {
    try {
      const r = await api('/api/ddns/sync', { method: 'POST', body: { force: true } });
      toast(r.ok ? '同步完成' : `同步未完成：${r.reason || '失败'}`, r.ok ? 'ok' : 'danger');
      await refreshStatus();
    } catch (e) { toast(e.message, 'danger'); }
  });

  $('#form-record').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await api('/api/ddns/records', {
        method: 'POST',
        body: {
          domain: $('#r-domain').value, name: $('#r-name').value || '@',
          type: $('#r-type').value, ttl: Number($('#r-ttl').value || 60),
          vendor: $('#r-vendor').value, providerId: $('#r-provider').value || null,
        },
      });
      toast('记录已添加', 'ok');
      await loadRecords();
    } catch (e) { toast(e.message, 'danger'); }
  });

  $('#form-upstream').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await api('/api/ai/upstreams', {
        method: 'POST',
        body: {
          vendor: $('#u-vendor').value, name: $('#u-name').value || undefined,
          model: $('#u-model').value || undefined,
          priority: Number($('#u-priority').value || 100),
          dailyCap: Number($('#u-cap').value || 1000),
          providerId: $('#u-provider').value || null,
        },
      });
      toast('上游已添加', 'ok');
      await loadUpstreams();
    } catch (e) { toast(e.message, 'danger'); }
  });

  $('#lk-generate').addEventListener('click', async () => {
    if (!window.confirm('生成新的本机中转密钥？旧密钥将立即失效，且新密钥只显示一次。')) return;
    try {
      const r = await api('/api/ai/local-key', { method: 'POST', body: {} });
      const box = $('#lk-once');
      clear(box);
      box.hidden = false;
      box.dataset.field = 'local-key-once';
      box.dataset.once = 'true';
      box.append(el('div', 'muted', '请立即复制保存，关闭后无法再次查看：'));
      box.append(el('div', 'once-key', r.key));
      box.append(miniBtn('我已保存，关闭', () => { clear(box); box.hidden = true; box.removeAttribute('data-once'); }));
      await refreshStatus();
    } catch (e) { toast(e.message, 'danger'); }
  });

  $('#lk-revoke').addEventListener('click', async () => {
    if (!window.confirm('吊销本机中转密钥？/v1/chat/completions 将立即恢复为默认关闭。')) return;
    try {
      await api('/api/ai/local-key', { method: 'DELETE', body: { confirmName: 'REVOKE_LOCAL_KEY' } });
      const box = $('#lk-once'); clear(box); box.hidden = true; box.removeAttribute('data-once');
      toast('密钥已吊销，端点已关闭', 'ok');
      await refreshStatus();
    } catch (e) { toast(e.message, 'danger'); }
  });

  $('#form-settings').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      await api('/api/settings', {
        method: 'PATCH',
        body: {
          ddnsIntervalSec: $('#s-interval').value ? Number($('#s-interval').value) : undefined,
          minAgree: $('#s-agree').value ? Number($('#s-agree').value) : undefined,
          logLevel: $('#s-log').value,
          autoStart: $('#s-autostart').checked,
        },
      });
      toast('设置已保存', 'ok');
    } catch (e) { toast(e.message, 'danger'); }
  });

  $('#cfg-export').addEventListener('click', async () => {
    try {
      const r = await api('/api/config/export');
      $('#cfg-text').value = JSON.stringify(r, null, 2);
      toast('已生成脱敏配置（不含任何凭据）', 'ok');
    } catch (e) { toast(e.message, 'danger'); }
  });
  $('#cfg-import').addEventListener('click', async () => {
    try {
      await api('/api/config/import', { method: 'POST', body: { payload: $('#cfg-text').value } });
      toast('已导入脱敏配置；凭据需重新录入', 'ok');
      await refreshStatus();
    } catch (e) { toast(e.message, 'danger'); }
  });

  $('#btn-logout').addEventListener('click', async () => {
    if (!window.confirm('退出应用？会话将被销毁，需重新运行 start.cmd 才能再次使用。')) return;
    try { await api('/api/session/logout', { method: 'POST', body: {} }); } catch { /* shutting down */ }
    showLock('session-invalid');
    $('#lock-body').textContent = '应用已退出。请重新运行 start.cmd 完成重新认证。';
  });
  $('#lock-exit').addEventListener('click', async () => {
    try { await api('/api/session/logout', { method: 'POST', body: {} }); } catch { /* already gone */ }
    $('#lock-body').textContent = '应用已退出。请重新运行 start.cmd 完成重新认证。';
  });

  ['click', 'keydown', 'mousemove'].forEach((ev) => {
    document.addEventListener(ev, armIdle, { passive: true });
  });
}

/* ---------------- boot ---------------- */

(async function boot() {
  try {
    const r = await fetch('/__bootstrap', {
      method: 'POST',
      headers: { 'X-FCC-CSRF': '1', 'X-Local-CSRF': '1' },
      credentials: 'same-origin',
      cache: 'no-store',
    });
    if (!r.ok) { showLock('session-invalid'); return; }
    wire();
    armIdle();
    await loadVendorMeta();
    await refreshStatus();
    await Promise.all([loadProviders(), loadRecords(), loadUpstreams()]);
    connectEvents();
    switchPage('overview');
  } catch (e) {
    document.body.dataset.state = 'error';
    toast(`初始化失败：${e.message}`, 'danger');
    if (e.message === 'SESSION_INVALID') showLock('session-invalid');
  }
})();
