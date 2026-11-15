import { assertUpstream } from '../util.js';
import { tc3Headers, sigV4Headers } from './sign.js';

const ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const safeId = (v, label) => {
  if (!ID_RE.test(String(v || ''))) throw new Error(`invalid ${label}`);
  return String(v);
};
const enc = encodeURIComponent;

function render(template, vars) {
  return template.replace(/\{(\w+)\}/g, (_, key) => {
    const v = vars[key];
    if (v === undefined || v === null || v === '') throw new Error(`missing upstream parameter: ${key}`);
    return enc(v);
  });
}

/**
 * Build a fully validated upstream request. The endpoint ALWAYS comes from
 * the server-side allowlisted template - the caller can never supply a
 * base_url (SSRF / credential-exfiltration guard).
 */
export function buildUpstreamRequest(upstream, secrets, body) {
  const kind = upstream.kind;

  if (kind === 'mock') {
    return { kind, url: null, headers: {}, payload: JSON.stringify(body) };
  }

  if (kind === 'openai-compatible') {
    const url = render(upstream.endpoint, { accountId: secrets.accountId });
    assertUpstream(url, 'ai');
    return {
      kind,
      url,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${secrets.apiToken}`,
      },
      payload: JSON.stringify({ ...body, model: upstream.model || body.model }),
    };
  }

  if (kind === 'azure-openai') {
    const url = render(upstream.endpoint, {
      resource: secrets.resource,
      deployment: secrets.deployment || upstream.model,
    });
    assertUpstream(url, 'ai');
    return {
      kind,
      url,
      headers: { 'Content-Type': 'application/json', 'api-key': secrets.apiKey },
      payload: JSON.stringify({ ...body, model: undefined }),
    };
  }

  if (kind === 'tencent-tc3') {
    const url = 'https://hunyuan.tencentcloudapi.com/';
    assertUpstream(url, 'ai');
    const payload = JSON.stringify({
      Model: upstream.model,
      Messages: (body.messages || []).map((m) => ({ Role: m.role, Content: m.content })),
      Temperature: body.temperature,
      TopP: body.top_p,
      Stream: Boolean(body.stream),
    });
    const headers = tc3Headers({
      secretId: secrets.secretId,
      secretKey: secrets.secretKey,
      host: 'hunyuan.tencentcloudapi.com',
      service: 'hunyuan',
      action: 'ChatCompletions',
      version: '2023-09-01',
      payload,
    });
    return { kind, url, headers, payload };
  }

  if (kind === 'aws-bedrock') {
    const region = safeId(secrets.region || 'us-east-1', 'region');
    const modelId = safeId(upstream.model, 'modelId');
    const host = `bedrock-runtime.${region}.amazonaws.com`;
    const path = `/model/${modelId}/invoke`;
    const url = `https://${host}${path}`;
    assertUpstream(url, 'ai');
    const payload = JSON.stringify({
      anthropic_version: 'bedrock-2023-05-31',
      max_tokens: body.max_tokens || 1024,
      temperature: body.temperature,
      messages: (body.messages || []).filter((m) => m.role !== 'system').map((m) => ({
        role: m.role, content: m.content,
      })),
    });
    const headers = sigV4Headers({
      accessKeyId: secrets.accessKeyId,
      secretAccessKey: secrets.secretAccessKey,
      sessionToken: secrets.sessionToken || '',
      region,
      service: 'bedrock',
      method: 'POST',
      host,
      canonicalPath: path,
      query: {},
      payload,
      extraHeaders: { 'Content-Type': 'application/json' },
    });
    return { kind, url, headers, payload };
  }

  throw new Error(`unsupported upstream kind: ${kind}`);
}

/** Normalise non-OpenAI upstream replies into OpenAI chat.completion shape. */
export function normalizeUpstreamResponse(kind, data, fallbackModel) {
  if (!data || typeof data !== 'object') return null;
  if (kind === 'openai-compatible' || kind === 'azure-openai' || kind === 'mock') return data;

  if (kind === 'tencent-tc3') {
    const r = data.Response || data;
    const choice = r.Choices?.[0];
    const text = choice?.Message?.Content || choice?.Delta?.Content || '';
    return {
      id: r.Id || `chatcmpl-tc3-${Date.now()}`,
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: fallbackModel,
      choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: choice?.FinishReason || 'stop' }],
      usage: r.Usage || undefined,
    };
  }

  if (kind === 'aws-bedrock') {
    const text = (data.content || []).map((c) => c.text || '').join('');
    return {
      id: `chatcmpl-bedrock-${Date.now()}`,
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: fallbackModel,
      choices: [{ index: 0, message: { role: 'assistant', content: text }, finish_reason: data.stop_reason || 'stop' }],
      usage: data.usage ? {
        prompt_tokens: data.usage.input_tokens,
        completion_tokens: data.usage.output_tokens,
        total_tokens: (data.usage.input_tokens || 0) + (data.usage.output_tokens || 0),
      } : undefined,
    };
  }
  return data;
}
