import { httpJson, okOrThrow } from './http.js';

const API = 'https://api.cloudflare.com/client/v4';
const enc = encodeURIComponent;

export function createCloudflareDns({ apiToken, zoneId = '' }) {
  const auth = { Authorization: `Bearer ${apiToken}` };

  async function resolveZone(domain) {
    if (zoneId) return zoneId;
    const r = okOrThrow(
      await httpJson(`${API}/zones?name=${enc(domain)}&per_page=1`, { headers: auth }),
      'Cloudflare zone lookup',
    );
    const z = r.data?.result?.[0]?.id;
    if (!z) throw new Error('Cloudflare zone not found or token lacks Zone:Read');
    return z;
  }

  return {
    vendor: 'cloudflare',
    async test() {
      const r = await httpJson(`${API}/user/tokens/verify`, { headers: auth });
      return { ok: r.ok && r.data?.success === true, detail: `HTTP ${r.status}` };
    },
    async current(record) {
      const z = await resolveZone(record.domain);
      const fqdn = record.name === '@' ? record.domain : `${record.name}.${record.domain}`;
      const r = okOrThrow(
        await httpJson(`${API}/zones/${z}/dns_records?name=${enc(fqdn)}&type=${enc(record.type)}`, { headers: auth }),
        'Cloudflare record lookup',
      );
      const hit = r.data?.result?.[0];
      return { value: hit?.content || null, recordId: hit?.id || null };
    },
    async update(record, ip) {
      const z = await resolveZone(record.domain);
      const fqdn = record.name === '@' ? record.domain : `${record.name}.${record.domain}`;
      const found = await this.current({ ...record });
      const body = JSON.stringify({
        type: record.type,
        name: fqdn,
        content: ip,
        ttl: Number(record.ttl || 60),
        proxied: false,
      });
      const url = found.recordId
        ? `${API}/zones/${z}/dns_records/${found.recordId}`
        : `${API}/zones/${z}/dns_records`;
      const r = okOrThrow(
        await httpJson(url, {
          method: found.recordId ? 'PATCH' : 'POST',
          headers: { ...auth, 'Content-Type': 'application/json' },
          body,
        }),
        'Cloudflare record update',
      );
      if (r.data && r.data.success === false) throw new Error('Cloudflare API returned success=false');
      return { ok: true, detail: `${fqdn} -> ${ip}` };
    },
  };
}
