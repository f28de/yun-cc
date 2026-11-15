import { httpRequest, httpJson } from './http.js';

const API_VERSION = '2018-05-01';
const ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const assertId = (v, label) => {
  if (!ID_RE.test(String(v || ''))) throw new Error(`invalid ${label}`);
  return String(v);
};

export function createAzureDns(creds) {
  let cached = { token: '', expiresAt: 0 };

  async function token() {
    if (cached.token && cached.expiresAt > Date.now() + 60000) return cached.token;
    const tenant = assertId(creds.tenantId, 'tenantId');
    const url = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
    const body = new URLSearchParams({
      client_id: creds.clientId,
      client_secret: creds.clientSecret,
      grant_type: 'client_credentials',
      scope: 'https://management.azure.com/.default',
    }).toString();
    const r = await httpJson(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!r.ok || !r.data?.access_token) throw new Error(`Azure token HTTP ${r.status}`);
    cached = {
      token: r.data.access_token,
      expiresAt: Date.now() + Number(r.data.expires_in || 3600) * 1000,
    };
    return cached.token;
  }

  function recordUrl(record) {
    const sub = assertId(creds.subscriptionId, 'subscriptionId');
    const rg = assertId(creds.resourceGroup, 'resourceGroup');
    const zone = assertId(record.domain, 'dnsZone');
    const name = assertId(record.name, 'recordName');
    return `https://management.azure.com/subscriptions/${sub}/resourceGroups/${rg}`
      + `/providers/Microsoft.Network/dnsZones/${zone}/${record.type}/${name}`
      + `?api-version=${API_VERSION}`;
  }

  return {
    vendor: 'azure',
    async test() {
      await token();
      return { ok: true, detail: 'OAuth2 client_credentials ok' };
    },
    async current(record) {
      const r = await httpJson(recordUrl(record), {
        headers: { Authorization: `Bearer ${await token()}` },
      });
      if (r.status === 404) return { value: null, recordId: null };
      if (!r.ok) throw new Error(`Azure DNS GET HTTP ${r.status}`);
      const props = r.data?.properties || {};
      const list = record.type === 'AAAA' ? props.AAAARecords : props.ARecords;
      const value = list?.[0]?.[record.type === 'AAAA' ? 'ipv6Address' : 'ipv4Address'] || null;
      return { value, recordId: r.data?.id || null };
    },
    async update(record, ip) {
      const records = record.type === 'AAAA'
        ? { AAAARecords: [{ ipv6Address: ip }] }
        : { ARecords: [{ ipv4Address: ip }] };
      const body = JSON.stringify({ properties: { TTL: Number(record.ttl || 600), ...records } });
      const r = await httpRequest(recordUrl(record), {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${await token()}`,
          'Content-Type': 'application/json',
        },
        body,
      });
      if (!r.ok) throw new Error(`Azure DNS PATCH HTTP ${r.status}`);
      return { ok: true, detail: `${record.name}.${record.domain} -> ${ip}` };
    },
  };
}
