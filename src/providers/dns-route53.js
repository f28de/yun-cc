import { httpRequest } from './http.js';
import { sigV4Headers } from './sign.js';

const HOST = 'route53.amazonaws.com';
const BASE = `https://${HOST}`;
const REGION = 'us-east-1';
const SERVICE = 'route53';

const esc = (s) => String(s).replace(/[<>&"']/g, (c) => (
  { '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]
));
const fqdn = (r) => (r.name === '@' ? r.domain : `${r.name}.${r.domain}`);

function auth(creds, method, canonicalPath, query, payload, extra = {}) {
  return sigV4Headers({
    accessKeyId: creds.accessKeyId,
    secretAccessKey: creds.secretAccessKey,
    sessionToken: creds.sessionToken || '',
    region: REGION,
    service: SERVICE,
    method,
    host: HOST,
    canonicalPath,
    query,
    payload,
    extraHeaders: extra,
  });
}

function xmlValue(text, tag) {
  const m = text.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i'));
  return m ? m[1].trim() : null;
}

export function createRoute53Dns(creds) {
  return {
    vendor: 'aws',
    async test() {
      const path = '/2013-04-01/hostedzones';
      const r = await httpRequest(`${BASE}${path}`, {
        headers: auth(creds, 'GET', path, {}, ''),
      });
      return { ok: r.ok, detail: `HTTP ${r.status}` };
    },
    async current(record) {
      const zone = record.zoneId;
      if (!zone) throw new Error('Route53 record requires zoneId (hosted zone id)');
      const path = `/2013-04-01/hostedzone/${zone}/rrset`;
      const query = { name: fqdn(record), type: record.type, maxitems: '1' };
      const qs = new URLSearchParams(query).toString();
      const r = await httpRequest(`${BASE}${path}?${qs}`, {
        headers: auth(creds, 'GET', path, query, ''),
      });
      if (!r.ok) throw new Error(`Route53 lookup HTTP ${r.status}`);
      return { value: xmlValue(r.text, 'Value'), recordId: `${zone}:${fqdn(record)}` };
    },
    async update(record, ip) {
      const zone = record.zoneId;
      if (!zone) throw new Error('Route53 record requires zoneId (hosted zone id)');
      const path = `/2013-04-01/hostedzone/${zone}/rrset/`;
      const payload = `<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
<ChangeBatch><Changes><Change><Action>UPSERT</Action>
<ResourceRecordSet><Name>${esc(fqdn(record))}</Name><Type>${esc(record.type)}</Type>
<TTL>${Number(record.ttl || 60)}</TTL><ResourceRecords>
<ResourceRecord><Value>${esc(ip)}</Value></ResourceRecord>
</ResourceRecords></ResourceRecordSet>
</Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>`;
      const r = await httpRequest(`${BASE}${path}`, {
        method: 'POST',
        headers: auth(creds, 'POST', path, {}, payload, { 'Content-Type': 'text/xml' }),
        body: payload,
      });
      if (!r.ok) throw new Error(`Route53 UPSERT HTTP ${r.status}`);
      return { ok: true, detail: `${fqdn(record)} -> ${ip}` };
    },
  };
}
