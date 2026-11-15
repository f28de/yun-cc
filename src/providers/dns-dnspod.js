import { httpJson } from './http.js';
import { tc3Headers } from './sign.js';

const HOST = 'dnspod.tencentcloudapi.com';
const URL = `https://${HOST}/`;
const VERSION = '2021-03-23';

export function createDnspodDns({ secretId, secretKey }) {
  async function call(action, params) {
    const payload = JSON.stringify(params);
    const headers = tc3Headers({
      secretId, secretKey, host: HOST, service: 'dnspod',
      action, version: VERSION, payload,
    });
    const r = await httpJson(URL, { method: 'POST', headers, body: payload });
    const resp = r.data?.Response || {};
    if (resp.Error) throw new Error(`DNSPod ${action}: ${resp.Error.Code} ${resp.Error.Message}`);
    if (!r.ok) throw new Error(`DNSPod ${action}: HTTP ${r.status}`);
    return resp;
  }

  function split(record) {
    return { Domain: record.domain, SubDomain: record.name === '@' ? '@' : record.name };
  }

  return {
    vendor: 'tencent',
    async test() {
      await call('DescribeDomainList', { Limit: 1, Offset: 0 });
      return { ok: true, detail: 'DescribeDomainList ok' };
    },
    async current(record) {
      const resp = await call('DescribeRecordList', { ...split(record), RecordType: record.type, Limit: 20 });
      const hit = (resp.RecordList || [])[0];
      return { value: hit?.Value || null, recordId: hit?.RecordId ? String(hit.RecordId) : null };
    },
    async update(record, ip) {
      const found = await this.current(record);
      const params = {
        ...split(record),
        RecordType: record.type,
        RecordLine: '默认',
        Value: ip,
        TTL: Number(record.ttl || 600),
      };
      if (found.recordId) params.RecordId = Number(found.recordId);
      await call(found.recordId ? 'ModifyRecord' : 'CreateRecord', params);
      return { ok: true, detail: `${record.name}.${record.domain} -> ${ip}` };
    },
  };
}
