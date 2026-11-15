import { createHash, createHmac } from 'node:crypto';

const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const hmac = (key, msg) => createHmac('sha256', key).update(msg, 'utf8').digest();
const hmacHex = (key, msg) => createHmac('sha256', key).update(msg, 'utf8').digest('hex');

/**
 * Tencent Cloud TC3-HMAC-SHA256 (v3 signature).
 * Used by DNSPod (service=dnspod) and Hunyuan (service=hunyuan).
 */
export function tc3Headers({ secretId, secretKey, host, service, action, version, region = '', payload = '{}' }) {
  const timestamp = Math.floor(Date.now() / 1000);
  const date = new Date(timestamp * 1000).toISOString().slice(0, 10);
  const credentialScope = `${date}/${service}/tc3_request`;
  const canonicalHeaders = `content-type:application/json; charset=utf-8\nhost:${host}\n`;
  const signedHeaders = 'content-type;host';
  const canonicalRequest = [
    'POST', '/', '', canonicalHeaders, signedHeaders, sha256hex(payload),
  ].join('\n');
  const stringToSign = [
    'TC3-HMAC-SHA256', String(timestamp), credentialScope, sha256hex(canonicalRequest),
  ].join('\n');
  const secretDate = hmac(`TC3${secretKey}`, date);
  const secretService = hmac(secretDate, service);
  const secretSigning = hmac(secretService, 'tc3_request');
  const signature = hmacHex(secretSigning, stringToSign);
  const authorization = `TC3-HMAC-SHA256 Credential=${secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return {
    Authorization: authorization,
    'Content-Type': 'application/json; charset=utf-8',
    'X-TC-Action': action,
    'X-TC-Timestamp': String(timestamp),
    'X-TC-Version': version,
    ...(region ? { 'X-TC-Region': region } : {}),
  };
}

function uriEncode(value, encodeSlash = true) {
  return encodeURIComponent(String(value))
    .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/%2F/g, encodeSlash ? '%2F' : '/');
}

/** AWS Signature V4, used by Route 53 (service=route53, region=us-east-1). */
export function sigV4Headers({
  accessKeyId,
  secretAccessKey,
  sessionToken = '',
  region,
  service,
  method = 'GET',
  host,
  canonicalPath = '/',
  query = {},
  payload = '',
  extraHeaders = {},
}) {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]/g, '').replace(/\.\d{3}/, '');
  const date = amzDate.slice(0, 8);
  const credentialScope = `${date}/${region}/${service}/aws4_request`;

  const canonicalQuery = Object.entries(query)
    .map(([k, v]) => [uriEncode(k), uriEncode(v)])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');

  const allHeaders = {
    host,
    'x-amz-content-sha256': sha256hex(payload),
    'x-amz-date': amzDate,
    ...Object.fromEntries(Object.entries(extraHeaders).map(([k, v]) => [k.toLowerCase(), v])),
    ...(sessionToken ? { 'x-amz-security-token': sessionToken } : {}),
  };
  const sortedNames = Object.keys(allHeaders).sort();
  const canonicalHeaders = sortedNames
    .map((n) => `${n}:${String(allHeaders[n]).trim().replace(/\s+/g, ' ')}\n`)
    .join('');
  const signedHeaders = sortedNames.join(';');

  const canonicalRequest = [
    method.toUpperCase(),
    uriEncode(canonicalPath, false),
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    sha256hex(payload),
  ].join('\n');
  const stringToSign = [
    'AWS4-HMAC-SHA256', amzDate, credentialScope, sha256hex(canonicalRequest),
  ].join('\n');

  const kDate = hmac(`AWS4${secretAccessKey}`, date);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = hmacHex(kSigning, stringToSign);

  return {
    Authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Content-Sha256': sha256hex(payload),
    ...(sessionToken ? { 'X-Amz-Security-Token': sessionToken } : {}),
    ...extraHeaders,
  };
}
