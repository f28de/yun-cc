import { createCloudflareDns } from './dns-cloudflare.js';
import { createDnspodDns } from './dns-dnspod.js';
import { createRoute53Dns } from './dns-route53.js';
import { createAzureDns } from './dns-azure.js';
import { createMockDns } from './dns-mock.js';

export const VENDOR_META = {
  cloudflare: {
    label: 'Cloudflare',
    fields: [
      { key: 'apiToken', label: 'API Token', secret: true, hint: 'Zone:DNS Edit + Zone:Read, scoped per zone' },
    ],
  },
  tencent: {
    label: '腾讯云 DNSPod',
    fields: [
      { key: 'secretId', label: 'SecretId', secret: true },
      { key: 'secretKey', label: 'SecretKey', secret: true },
    ],
  },
  aws: {
    label: 'AWS Route 53',
    fields: [
      { key: 'accessKeyId', label: 'Access Key ID', secret: true },
      { key: 'secretAccessKey', label: 'Secret Access Key', secret: true },
      { key: 'sessionToken', label: 'Session Token (optional)', secret: true, optional: true },
    ],
  },
  azure: {
    label: 'Azure DNS',
    fields: [
      { key: 'tenantId', label: 'Tenant ID', secret: false },
      { key: 'clientId', label: 'Client ID', secret: false },
      { key: 'clientSecret', label: 'Client Secret', secret: true },
      { key: 'subscriptionId', label: 'Subscription ID', secret: false },
      { key: 'resourceGroup', label: 'Resource Group', secret: false },
    ],
  },
  mock: {
    label: '本地演示 (Mock)',
    fields: [],
    offline: true,
  },
};

export function createDnsProvider(vendor, secrets = {}) {
  switch (vendor) {
    case 'cloudflare': return createCloudflareDns(secrets);
    case 'tencent': return createDnspodDns(secrets);
    case 'aws': return createRoute53Dns(secrets);
    case 'azure': return createAzureDns(secrets);
    case 'mock': return createMockDns();
    default: throw new Error(`unsupported DNS vendor: ${vendor}`);
  }
}

export function missingSecretFields(vendor, secrets) {
  const fields = VENDOR_META[vendor]?.fields || [];
  return fields
    .filter((f) => f.secret && !f.optional && !String(secrets?.[f.key] || '').trim())
    .map((f) => f.key);
}
