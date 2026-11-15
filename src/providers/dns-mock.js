/** In-memory DNS provider for offline verification. Never touches the network. */
export const mockStore = new Map();

export function createMockDns() {
  return {
    vendor: 'mock',
    async test() { return { ok: true, detail: 'offline mock provider' }; },
    async current(record) {
      const key = `${record.domain}/${record.name}/${record.type}`;
      return { value: mockStore.get(key) || null, recordId: `mock:${key}` };
    },
    async update(record, ip) {
      const key = `${record.domain}/${record.name}/${record.type}`;
      mockStore.set(key, ip);
      return { ok: true, detail: `mock ${key} -> ${ip}` };
    },
  };
}
