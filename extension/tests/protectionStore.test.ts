/** The organisation's list (pushed by policy) is merged into every check but never written to the user's own list. */
const local: Record<string, unknown> = {};
let managed: Record<string, unknown> | Error = {};

vi.mock('wxt/browser', () => ({
  browser: {
    storage: {
      local: {
        get: async (k: string) => (k in local ? { [k]: local[k] } : {}),
        set: async (o: Record<string, unknown>) => void Object.assign(local, o),
      },
      managed: {
        get: async (k: string) => {
          if (managed instanceof Error) throw managed;
          return k in managed ? { [k]: managed[k] } : {};
        },
      },
    },
  },
}));

const store = await import('../src/lib/protectionStore');

beforeEach(() => {
  for (const k of Object.keys(local)) delete local[k];
  managed = {};
});

describe('organisation protection list', () => {
  it('merges the policy list into the checks without saving it as the user’s own', async () => {
    await store.saveProtection({ version: 1, brands: [], contacts: [], trusted: ['me@home.org'] });
    managed = { protectionList: { label: 'Acme IT', brands: [{ name: 'Acme Payroll', domains: ['acmepay.com'] }], contacts: [], trusted: ['acme.com'] } };
    const merged = await store.loadProtection();
    expect(merged.brands.map((b) => b.name)).toEqual(['Acme Payroll']);
    expect(merged.trusted).toEqual(['me@home.org', 'acme.com']);
    expect((await store.loadOwnProtection()).trusted).toEqual(['me@home.org']);
    expect((await store.loadManagedProtection()).label).toBe('Acme IT');
  });

  it('works unmanaged, and when the browser has no managed storage at all', async () => {
    await store.saveProtection({ version: 1, brands: [], contacts: [], trusted: ['me@home.org'] });
    expect((await store.loadProtection()).trusted).toEqual(['me@home.org']);
    managed = new Error('managed storage not available');
    expect((await store.loadProtection()).trusted).toEqual(['me@home.org']);
  });

  it('drops malformed policy entries', async () => {
    managed = { protectionList: { brands: [{ name: 'No domains', domains: [] }, 'junk'], trusted: ['not an address', 'ok.com'] } };
    const m = await store.loadManagedProtection();
    expect(m.brands).toEqual([]);
    expect(m.trusted).toEqual(['ok.com']);
  });
});
