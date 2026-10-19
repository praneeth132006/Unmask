import { testBackend, testUrlscanKey, testVirusTotalKey } from '../src/integrations/keyTest';

const respond = (status: number, body: unknown = {}) => vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status }));

afterEach(() => vi.unstubAllGlobals());

describe('key tests', () => {
  it('rejects malformed VirusTotal keys without calling the API', async () => {
    const f = respond(200);
    vi.stubGlobal('fetch', f);
    expect((await testVirusTotalKey('https://www.virustotal.com/gui/my-apikey')).ok).toBe(false);
    expect(f).not.toHaveBeenCalled();
  });

  it('accepts a working VirusTotal key and reports an invalid one', async () => {
    vi.stubGlobal('fetch', respond(200));
    expect(await testVirusTotalKey('a'.repeat(64))).toEqual({ ok: true, message: 'Connected to VirusTotal.' });
    vi.stubGlobal('fetch', respond(401));
    expect((await testVirusTotalKey('a'.repeat(64))).message).toMatch(/not valid/);
  });

  it('checks urlscan key format and validity', async () => {
    expect((await testUrlscanKey('nope')).ok).toBe(false);
    vi.stubGlobal('fetch', respond(200));
    expect((await testUrlscanKey('1a2b3c4d-1a2b-1a2b-1a2b-1a2b3c4d5e6f')).ok).toBe(true);
  });

  it('recognises an Unmask backend', async () => {
    vi.stubGlobal('fetch', respond(200, { ok: true }));
    expect((await testBackend('http://localhost:8787/')).ok).toBe(true);
    vi.stubGlobal('fetch', respond(200, { hello: 1 }));
    expect((await testBackend('https://example.com')).ok).toBe(false);
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('fail')));
    expect((await testBackend('http://localhost:8787')).message).toMatch(/pnpm backend/);
  });
});
