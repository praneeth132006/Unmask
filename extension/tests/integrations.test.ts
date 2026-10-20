import { domainAgeFindings, parseRdap } from '../src/integrations/rdap';
import { lookupFileHash, vtFindings, vtUrlId } from '../src/integrations/virustotal';
import { parseUrlscan, urlscanFindings } from '../src/integrations/urlscan';

describe('rdap', () => {
  const now = Date.parse('2026-10-19T00:00:00Z');
  it('parses registration date and registrar', () => {
    const age = parseRdap('x.top', {
      events: [{ eventAction: 'registration', eventDate: '2026-10-15T00:00:00Z' }],
      entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'NameCheap, Inc.']]] }],
    }, now);
    expect(age).toEqual({ domain: 'x.top', created: '2026-10-15T00:00:00Z', ageDays: 4, registrar: 'NameCheap, Inc.' });
    expect(domainAgeFindings(age, 'sender')[0]).toMatchObject({ severity: 'high', points: 25 });
  });

  it('treats old domains as informational', () => {
    const age = parseRdap('github.com', { events: [{ eventAction: 'registration', eventDate: '2007-10-09T18:20:50Z' }] }, now);
    expect(domainAgeFindings(age, 'sender')[0]?.severity).toBe('info');
  });
});

describe('virustotal', () => {
  it('builds URL ids as unpadded base64url', () => {
    expect(vtUrlId('http://www.example.com/')).toBe('aHR0cDovL3d3dy5leGFtcGxlLmNvbS8');
  });

  it('maps detection counts to findings', () => {
    const stats = { malicious: 12, suspicious: 1, harmless: 0, undetected: 50 };
    expect(vtFindings('vt', 'a.html', { found: true, stats, label: 'trojan.html/phish', permalink: '' }, 'attachments')[0]).toMatchObject({ severity: 'critical', points: 40 });
    expect(vtFindings('vt', 'a.html', { found: false, stats: null, label: null, permalink: '' }, 'attachments')[0]?.points).toBe(0);
  });

  it('treats 404 as "never seen" and sends the key header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 404 }));
    vi.stubGlobal('fetch', fetchMock);
    const r = await lookupFileHash('KEY', 'ab'.repeat(32));
    expect(r.found).toBe(false);
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toMatchObject({ 'x-apikey': 'KEY' });
    vi.unstubAllGlobals();
  });

  it('requires an API key', async () => {
    await expect(lookupFileHash('', 'ab')).rejects.toThrow(/API key/);
  });
});

describe('urlscan', () => {
  it('parses a result', () => {
    const r = parseUrlscan('uuid-1', {
      page: { url: 'https://evil.top/login', domain: 'evil.top', ip: '1.2.3.4', country: 'RU', title: 'PayPal Login' },
      verdicts: { overall: { malicious: true, score: 100, brands: [{ name: 'PayPal' }] } },
    });
    expect(r).toMatchObject({ finalUrl: 'https://evil.top/login', malicious: true, brands: ['PayPal'], screenshot: 'https://urlscan.io/screenshots/uuid-1.png' });
    expect(urlscanFindings('u', r)[0]?.severity).toBe('critical');
  });
});

describe('rdap not found', () => {
  it('turns a 404 into a medium finding', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{}', { status: 404 })));
    const { lookupDomainAge } = await import('../src/integrations/rdap');
    const age = await lookupDomainAge('nope-not-real.xyz');
    expect(age.notFound).toBe(true);
    expect(domainAgeFindings(age, 'sender')[0]).toMatchObject({ severity: 'medium', points: 10 });
    vi.unstubAllGlobals();
  });
});

describe('virustotal scan now', () => {
  it('submits the URL, polls the analysis and returns vendor stats', async () => {
    const { scanUrlNow } = await import('../src/integrations/virustotal');
    const calls: string[] = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: RequestInit) => {
      calls.push(`${init?.method ?? 'GET'} ${url.replace('https://www.virustotal.com/api/v3', '')}`);
      if (url.endsWith('/urls')) return new Response(JSON.stringify({ data: { id: 'u-abc-1' } }), { status: 200 });
      return new Response(JSON.stringify({ data: { attributes: { status: 'completed', stats: { malicious: 4, suspicious: 0, harmless: 60, undetected: 10 } } } }), { status: 200 });
    }));
    const r = await scanUrlNow('KEY', 'https://evil.top/login', undefined, 1);
    expect(calls).toEqual(['POST /urls', 'GET /analyses/u-abc-1']);
    expect(r.stats?.malicious).toBe(4);
    vi.unstubAllGlobals();
  });
});

describe('VirusTotal upload', () => {
  it('sends the attachment bytes straight from the email and returns the scan', async () => {
    const { uploadFile } = await import('../src/integrations/virustotal');
    const sent: { url: string; body: unknown }[] = [];
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      sent.push({ url: String(input), body: init?.body });
      if (String(input).endsWith('/files')) return new Response(JSON.stringify({ data: { id: 'an-1' } }), { status: 200 });
      return new Response(JSON.stringify({ data: { attributes: { status: 'completed', stats: { malicious: 5, suspicious: 0, harmless: 0, undetected: 60 } } } }), { status: 200 });
    });
    const bytes = new TextEncoder().encode('%PDF-1.7 test');
    const r = await uploadFile('key', bytes, 'challan.pdf', 'abc', undefined, 1);
    fetchMock.mockRestore();
    expect(sent[0]!.url).toBe('https://www.virustotal.com/api/v3/files');
    const file = (sent[0]!.body as FormData).get('file') as File;
    expect(file.name).toBe('challan.pdf');
    expect(new Uint8Array(await file.arrayBuffer())).toEqual(bytes);
    expect(r).toMatchObject({ found: true, stats: { malicious: 5 }, permalink: 'https://www.virustotal.com/gui/file/abc' });
  });
});

describe('urlscan polling', () => {
  it('sends the API key when fetching the result, so unlisted and private scans are found', async () => {
    const { scanUrl } = await import('../src/integrations/urlscan');
    const calls: { url: string; key: string | null }[] = [];
    let polls = 0;
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input);
      calls.push({ url, key: new Headers(init?.headers).get('API-Key') });
      if (url.endsWith('/scan/')) return new Response(JSON.stringify({ uuid: 'u1' }), { status: 200 });
      // Like urlscan: without the key, an unlisted result stays "not found".
      if (!new Headers(init?.headers).get('API-Key')) return new Response('', { status: 404 });
      return ++polls < 2 ? new Response('', { status: 404 }) : new Response(JSON.stringify({ page: { url: 'https://x.example/' } }), { status: 200 });
    });
    const r = await scanUrl('key-1', 'https://x.example/', 'unlisted', undefined, { firstWaitMs: 1, pollMs: 1, maxWaitMs: 5000 });
    fetchMock.mockRestore();
    expect(r.finalUrl).toBe('https://x.example/');
    expect(calls.filter((c) => c.url.includes('/result/')).every((c) => c.key === 'key-1')).toBe(true);
  });

  it('reports a still-running scan with its report link instead of failing', async () => {
    const { scanUrl, UrlscanPending } = await import('../src/integrations/urlscan');
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) =>
      String(input).endsWith('/scan/') ? new Response(JSON.stringify({ uuid: 'u2' }), { status: 200 }) : new Response('', { status: 404 }),
    );
    const err = await scanUrl('k', 'https://x.example/', 'unlisted', undefined, { firstWaitMs: 1, pollMs: 1, maxWaitMs: 30 }).catch((e: unknown) => e);
    fetchMock.mockRestore();
    expect(err).toBeInstanceOf(UrlscanPending);
    expect((err as InstanceType<typeof UrlscanPending>).reportUrl).toBe('https://urlscan.io/result/u2/');
  });
});
