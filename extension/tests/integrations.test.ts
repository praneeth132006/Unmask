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
