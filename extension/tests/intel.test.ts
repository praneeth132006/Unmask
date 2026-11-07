import { PrivateGoogleFile, fetchGoogleFile, googleDocLinks, googleDocRef } from '../src/integrations/googleDocs';
import { intelFindings, lookupHybridAnalysis, lookupMalwareBazaar, parseBazaar, parseHybrid } from '../src/integrations/intel';

const SHA = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

afterEach(() => vi.unstubAllGlobals());

describe('hash-only lookups', () => {
  it('Hybrid Analysis: asks for the hash only and reads the verdict', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ verdict: 'malicious', threat_score: 100, av_detect: 81, vx_family: 'Emotet', tags: ['trojan', 'macro'] }));
    vi.stubGlobal('fetch', fetchMock);
    const hit = await lookupHybridAnalysis('k'.repeat(40), SHA);
    expect(fetchMock.mock.calls[0]![0]).toBe(`https://www.hybrid-analysis.com/api/v2/overview/${SHA}`);
    expect(fetchMock.mock.calls[0]![1].method).toBeUndefined(); // a GET: no file body is ever sent
    expect(hit).toMatchObject({ found: true, verdict: 'malicious', permalink: `https://www.hybrid-analysis.com/sample/${SHA}` });
    expect(hit.summary).toMatch(/Emotet/);
    expect(intelFindings('x', 'invoice.pdf', hit, 'attachments')[0]).toMatchObject({ severity: 'critical', points: 40 });
  });

  it('Hybrid Analysis: unknown file is "no record", not "safe"', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 404 })));
    const hit = await lookupHybridAnalysis('k'.repeat(40), SHA);
    expect(hit).toMatchObject({ found: false, verdict: 'unknown' });
    expect(intelFindings('x', 'a.pdf', hit, 'attachments')[0]!.points).toBe(0);
  });

  it('Hybrid Analysis: explains a rejected key and a missing key', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 403 })));
    await expect(lookupHybridAnalysis('k'.repeat(40), SHA)).rejects.toThrow(/rejected the API key/);
    await expect(lookupHybridAnalysis('', SHA)).rejects.toThrow(/Add your free Hybrid Analysis/);
  });

  it('parses sandbox verdict wording', () => {
    expect(parseHybrid({ verdict: 'whitelisted' }, 'p').verdict).toBe('clean');
    expect(parseHybrid({ verdict: 'suspicious', threat_score: 55 }, 'p').verdict).toBe('suspicious');
    expect(parseHybrid({}, 'p').verdict).toBe('unknown');
  });

  it('MalwareBazaar: posts only the hash with the Auth-Key header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ query_status: 'ok', data: [{ sha256_hash: SHA, signature: 'AgentTesla', file_type: 'docx', first_seen: '2026-01-02 03:04:05', tags: ['docx', 'AgentTesla'], delivery_method: 'email_attachment' }] }));
    vi.stubGlobal('fetch', fetchMock);
    const hit = await lookupMalwareBazaar('auth-key-1234567890', SHA);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('https://mb-api.abuse.ch/api/v1/');
    expect(init.headers['Auth-Key']).toBe('auth-key-1234567890');
    expect(init.body).toBe(`query=get_info&hash=${SHA}`);
    expect(hit).toMatchObject({ found: true, verdict: 'malicious' });
    expect(hit.summary).toMatch(/AgentTesla/);
  });

  it('MalwareBazaar: hash_not_found is not a verdict', () => {
    expect(parseBazaar({ query_status: 'hash_not_found' }, 'p')).toMatchObject({ found: false, verdict: 'unknown' });
    expect(() => parseBazaar({ query_status: 'unknown_auth_key' }, 'p')).toThrow(/Auth-Key/);
  });
});

describe('Google files linked from an email', () => {
  const ID = '1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';
  it('recognises Docs, Sheets, Slides and Drive links', () => {
    expect(googleDocRef(`https://docs.google.com/document/d/${ID}/edit?usp=sharing`)).toMatchObject({ kind: 'document', exportUrl: `https://docs.google.com/document/d/${ID}/export?format=docx` });
    expect(googleDocRef(`https://docs.google.com/spreadsheets/u/0/d/${ID}/edit`)).toMatchObject({ kind: 'spreadsheet', exportUrl: `https://docs.google.com/spreadsheets/d/${ID}/export?format=xlsx` });
    expect(googleDocRef(`https://docs.google.com/presentation/d/${ID}/edit`)).toMatchObject({ kind: 'presentation', exportUrl: `https://docs.google.com/presentation/d/${ID}/export/pptx` });
    expect(googleDocRef(`https://drive.google.com/file/d/${ID}/view`)).toMatchObject({ kind: 'drive-file' });
    expect(googleDocRef(`https://drive.google.com/open?id=${ID}`)).toMatchObject({ kind: 'drive-file' });
    expect(googleDocRef('https://docs.google.com/forms/d/e/abc/viewform')).toBeNull();
    expect(googleDocRef('https://evil.example/document/d/' + ID)).toBeNull();
  });

  it('lists each file once', () => {
    expect(googleDocLinks([`https://docs.google.com/document/d/${ID}/edit`, `https://docs.google.com/document/d/${ID}/view`, 'https://example.com'])).toHaveLength(1);
  });

  it('fetches anonymously and refuses private files', async () => {
    const ref = googleDocRef(`https://docs.google.com/document/d/${ID}/edit`)!;
    const ok = vi.fn().mockResolvedValue(new Response(new Uint8Array([0x50, 0x4b, 3, 4]), { headers: { 'content-type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' } }));
    expect((await fetchGoogleFile(ref, ok)).length).toBe(4);
    expect(ok.mock.calls[0]![1]).toMatchObject({ credentials: 'omit', referrerPolicy: 'no-referrer' });
    const login = vi.fn().mockResolvedValue(new Response('<html>accounts.google.com ServiceLogin</html>', { headers: { 'content-type': 'text/html' } }));
    await expect(fetchGoogleFile(ref, login)).rejects.toBeInstanceOf(PrivateGoogleFile);
    await expect(fetchGoogleFile(ref, vi.fn().mockResolvedValue(new Response('', { status: 403 })))).rejects.toBeInstanceOf(PrivateGoogleFile);
  });
});

describe('link lookups', () => {
  it('URLhaus: sends only the link with the Auth-Key and reads the answer', async () => {
    const { lookupUrlhaus, parseUrlhaus } = await import('../src/integrations/intel');
    const fetchMock = vi.fn().mockResolvedValue(json({ query_status: 'ok', url_status: 'online', threat: 'malware_download', tags: ['Emotet'], urlhaus_reference: 'https://urlhaus.abuse.ch/url/1/', payloads: [{ filename: 'a.exe', file_type: 'exe', signature: 'Emotet' }] }));
    vi.stubGlobal('fetch', fetchMock);
    const hit = await lookupUrlhaus('auth-key-1234567890', 'https://evil.example/a.exe');
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe('https://urlhaus-api.abuse.ch/v1/url/');
    expect(init.headers['Auth-Key']).toBe('auth-key-1234567890');
    expect(init.body).toBe('url=https%3A%2F%2Fevil.example%2Fa.exe');
    expect(hit).toMatchObject({ found: true, verdict: 'malicious', permalink: 'https://urlhaus.abuse.ch/url/1/' });
    expect(hit.summary).toMatch(/still online/);
    expect(parseUrlhaus({ query_status: 'no_results' }, 'u')).toMatchObject({ found: false, verdict: 'unknown' });
  });

  it('PhishTank: needs no key, sends the link base64 encoded, tells verified from reported', async () => {
    const { lookupPhishTank, parsePhishTank } = await import('../src/integrations/intel');
    const fetchMock = vi.fn().mockResolvedValue(json({ meta: { status: 'success' }, results: { url: 'https://x', in_database: true, phish_id: 123, phish_detail_url: 'https://phishtank.org/phish_detail.php?phish_id=123', verified: true, valid: true, verified_at: '2026-01-01T00:00:00+00:00' } }));
    vi.stubGlobal('fetch', fetchMock);
    const hit = await lookupPhishTank('https://paypa1-secure.top/login');
    const [, init] = fetchMock.mock.calls[0]!;
    expect(Object.keys(init.headers)).not.toContain('api-key');
    expect(init.body).toBe(`url=${encodeURIComponent(btoa('https://paypa1-secure.top/login'))}&format=json`);
    expect(hit).toMatchObject({ found: true, verdict: 'malicious', permalink: 'https://phishtank.org/phish_detail.php?phish_id=123' });
    expect(parsePhishTank({ results: { in_database: true, verified: false } }).verdict).toBe('suspicious');
    expect(parsePhishTank({ results: { in_database: true, verified: true, valid: false } }).verdict).toBe('clean');
    expect(parsePhishTank({ results: { in_database: false } })).toMatchObject({ found: false, verdict: 'unknown' });
  });

  it('PhishTank: explains its rate limit', async () => {
    const { lookupPhishTank } = await import('../src/integrations/intel');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('', { status: 509 })));
    await expect(lookupPhishTank('https://x.example')).rejects.toThrow(/rate limit/);
  });
});
