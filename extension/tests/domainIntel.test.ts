import { certFindings, lookupMailRecords, mailRecordFindings, parseCrtSh, parseDmarc, postureFindings } from '../src/integrations/domainIntel';

const NOW = Date.parse('2026-10-19T12:00:00Z');

describe('domain intelligence', () => {
  it('finds the first certificate in crt.sh results', () => {
    const c = parseCrtSh('x.top', [{ not_before: '2026-10-17T08:00:00' }, { not_before: '2026-10-18T08:00:00' }], NOW);
    expect(c).toMatchObject({ firstSeen: '2026-10-17T08:00:00.000Z', ageDays: 2, count: 2 });
    expect(parseCrtSh('none.top', [], NOW)).toMatchObject({ firstSeen: null, ageDays: null });
  });

  it('warns about brand-new certificates only', () => {
    expect(certFindings(parseCrtSh('x.top', [{ not_before: '2026-10-18T00:00:00' }], NOW), 'link')[0]).toMatchObject({ severity: 'high', category: 'links' });
    expect(certFindings(parseCrtSh('x.top', [{ not_before: '2026-10-01T00:00:00' }], NOW), 'sender')[0]).toMatchObject({ severity: 'medium' });
    expect(certFindings(parseCrtSh('old.com', [{ not_before: '2019-01-01T00:00:00' }], NOW), 'sender')).toEqual([]);
    expect(certFindings(parseCrtSh('nocert.com', [], NOW), 'sender')).toEqual([]);
  });

  it('reads mail records over DNS-over-HTTPS', async () => {
    const answers: Record<string, { type: number; data: string }[]> = {
      'x.top/MX': [],
      'x.top/TXT': [{ type: 16, data: '"google-site-verification=abc"' }],
      '_dmarc.x.top/TXT': [],
      'x.top/A': [{ type: 1, data: '1.2.3.4' }],
      'x.top/AAAA': [],
    };
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const u = new URL(String(input));
      return new Response(JSON.stringify({ Status: 0, Answer: answers[`${u.searchParams.get('name')}/${u.searchParams.get('type')}`] }), { status: 200 });
    });
    const m = await lookupMailRecords('x.top');
    fetchMock.mockRestore();
    expect(m).toEqual({ domain: 'x.top', mx: [], hasAddress: true, spf: null, dmarc: null, bimi: null });
    expect(mailRecordFindings(m)[0]).toMatchObject({ severity: 'medium', title: 'Sender domain x.top is missing mail records' });
  });

  it('is quiet when all mail records exist, and loud when the domain has nothing', () => {
    expect(mailRecordFindings({ domain: 'ok.com', mx: ['10 mx.ok.com.'], hasAddress: true, spf: 'v=spf1 -all', dmarc: 'v=DMARC1; p=reject' })).toEqual([]);
    expect(mailRecordFindings({ domain: 'ghost.top', mx: [], hasAddress: false, spf: null, dmarc: null })[0]!.title).toBe('Sender domain ghost.top has no mail server and no website');
  });
});

describe('sender DNS posture', () => {
  const rec = (spf: string | null, dmarc: string | null, bimi: string | null = null) => ({ domain: 'd.com', mx: ['10 mx.d.com.'], hasAddress: true, spf, dmarc, bimi });
  const ids = (fs: { id: string }[]) => fs.map((f) => f.id);

  it('parses DMARC policies', () => {
    expect(parseDmarc('v=DMARC1; p=quarantine; sp=reject; pct=50')).toEqual({ policy: 'quarantine', subdomainPolicy: 'reject', pct: 50 });
    expect(parseDmarc(null)).toBeNull();
  });

  it('flags SPF that lets anyone send, and a domain that does not block fakes', () => {
    expect(ids(postureFindings(rec('v=spf1 +all', null), 'none'))).toEqual(['spf-open-d.com']);
    expect(ids(postureFindings(rec('v=spf1 a mx all', null), 'none'))).toEqual(['spf-open-d.com']);
    expect(ids(postureFindings(rec('v=spf1 include:_spf.google.com ?all', 'v=DMARC1; p=none'), 'fail'))).toEqual(['spf-neutral-d.com', 'dmarc-none-d.com']);
    expect(postureFindings(rec('v=spf1 include:_spf.google.com -all', 'v=DMARC1; p=none'), 'pass')).toEqual([]);
  });

  it('rewards a verified brand logo only with enforced DMARC and a pass', () => {
    const bimi = 'v=BIMI1; l=https://d.com/logo.svg; a=https://d.com/vmc.pem';
    expect(postureFindings(rec('v=spf1 -all', 'v=DMARC1; p=reject', bimi), 'pass')[0]).toMatchObject({ id: 'bimi-d.com', severity: 'good' });
    expect(postureFindings(rec('v=spf1 -all', 'v=DMARC1; p=reject', bimi), 'fail')).toEqual([]);
  });
});
