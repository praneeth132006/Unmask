import { analyzeRawEmail } from '../src/core/analyze';
import { plainSummary } from '../src/core/plain';
import { EMPTY_HISTORY } from '../src/analyzers/history';
import { asBrand, isTrusted, mergeProtection, sanitizeProtection, type ProtectionList } from '../src/analyzers/protection';
import { detectLookalike } from '../src/analyzers/lookalike';
import { fixture } from './helpers';

const ids = (r: { findings: { id: string }[] }) => r.findings.map((f) => f.id);

function eml(from: string, opts: { subject?: string; body?: string; auth?: string } = {}): string {
  return [
    ...(opts.auth ? [`Authentication-Results: mx.google.com; ${opts.auth}`] : []),
    `From: ${from}`,
    'To: me@example.org',
    `Subject: ${opts.subject ?? 'Hello'}`,
    'Message-ID: <x1@x>',
    'Content-Type: text/html; charset=utf-8',
    '',
    opts.body ?? '<p>Hi</p>',
  ].join('\r\n');
}

const LIST: ProtectionList = sanitizeProtection({
  label: 'Sharma family',
  brands: [{ name: 'Canara Bank', domains: ['canarabank.com'] }],
  contacts: [{ name: 'Rahul Sharma', addresses: ['rahul@acme-corp.com'] }],
  trusted: ['acme-corp.com', 'mom@gmail.com'],
});

describe('protection list', () => {
  it('cleans imported files and drops junk', () => {
    const l = sanitizeProtection({ brands: [{ name: 'X', domains: ['https://www.x.com/login', 'not a domain'] }, { name: '', domains: ['y.com'] }], contacts: [{ name: 'A B', addresses: ['bad'] }], trusted: ['ok.com', 'nope', 5] });
    expect(l).toEqual({ version: 1, brands: [{ name: 'X', domains: ['x.com'] }], contacts: [], trusted: ['ok.com'] });
  });

  it('merges lists without losing anything', () => {
    const merged = mergeProtection(LIST, sanitizeProtection({ brands: [{ name: 'canara bank', domains: ['canarabank.in'] }], trusted: ['dad@gmail.com'] }));
    expect(merged.brands).toEqual([{ name: 'Canara Bank', domains: ['canarabank.com', 'canarabank.in'] }]);
    expect(merged.trusted).toEqual(['acme-corp.com', 'mom@gmail.com', 'dad@gmail.com']);
  });

  it('flags someone using a protected person’s name from another address', async () => {
    const r = await analyzeRawEmail(eml('"Rahul Sharma (CEO)" <rahul.ceo.office@gmail.com>', { body: '<p>Are you free? Need a quick favour.</p>' }), { protection: LIST });
    expect(ids(r)).toContain('protected-contact');
    expect(r.verdict).toBe('high');
    expect(plainSummary(r).reasons[0]).toBe('It pretends to be Rahul Sharma, but it isn’t from Rahul Sharma’s real address.');
  });

  it('flags a protected bank named in the sender, and look-alike domains and links', async () => {
    const r = await analyzeRawEmail(eml('Canara Bank Alerts <alerts@secure-notify.top>', { body: '<a href="https://canarabank-kyc.top/update">Update KYC</a>' }), { protection: LIST });
    expect(ids(r)).toEqual(expect.arrayContaining(['protected-brand', 'protected-link-lookalike']));
    const look = await analyzeRawEmail(eml('Support <help@canarabnak.com>'), { protection: LIST });
    expect(ids(look)).toContain('protected-lookalike');
    expect(detectLookalike('canarabank-kyc.top', [asBrand(LIST.brands[0]!)])?.brand.name).toBe('Canara Bank');
  });

  it('leaves the real bank and the real person alone', async () => {
    const bank = await analyzeRawEmail(eml('Canara Bank <alerts@canarabank.com>'), { protection: LIST });
    const rahul = await analyzeRawEmail(eml('Rahul Sharma <rahul@acme-corp.com>'), { protection: LIST });
    expect(ids(bank).filter((i) => i.startsWith('protected'))).toEqual([]);
    expect(ids(rahul).filter((i) => i.startsWith('protected'))).toEqual([]);
  });

  it('trusts verified senders, and catches fakes of a trusted address', async () => {
    expect(isTrusted(LIST, 'anyone@acme-corp.com')).toBe(true);
    expect(isTrusted(LIST, 'mom@gmail.com')).toBe(true);
    expect(isTrusted(LIST, 'stranger@gmail.com')).toBe(false);
    const ok = await analyzeRawEmail(eml('Mom <mom@gmail.com>', { auth: 'dkim=pass header.d=gmail.com; spf=pass smtp.mailfrom=gmail.com; dmarc=pass header.from=gmail.com' }), { protection: LIST, history: EMPTY_HISTORY });
    expect(ids(ok)).toContain('trusted-sender');
    expect(plainSummary(ok).headline).toBe('This email is from a sender on your trusted list.');
    const fake = await analyzeRawEmail(eml('Mom <mom@gmail.com>', { auth: 'dkim=none; spf=fail smtp.mailfrom=evil.top; dmarc=fail header.from=gmail.com' }), { protection: LIST });
    expect(ids(fake)).toContain('trusted-spoof');
  });
});

describe('plain-language summary', () => {
  it('explains a phishing email in everyday words', async () => {
    const p = plainSummary(await analyzeRawEmail(fixture('phishing-paypal.eml')));
    expect(p.headline).toBe('This email looks like a scam.');
    expect(p.reasons).toContain('It pretends to be PayPal, but PayPal didn’t send it.');
    expect(p.reasons.length).toBeLessThanOrEqual(3);
    expect(p.action).toMatch(/Don’t click/);
  });

  it('stays calm about an ordinary email', async () => {
    const p = plainSummary(await analyzeRawEmail(fixture('legit-newsletter.eml')));
    expect(p.headline).toBe('Nothing looks wrong with this email.');
  });

  it('keeps a short text preview without rendering anything', async () => {
    const r = await analyzeRawEmail(eml('A <a@b.com>', { body: '<p>Hello <b>there</b></p><img src="https://track.example/p.gif">' }));
    expect(r.previewText).toContain('Hello there');
  });
});

describe('plain summary wording', () => {
  it('says each problem once', async () => {
    const list = sanitizeProtection({ brands: [{ name: 'PayPal', domains: ['paypal.com'] }] });
    const r = await analyzeRawEmail(fixture('phishing-paypal.eml'), { protection: list });
    const p = plainSummary(r);
    const fakeSite = p.reasons.filter((x) => /fake (copy|website)/.test(x));
    expect(fakeSite).toHaveLength(1);
  });
});
