import { parseEmail } from '../src/core/parse';
import { analyzeRawEmail } from '../src/core/analyze';
import { EMPTY_HISTORY, historyFindings, normalizeName, recordSender, type SenderHistory } from '../src/analyzers/history';

const ids = (fs: { id: string }[]) => fs.map((f) => f.id);

function eml(from: string, opts: { subject?: string; body?: string; id?: string; replyTo?: string } = {}): string {
  return [
    `From: ${from}`,
    'To: me@example.org',
    `Subject: ${opts.subject ?? 'Hello'}`,
    `Message-ID: <${opts.id ?? Math.random().toString(36).slice(2)}@x>`,
    ...(opts.replyTo ? [`Reply-To: ${opts.replyTo}`] : []),
    'Content-Type: text/plain; charset=utf-8',
    '',
    opts.body ?? 'Hi there',
  ].join('\r\n');
}

/** A history that has seen `n` emails from each sender. */
async function historyOf(senders: [string, number][]): Promise<SenderHistory> {
  let h = EMPTY_HISTORY;
  for (const [from, n] of senders) for (let i = 0; i < n; i++) h = recordSender(h, await parseEmail(eml(from)), 1_700_000_000_000);
  return h;
}

const filler: [string, number][] = Array.from({ length: 12 }, (_, i) => [`Friend ${i} <friend${i}@company${i}.com>`, 1]);

describe('sender history', () => {
  it('records each email once, even when reopened', async () => {
    const e = await parseEmail(eml('Ann <ann@acme.com>', { id: 'same' }));
    const h = recordSender(recordSender(EMPTY_HISTORY, e), e);
    expect(h.senders['ann@acme.com']).toMatchObject({ count: 1, domain: 'acme.com', name: 'Ann' });
  });

  it('only notes that it is learning while the history is small', async () => {
    const f = historyFindings(await parseEmail(eml('X <x@new.com>')), EMPTY_HISTORY);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ id: 'first-contact', severity: 'info', points: 0 });
  });

  it('warns about a first email from an unknown domain', async () => {
    const f = historyFindings(await parseEmail(eml('X <x@never-seen.xyz>')), await historyOf(filler));
    expect(f.find((x) => x.id === 'first-contact')).toMatchObject({ severity: 'low', title: "You've never received mail from never-seen.xyz" });
  });

  it('says where the brand usually emails from', async () => {
    const h = await historyOf([...filler, ['PayPal <service@paypal.com>', 4]]);
    const f = historyFindings(await parseEmail(eml('PayPal <security@paypa1-support.xyz>')), h);
    expect(ids(f)).toEqual(expect.arrayContaining(['history-brand-mismatch', 'first-contact']));
    expect(f.find((x) => x.id === 'history-brand-mismatch')!.title).toBe('Your PayPal emails usually come from paypal.com');
    expect(f.find((x) => x.id === 'first-contact')!.severity).toBe('medium');
  });

  it('spots a contact name used from another address', async () => {
    const h = await historyOf([...filler, ['Smith, John <john.smith@acme-corp.com>', 3]]);
    const f = historyFindings(await parseEmail(eml('John Smith <johnsmith.ceo@gmail.com>')), h);
    expect(f.find((x) => x.id === 'contact-impersonation')).toMatchObject({ severity: 'high', points: 30 });
  });

  it('reassures about senders seen often, without counting the open email', async () => {
    const h = await historyOf([...filler, ['Ann <ann@acme.com>', 3]]);
    const f = historyFindings(await parseEmail(eml('Ann <ann@acme.com>')), h);
    expect(f).toEqual([expect.objectContaining({ id: 'known-sender', points: -5 })]);
  });

  it('normalizes names loosely', () => {
    expect(normalizeName('Smith, John')).toBe(normalizeName('john SMITH'));
    expect(normalizeName('"John Smith" (CEO)')).toBe('ceo john smith');
  });

  it('is used by analyzeRawEmail when a history is passed', async () => {
    const h = await historyOf([...filler, ['PayPal <service@paypal.com>', 2]]);
    const r = await analyzeRawEmail(eml('PayPal <security@paypa1-support.xyz>'), { history: h });
    expect(ids(r.findings)).toContain('history-brand-mismatch');
    const none = await analyzeRawEmail(eml('PayPal <security@paypa1-support.xyz>'));
    expect(ids(none.findings)).not.toContain('first-contact');
  });
});
