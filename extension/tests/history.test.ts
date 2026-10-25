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

describe('sender fingerprints', () => {
  const vendor = (opts: { dkim?: string; route?: string; mailer?: string; replyTo?: string; id: number }) =>
    [
      `Received: from ${opts.route ?? 'o1.mail.vendor.com'} (${opts.route ?? 'o1.mail.vendor.com'} [198.51.100.7]) by mx.google.com; Mon, 19 Oct 2026 16:00:00 +0000`,
      `Authentication-Results: mx.google.com; ${opts.dkim === 'none' ? 'dkim=none' : `dkim=pass header.d=${opts.dkim ?? 'vendor.com'}`}; spf=pass smtp.mailfrom=vendor.com; dmarc=${opts.dkim === 'none' ? 'fail' : 'pass'} header.from=vendor.com`,
      'From: Accounts <accounts@vendor.com>',
      ...(opts.replyTo ? [`Reply-To: ${opts.replyTo}`] : []),
      `X-Mailer: ${opts.mailer ?? 'Microsoft Outlook 16.0'}`,
      `Message-ID: <${opts.id}@vendor.com>`,
      'Subject: Invoice',
      '',
      'Please find this month’s invoice.',
    ].join('\n');

  async function learned(n: number) {
    const { senderTraits } = await import('../src/analyzers/fingerprint');
    const { analyzeAuth } = await import('../src/analyzers/auth');
    const { deliveryPath } = await import('../src/analyzers/received');
    const { getHeaders } = await import('../src/core/parse');
    let h: SenderHistory = EMPTY_HISTORY;
    for (let i = 0; i < n; i++) {
      const e = await parseEmail(vendor({ id: i }));
      const hops = deliveryPath(getHeaders(e, 'received'));
      h = recordSender(h, e, 1_700_000_000_000, senderTraits(e, analyzeAuth(e, hops).auth, hops));
    }
    return h;
  }

  const findingsFor = async (raw: string, h: SenderHistory) => (await analyzeRawEmail(raw, { history: h })).findings.filter((f) => f.id === 'fingerprint-changed');

  it('is quiet while the sender behaves as usual', async () => {
    expect(await findingsFor(vendor({ id: 99 }), await learned(4))).toEqual([]);
  });

  it('flags a new Reply-To on a known sender (classic vendor fraud)', async () => {
    const [f] = await findingsFor(vendor({ id: 99, replyTo: 'accounts@vendor-billing.com' }), await learned(4));
    expect(f).toMatchObject({ severity: 'medium', points: 15, title: 'First time accounts@vendor.com asks for replies to go somewhere else' });
  });

  it('flags a lost signature and a different route', async () => {
    const [f] = await findingsFor(vendor({ id: 99, dkim: 'none', route: 'vps-22.hosting.example' }), await learned(4));
    expect(f?.title).toBe("accounts@vendor.com always signs their emails; this one isn't signed");
    expect(f?.detail).toMatch(/sent through hosting\.example \(usually sent through vendor\.com\)/);
  });

  it('needs a few earlier emails first', async () => {
    expect(await findingsFor(vendor({ id: 99, replyTo: 'x@other.com' }), await learned(2))).toEqual([]);
  });
});
