import { parseEmail } from '../src/core/parse';
import { analyzeBec } from '../src/analyzers/bec';
import { analyzeContent } from '../src/analyzers/content';

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

describe('business email compromise', () => {
  const bec = async (raw: string) => {
    const email = await parseEmail(raw);
    return analyzeBec(email, analyzeContent(email).visibleText);
  };

  it('flags changed bank details', async () => {
    const f = await bec(eml('Vendor <ap@supplier.com>', { body: 'Please note our bank details have changed. Use the new account for all future invoices.' }));
    expect(ids(f)).toContain('bec-bank-change');
  });

  it('flags gift-card requests with a secrecy opener as fraud', async () => {
    const f = await bec(eml('The CEO <ceo.office@gmail.com>', { body: 'Are you available? I need a quick favor. Buy 5 Apple gift cards and send me the codes. Keep this confidential.' }));
    expect(ids(f)).toEqual(expect.arrayContaining(['bec-gift-card', 'bec-pretext', 'bec-pattern']));
  });

  it('flags a payment request whose replies go elsewhere', async () => {
    const f = await bec(eml('Finance <cfo@acme.com>', { body: 'Please process a wire transfer today. Beneficiary account details attached.', replyTo: 'cfo@acme-payments.co' }));
    expect(ids(f)).toEqual(expect.arrayContaining(['bec-payment', 'bec-pattern']));
  });

  it('stays quiet on an ordinary email', async () => {
    expect(await bec(eml('Ann <ann@acme.com>', { body: 'Lunch on Friday? The new menu looks good.' }))).toEqual([]);
  });
});
