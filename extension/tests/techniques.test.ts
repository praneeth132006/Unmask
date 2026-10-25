import { analyzeRawEmail } from '../src/core/analyze';
import { callbackSigns, phoneNumbers } from '../src/analyzers/techniques';

const ids = async (raw: string) => (await analyzeRawEmail(raw)).findings.map((f) => f.id);
const mail = (headers: string[], body: string) => `${headers.join('\n')}\n\n${body}`;

describe('callback (TOAD) scams', () => {
  const geekSquad = 'Thank you for renewing your Geek Squad protection. Your account has been charged $399.99 for the annual subscription. If you did not authorize this transaction, call our billing department at +1 (808) 555-0142 to cancel and get a refund.';

  it('finds phone numbers, not order numbers or dates', () => {
    expect(phoneNumbers('Call 1-800-555-0199 or +44 20 7946 0958. Order 2026-10-19 #12345678.')).toEqual(['1-800-555-0199', '+44 20 7946 0958']);
  });

  it('recognises the shape of a callback scam', () => {
    expect(callbackSigns(geekSquad)).toEqual({ phones: ['+1 (808) 555-0142'], amount: '$399.99' });
    expect(callbackSigns('Questions about your order? Call us at 1-800-555-0199.')).toBeNull();
  });

  it('flags it high from an unverified sender, as a note from a verified brand', async () => {
    const scam = await analyzeRawEmail(mail(['From: Billing <invoices@quick-billing-desk.com>', 'Subject: Invoice INV-4421'], geekSquad));
    expect(scam.findings.find((f) => f.id === 'callback-phishing')?.severity).toBe('high');
    const amazon = await analyzeRawEmail(mail(['Authentication-Results: mx.google.com; dmarc=pass header.from=amazon.com', 'From: Amazon <auto-confirm@amazon.com>', 'Subject: Your order'], geekSquad));
    expect(amazon.findings.find((f) => f.id === 'callback-phishing')?.severity).toBe('low');
  });
});

describe('abused notification platforms', () => {
  const paypalInvoice = (body: string) =>
    mail(['Authentication-Results: mx.google.com; dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com', 'From: "service@paypal.com" <service@paypal.com>', 'Subject: You have a new invoice'], body);

  it('flags a genuine PayPal invoice whose note is a callback scam', async () => {
    const r = await analyzeRawEmail(paypalInvoice('Seller note: Your PayPal account was charged $499.00 for Bitcoin purchase. If you did not authorize this, call PayPal support at +1 (888) 555-0187 to cancel and get a refund.'));
    const f = r.findings.find((x) => x.id === 'platform-abuse');
    expect(f?.severity).toBe('high');
    expect(f?.title).toBe("A real PayPal email carrying a scammer's message");
    expect(f?.detail).toMatch(/\+1 \(888\) 555-0187/);
    expect(r.findings.map((x) => x.id)).not.toContain('callback-phishing');
  });

  it('leaves an ordinary PayPal invoice alone', async () => {
    expect(await ids(paypalInvoice('Acme Ltd sent you an invoice for $25.00. View and pay it at https://www.paypal.com/invoice/p/#ABC'))).not.toContain('platform-abuse');
  });
});
