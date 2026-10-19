import { parseEmail, getHeaders } from '../src/core/parse';
import { fixture } from './helpers';

describe('parseEmail', () => {
  it('extracts sender, reply-to, return-path and parts from a phishing sample', async () => {
    const email = await parseEmail(fixture('phishing-paypal.eml'));
    expect(email.from).toEqual({
      name: 'PayPal Service <service@paypal.com>',
      address: 'billing@paypa1-support.xyz',
      domain: 'paypa1-support.xyz',
    });
    expect(email.replyTo[0]?.domain).toBe('protonmail.com');
    expect(email.returnPath).toBe('bounce@mailer-77.ru');
    expect(email.subject).toMatch(/limited/);
    expect(email.html).toContain('Resolution Center');
    expect(email.text).toContain('bit.ly');
    expect(email.attachments).toHaveLength(1);
    expect(email.attachments[0]?.filename).toBe('Invoice_Statement.pdf.html');
    expect(new TextDecoder().decode(email.attachments[0]?.content)).toContain('type="password"');
  });

  it('exposes raw headers', async () => {
    const email = await parseEmail(fixture('legit-newsletter.eml'));
    expect(getHeaders(email, 'Authentication-Results')[0]).toContain('dmarc=pass');
  });

  it('handles LF-only input pasted from "Show original"', async () => {
    const email = await parseEmail(fixture('legit-newsletter.eml').replace(/\r\n/g, '\n'));
    expect(email.from?.address).toBe('noreply@github.com');
  });
});

describe('header names', () => {
  it('keeps the original capitalisation for copying', async () => {
    const email = await parseEmail(fixture('legit-newsletter.eml'));
    expect(email.headers.find((h) => h.key === 'authentication-results')?.name).toBe('Authentication-Results');
  });
});
