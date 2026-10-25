import { analyzeRawEmail } from '../src/core/analyze';
import { hypotheses, limitations } from '../src/core/assessment';
import { fixture } from './helpers';

describe('assessment', () => {
  it('reads the PayPal sample as impersonation, spoofing and password phishing', async () => {
    const r = await analyzeRawEmail(fixture('phishing-paypal.eml'));
    const kinds = hypotheses(r);
    expect(kinds.map((h) => h.kind)).toEqual(expect.arrayContaining(['impersonation', 'credential-phishing', 'spoofing']));
    expect(kinds[0]!.confidence).toBe('high');
  });

  it('has no attack type for a clean notification', async () => {
    expect(hypotheses(await analyzeRawEmail(fixture('legit-newsletter.eml')))).toEqual([]);
  });

  it('says what it could not check', async () => {
    const pasted = await analyzeRawEmail('From: a@b.com\nSubject: x\n\nSee https://example.com/x');
    const limits = limitations(pasted);
    expect(limits[0]).toMatch(/No authentication results/);
    expect(limits.some((l) => /checked by address only/.test(l))).toBe(true);
  });
});
