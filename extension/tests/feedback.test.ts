import { analyzeRawEmail } from '../src/core/analyze';
import { feedbackText, feedbackUrl, likelyMistake } from '../src/lib/feedback';

const raw = ['From: "PayPal" <service@paypa1-support.xyz>', 'To: alex.morgan@example.org', 'Subject: Your account is limited', 'Content-Type: text/html', '', '<p>Dear alex.morgan@example.org, verify now:</p><a href="https://paypa1-secure.top/login?u=alex">https://www.paypal.com/signin</a>'].join('\r\n');

describe('Was this right?', () => {
  it('shares only the verdict, the check ids and the version by default', async () => {
    const r = await analyzeRawEmail(raw);
    const t = feedbackText(r, { mistake: likelyMistake(r), includeDomain: false, version: '0.6.0' });
    expect(t.title).toMatch(/^False alarm: High risk \(\d+\)$/);
    expect(t.why).toContain('Checks that fired:');
    expect(t.why).toContain('Sender’s domain: not shared');
    expect(t.why).toContain('Unmask version: 0.6.0');
    // Nothing personal: no addresses, links, names or finding titles.
    const all = `${t.title}\n${t.why}`;
    for (const secret of ['alex.morgan', 'example.org', 'paypa1-secure.top', 'paypa1-support.xyz', 'Dear', 'PayPal']) expect(all).not.toContain(secret);
  });

  it('adds the sender’s domain only when asked, and fills in the issue form', async () => {
    const r = await analyzeRawEmail(raw);
    const u = new URL(feedbackUrl(r, { mistake: 'missed', includeDomain: true, version: '0.6.0' }));
    expect(u.origin + u.pathname).toBe('https://github.com/praneeth132006/Unmask/issues/new');
    expect(u.searchParams.get('template')).toBe('detection.yml');
    expect(u.searchParams.get('kind')).toBe('Missed phishing (scored too low)');
    expect(u.searchParams.get('title')).toContain('from paypa1-support.xyz');
    expect(u.searchParams.get('why')).not.toContain('alex.morgan');
  });
});
