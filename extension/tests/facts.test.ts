/**
 * Every statement Unmask makes about trackers and the verdict must match the
 * analysis exactly. These tests pin the wording to the data.
 */
import { analyzeRawEmail } from '../src/core/analyze';
import { concernsHeading, peekPrivacyLines, trackerChipLabel, trackerFacts, verdictLabel } from '../src/core/facts';
import { plainSummary } from '../src/core/plain';

function newsletter(opts: { pixels?: number; images?: number; trackedLinks?: number; replyTo?: string; dmarc?: 'pass' | 'fail' } = {}): string {
  const imgs = [
    ...Array.from({ length: opts.pixels ?? 0 }, (_, i) => `<img src="https://open.mail.beehiiv.com/o/${i}.gif" width="1" height="1">`),
    ...Array.from({ length: opts.images ?? 0 }, (_, i) => `<img src="https://media.beehiiv.com/uploads/photo${i}.png" width="600">`),
  ].join('');
  const links = Array.from({ length: opts.trackedLinks ?? 0 }, (_, i) => `<a href="https://link.mail.beehiiv.com/v2/c/${i}">Story ${i}</a>`).join(' ');
  return [
    `Authentication-Results: mx.google.com; dkim=pass header.d=mail.beehiiv.com; spf=pass smtp.mailfrom=mail.beehiiv.com; dmarc=${opts.dmarc ?? 'pass'} header.from=mail.beehiiv.com`,
    'From: "That1AI Newsletter" <that1ai@mail.beehiiv.com>',
    ...(opts.replyTo ? [`Reply-To: ${opts.replyTo}`] : []),
    'Subject: This week in AI',
    'Content-Type: text/html; charset=utf-8',
    '',
    `<p>Hello</p>${imgs}${links}`,
  ].join('\r\n');
}

describe('tracker statements match the email exactly', () => {
  it('counts pixels, tracked links and remote images separately', async () => {
    const r = await analyzeRawEmail(newsletter({ pixels: 1, images: 3, trackedLinks: 24 }));
    expect(trackerFacts(r)).toEqual({ pixels: 1, trackedLinks: 24, remoteImages: 4 });
    expect(trackerChipLabel(r)).toBe('1 pixel · 24 tracked links');
    expect(peekPrivacyLines(r)).toEqual([
      'Contains 1 tracking pixel among 4 remote images. Peek loaded none of them, so the sender has not been told you looked.',
      '24 links are click-tracked: each reports a click only if you click it.',
      'Opening it in Gmail loads these images, which tells the sender that you opened it and when.',
    ]);
  });

  it('never says "no trackers" for an email that has tracked links', async () => {
    const r = await analyzeRawEmail(newsletter({ trackedLinks: 3 }));
    expect(trackerChipLabel(r)).toBe('3 tracked links');
    expect(peekPrivacyLines(r).join(' ').toLowerCase()).not.toContain('no trackers');
    expect(peekPrivacyLines(r)[0]).toBe('Contains no remote images or tracking pixels.');
  });

  it('distinguishes plain remote images from known trackers', async () => {
    const r = await analyzeRawEmail(newsletter({ images: 2 }));
    expect(trackerChipLabel(r)).toBe('No known trackers');
    expect(peekPrivacyLines(r)[0]).toBe('Contains 2 remote images (no known tracking pixels). Peek loaded none of them.');
  });

  it('says "No trackers" only when there is nothing that could track', async () => {
    const r = await analyzeRawEmail(newsletter());
    expect(trackerChipLabel(r)).toBe('No trackers');
    expect(peekPrivacyLines(r)).toEqual(['Contains no remote images or tracking pixels.']);
  });
});

describe('the verdict and the list never contradict each other', () => {
  it('a clean email with minor points is "Low risk", listed as "Worth knowing"', async () => {
    const r = await analyzeRawEmail(newsletter({ replyTo: 'that1aifeed@gmail.com' }));
    expect(r.verdict).toBe('clear');
    expect(verdictLabel(r)).toBe('Low risk');
    expect(concernsHeading(r, 1)).toBe('Worth knowing (1)');
    const p = plainSummary(r);
    expect(p.headline).toBe('Nothing serious found. Worth knowing:');
    expect(p.reasons).toContain('If you reply, your answer goes to that1aifeed@gmail.com, not to the address it came from.');
  });

  it('"No red flags" only when there is nothing to point out', async () => {
    const r = await analyzeRawEmail(newsletter());
    expect(verdictLabel(r)).toBe('No red flags');
    expect(plainSummary(r).headline).toBe('Nothing looks wrong with this email.');
  });

  it('webmail replies on a verified newsletter are medium, on an unverified email still high', async () => {
    const ok = await analyzeRawEmail(newsletter({ replyTo: 'a@gmail.com' }));
    expect(ok.findings.find((f) => f.id === 'reply-to-mismatch')).toMatchObject({ severity: 'medium', points: 10 });
    const spoof = await analyzeRawEmail(newsletter({ replyTo: 'a@gmail.com', dmarc: 'fail' }));
    expect(spoof.findings.find((f) => f.id === 'reply-to-mismatch')).toMatchObject({ severity: 'high' });
  });

  it('a company’s Typeform survey is a low note, not a red link warning', async () => {
    const raw = newsletter().replace('<p>Hello</p>', '<p>Hello</p><a href="https://trygrow.typeform.com/to/abc">Take our survey</a>');
    const r = await analyzeRawEmail(raw);
    expect(r.links.find((l) => l.host === 'trygrow.typeform.com')?.flags).toEqual([expect.objectContaining({ id: 'abused-host', severity: 'low' })]);
    expect(r.verdict).toBe('clear');
  });
});
