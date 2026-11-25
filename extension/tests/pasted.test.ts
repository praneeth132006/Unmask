import { describe, expect, it } from 'vitest';
import { analyzePasted, looksLikeEmail, pastedKind, pastedToRaw } from '../src/core/pasted';
import { scoreBreakdown } from '../src/core/breakdown';
import { analyzeRawEmail } from '../src/core/analyze';
import { EXAMPLE_EMAIL } from '../src/demo/example';

describe('paste anything', () => {
  it('tells emails, messages and links apart', () => {
    expect(looksLikeEmail(EXAMPLE_EMAIL)).toBe(true);
    expect(pastedKind(EXAMPLE_EMAIL)).toBe('email');
    expect(pastedKind('paypa1-secure.top/login')).toBe('link');
    expect(pastedKind('Your parcel is held. Pay the fee: https://evri-redelivery.top/pay')).toBe('message');
    expect(pastedKind('Subject: hi\nnot really headers')).toBe('message');
  });

  it('wraps a message as a plain email and gives a bare link a scheme', () => {
    expect(pastedToRaw('paypa1-secure.top')).toContain('\n\nhttps://paypa1-secure.top');
    expect(pastedToRaw(EXAMPLE_EMAIL)).toBe(EXAMPLE_EMAIL);
  });

  it('flags a parcel-fee text message without sender noise', async () => {
    const r = await analyzePasted('USPS: Your package is on hold due to an unpaid fee. Pay within 24 hours or it will be returned: https://usps-redelivery-fee.top/pay');
    expect(r.kind).toBe('message');
    expect(r.findings.some((f) => f.category === 'auth' || f.category === 'sender')).toBe(false);
    expect(r.verdict).not.toBe('clear');
  });

  it('keeps a friendly message clear', async () => {
    const r = await analyzePasted('Hey, are we still on for dinner on Friday at 7?');
    expect(r.verdict).toBe('clear');
  });
});

describe('score breakdown', () => {
  it('adds up to the score shown', async () => {
    const report = await analyzeRawEmail(EXAMPLE_EMAIL);
    const b = scoreBreakdown(report);
    const raised = b.raised.reduce((n, p) => n + p.points, 0);
    const lowered = Math.max(-15, b.lowered.reduce((n, p) => n + p.points, 0));
    expect(Math.min(100, Math.max(0, raised + lowered)) + b.floor).toBe(report.score);
    expect(b.raised[0]!.points).toBeGreaterThanOrEqual(b.raised.at(-1)!.points);
  });

  it('lists reassurance as ignored when something serious is found', () => {
    const b = scoreBreakdown({
      score: 60,
      findings: [
        { id: 'a', category: 'links', severity: 'critical', points: 40, title: 'Fake login' },
        { id: 'b', category: 'auth', severity: 'good', points: -10, title: 'DMARC passed' },
      ],
    });
    expect(b.ignored.map((p) => p.id)).toEqual(['b']);
    expect(b.lowered).toEqual([]);
    expect(b.floor).toBe(20);
  });
});
