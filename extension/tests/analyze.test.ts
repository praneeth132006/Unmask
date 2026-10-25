import { analyzeRawEmail, withExtraFindings } from '../src/core/analyze';
import { scoreFindings } from '../src/core/score';
import type { Finding } from '../src/core/types';
import { fixture } from './helpers';

const finding = (severity: Finding['severity'], points: number): Finding => ({ id: `${severity}-${points}`, category: 'content', severity, points, title: 't' });

describe('scoreFindings', () => {
  it('sums points and clamps to 0..100', () => {
    expect(scoreFindings([finding('medium', 10), finding('low', 5)])).toEqual({ score: 15, verdict: 'clear' });
    expect(scoreFindings([finding('medium', 60), finding('medium', 60)]).score).toBe(100);
    expect(scoreFindings([finding('good', -10)]).score).toBe(0);
  });

  it('limits how much reassuring signals can offset', () => {
    expect(scoreFindings([finding('medium', 30), finding('good', -10), finding('good', -10)]).score).toBe(15);
  });

  it('lets nothing offset a high or critical finding (passing DMARC is not "safe")', () => {
    expect(scoreFindings([finding('high', 25), finding('good', -10)])).toEqual({ score: 25, verdict: 'suspicious' });
  });

  it('forces a high verdict for any critical finding', () => {
    expect(scoreFindings([finding('critical', 35)]).verdict).toBe('high');
  });
});

describe('analyzeRawEmail', () => {
  it('rates the PayPal phishing sample as high risk', async () => {
    const r = await analyzeRawEmail(fixture('phishing-paypal.eml'));
    expect(r.verdict).toBe('high');
    expect(r.score).toBeGreaterThanOrEqual(80);
    expect(r.findings[0]?.severity).toBe('critical');
  });

  it('rates the GitHub notification as clear', async () => {
    const r = await analyzeRawEmail(fixture('legit-newsletter.eml'));
    expect(r.verdict).toBe('clear');
    expect(r.score).toBe(0);
  });

  it('keeps a normal marketing newsletter out of the suspicious band', async () => {
    const r = await analyzeRawEmail(fixture('marketing-newsletter.eml'));
    expect(r.verdict, JSON.stringify(r.findings.map((f) => [f.id, f.points]))).toBe('clear');
  });

  it('re-scores when online checks add findings', async () => {
    const r = await analyzeRawEmail(fixture('legit-newsletter.eml'));
    const updated = withExtraFindings(r, [{ id: 'vt-malicious', category: 'attachments', severity: 'critical', points: 40, title: 'x' }]);
    expect(updated.verdict).toBe('high');
    expect(updated.findings[0]?.id).toBe('vt-malicious');
  });
});
