/**
 * The labelled corpus: realistic phishing emails modelled on published
 * write-ups, and legitimate emails built like the real thing. Every phish
 * must be caught as the right kind of attack; every legitimate email must
 * come out clear. Add a sample by dropping an .eml into corpus/phish or
 * corpus/ham and, for a phish, naming the attack it should be read as.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeRawEmail } from '../src/core/analyze';
import { hypotheses, type AttackKind } from '../src/core/assessment';

const dir = join(__dirname, 'fixtures', 'corpus');
const load = (kind: 'phish' | 'ham') => readdirSync(join(dir, kind)).filter((f) => f.endsWith('.eml')).sort().map((f) => ({ name: f, raw: readFileSync(join(dir, kind, f)) }));

const EXPECTED: Record<string, AttackKind> = {
  'ceo-gift-cards-gmail.eml': 'payment-fraud',
  'clickfix-captcha.eml': 'malware',
  'device-code-teams.eml': 'consent',
  'dkim-replay-google-alert.eml': 'replay',
  'docusign-lookalike-prefilled.eml': 'credential-phishing',
  'entity-obfuscated-m365.eml': 'credential-phishing',
  'fake-reply-bank-change.eml': 'payment-fraud',
  'forged-google-stamp.eml': 'spoofing',
  'geek-squad-renewal-callback.eml': 'callback',
  'html-attachment-login.eml': 'credential-phishing',
  'locked-zip-password.eml': 'malware',
  'paypal-invoice-callback.eml': 'callback',
};

describe('labelled corpus', () => {
  const phish = load('phish');
  const ham = load('ham');

  it('has an expected attack for every phishing sample', () => {
    expect(phish.map((p) => p.name)).toEqual(Object.keys(EXPECTED).sort());
  });

  it.each(phish.map((p) => [p.name, p.raw] as const))('catches %s', async (name, raw) => {
    const r = await analyzeRawEmail(new Uint8Array(raw));
    const kinds = hypotheses(r).map((h) => h.kind);
    expect({ name, verdict: r.verdict, kind: kinds.includes(EXPECTED[name]!) }).toEqual({ name, verdict: 'high', kind: true });
  });

  it.each(ham.map((h) => [h.name, h.raw] as const))('leaves %s clear', async (name, raw) => {
    const r = await analyzeRawEmail(new Uint8Array(raw));
    expect({ name, verdict: r.verdict, flags: r.findings.filter((f) => f.points >= 10).map((f) => f.id) }).toEqual({ name, verdict: 'clear', flags: [] });
  });
});
