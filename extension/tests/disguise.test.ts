import { analyzeRawEmail } from '../src/core/analyze';
import { INVISIBLE, mixedScriptWords } from '../src/analyzers/lookalike';
import { detectLookalike } from '../src/analyzers/lookalike';

const mail = (from: string, subject: string, body = 'Hello, please review.') => `From: ${from}\r\nTo: you@example.org\r\nSubject: ${subject}\r\nDate: Mon, 19 Oct 2026 16:00:00 +0000\r\nMessage-ID: <t@x>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n${body}\r\n`;
const ids = (r: { findings: { id: string }[] }) => r.findings.map((f) => f.id);

describe('names disguised with look-alike letters and invisible characters', () => {
  it('sees supplementary variation selectors but not ordinary emoji', () => {
    expect('Secu\u{e0101}\u{e0101}rity'.match(INVISIBLE)).toHaveLength(2);
    expect('Heart ❤️ OK'.match(INVISIBLE)).toBeNull();
  });

  it('finds Latin words with Cyrillic look-alikes', () => {
    expect(mixedScriptWords('Account Sесurity Sеttings')).toHaveLength(2);
  });

  it('several altered words in a subject count as deliberate, not a typo', async () => {
    const r = await analyzeRawEmail(mail('Support <help@mailer.example.net>', 'Your Account Sесurіty Sеttіngs Chаngе'));
    const f = r.findings.find((x) => x.id === 'disguised-subject')!;
    expect(f.severity).toBe('medium');
    expect(f.points).toBe(10);
  });

  it('one stray look-alike stays a low-weight note', async () => {
    const r = await analyzeRawEmail(mail('Anna <anna@mailer.example.net>', 'Cafе menu for Friday'));
    expect(r.findings.find((x) => x.id === 'disguised-subject')!.severity).toBe('low');
  });

  it('leaves ordinary emoji and accented words alone', async () => {
    const r = await analyzeRawEmail(mail('Anna <anna@mailer.example.net>', 'Café menu ❤️ for Friday — zażółć gęślą jaźń'));
    expect(ids(r)).not.toContain('disguised-subject');
  });
});

describe('crypto-wallet brands', () => {
  it('flags a look-alike of a hardware-wallet maker', () => {
    expect(detectLookalike('coldcardblog.org')?.brand.name).toBe('Coinkite / COLDCARD');
    expect(detectLookalike('trezor-support.help')?.brand.name).toBe('Trezor');
  });

  it('does not touch the real domains or ordinary words', () => {
    expect(detectLookalike('coldcard.com')).toBeNull();
    expect(detectLookalike('trezor.io')).toBeNull();
    expect(detectLookalike('accounting-ledger-tips.com')).toBeNull();
  });
});
