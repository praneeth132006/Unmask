import { analyzeRawEmail } from '../src/core/analyze';
import { disguisedHrefs, encodedWords } from '../src/analyzers/obfuscation';

const html = (body: string, from = 'a@b.top') => `From: ${from}\nSubject: Notice\nContent-Type: text/html; charset=utf-8\n\n${body}`;
const find = async (body: string, id: string) => (await analyzeRawEmail(html(body))).findings.find((f) => f.id === id);

describe('HTML entity and encoding tricks', () => {
  it('decodes words spelt in character codes', () => {
    expect(encodedWords('<p>Your &#80;&#97;&#121;&#80;&#97;&#108; account &#x6C;ocked</p>')).toEqual(['PayPal']);
    expect(encodedWords('<p>It&#39;s &#8220;fine&#8221; &nbsp; &#169; 2026</p>')).toEqual([]);
  });

  it('flags a brand hidden in character codes', async () => {
    const f = await find('<p>Your &#80;&#97;&#121;&#80;&#97;&#108; account is limited.</p>', 'entity-encoded-text');
    expect(f).toMatchObject({ severity: 'high', title: '"PayPal" is written in character codes to hide it from filters' });
  });

  it('finds link addresses written in codes or with %-encoded host letters', () => {
    expect(disguisedHrefs('<a href="https://&#101;&#118;&#105;&#108;&#46;top/x">x</a>')).toEqual(['https://evil.top/x']);
    expect(disguisedHrefs('<a href="https://%70aypa1.top/login">x</a>')).toEqual(['https://paypa1.top/login']);
    expect(disguisedHrefs('<a href="https://example.com/search?q=a%20b&amp;x=1">x</a>')).toEqual([]);
  });

  it('flags words split by soft hyphens or zero-width spaces', async () => {
    const f = await find('<p>Your Pay&shy;Pal pass&#8203;word ex&#8203;pired, veri&shy;fy now</p>', 'invisible-splitters');
    expect(f).toMatchObject({ severity: 'high', title: '"PayPal" is broken up with invisible characters' });
  });

  it('flags brand names spelt with another alphabet in the text', async () => {
    const f = await find('<p>Your Micrоsoft 365 password expires today.</p>', 'mixed-script-text');
    expect(f?.severity).toBe('high');
  });

  it('is quiet on normal punctuation entities and accented words', async () => {
    const r = await analyzeRawEmail(html('<p>Caf&eacute; Zo&euml; &mdash; it&#39;s &#8220;great&#8221;. Soft&shy;ware updates.</p>', 'news@example.com'));
    expect(r.findings.filter((f) => ['entity-encoded-text', 'link-encoded-href', 'invisible-splitters', 'mixed-script-text'].includes(f.id))).toEqual([]);
  });
});
