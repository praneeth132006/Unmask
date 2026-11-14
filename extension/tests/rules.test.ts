import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { analyzeRawEmail } from '../src/core/analyze';
import { RULE_LIST } from '../src/analyzers/rules';
import { compileRule } from '../scripts/compile-rules.mjs';

/** A rule example ("Subject: …\n\nbody") as an email from an unknown sender. */
function eml(example: string): string {
  const [first, ...rest] = example.split('\n');
  const subject = first!.startsWith('Subject:') ? first!.slice(8).trim() : '';
  const body = first!.startsWith('Subject:') ? rest.join('\n').replace(/^\n/, '') : example;
  return ['From: Someone <someone@sender.example>', 'To: me@example.org', `Subject: ${subject}`, 'Content-Type: text/plain; charset=utf-8', '', body].join('\r\n');
}

describe('detection rules (rules/*.yml)', () => {
  it('src/rules/rules.json is compiled from the current YAML', () => {
    expect(() => execFileSync('node', [join(__dirname, '../scripts/compile-rules.mjs'), '--check'], { stdio: 'pipe' })).not.toThrow();
  });

  it.each(RULE_LIST.map((r) => [r.id, r] as const))('%s fires on its phishing example and not on its legitimate one', async (id, r) => {
    const phish = await analyzeRawEmail(eml(r.examples.phish));
    expect(phish.findings.map((f) => f.id)).toContain(`rule-${id}`);
    const legit = await analyzeRawEmail(eml(r.examples.legit));
    expect(legit.findings.map((f) => f.id)).not.toContain(`rule-${id}`);
  });

  it('skips mail verified from a domain the rule trusts', async () => {
    const r = RULE_LIST.find((x) => x.id === 'parcel-fee')!;
    const raw = eml(r.examples.phish).replace('From: Someone <someone@sender.example>', 'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=ups.com; dkim=pass header.d=ups.com; dmarc=pass header.from=ups.com\r\nFrom: UPS <noreply@ups.com>');
    expect((await analyzeRawEmail(raw)).findings.map((f) => f.id)).not.toContain('rule-parcel-fee');
  });

  it('rejects rules that are unclear or too broad, with the file name in the error', () => {
    const base = 'id: x-y\ntitle: A long enough title\nplain: Plain words long enough.\nseverity: medium\npoints: 10\nwhen:\n  any: ["something specific"]\nexamples:\n  phish: "a"\n  legit: "b"\n';
    expect(() => compileRule('x-y.yml', base)).not.toThrow();
    expect(() => compileRule('other.yml', base)).toThrow('other.yml: file must be named x-y.yml');
    expect(() => compileRule('x-y.yml', base.replace('points: 10', 'points: 40'))).toThrow('points for medium must be 6-15');
    expect(() => compileRule('x-y.yml', base.replace('severity: medium', 'severity: critical'))).toThrow('severity must be');
    expect(() => compileRule('x-y.yml', base.replace('"something specific"', '"/(unclosed/"'))).toThrow('bad regular expression');
    expect(() => compileRule('x-y.yml', base.replace('"something specific"', '"ab"'))).toThrow('too short');
    expect(() => compileRule('x-y.yml', base.replace('when:', 'whenn:'))).toThrow('unknown key "whenn"');
    expect(() => compileRule('x-y.yml', `${base}  extra: 1\n`)).toThrow();
  });
});
