import { describe, expect, it } from 'vitest';
import { cleanDomain, evaluate, lookupPosture } from '../src/lib/domainPosture';
import { lessonFor, LESSONS } from '../src/core/lessons';

const base = { txt: [], dmarc: [], mx: ['mx.example.com'], dkimSelectors: [], mtaSts: [], bimi: [] };

describe('is your domain spoofable?', () => {
  it('grades reject + SPF as protected', () => {
    const p = evaluate('acme.com', { ...base, txt: ['v=spf1 include:_spf.google.com -all'], dmarc: ['v=DMARC1; p=reject; rua=mailto:d@acme.com'], dkimSelectors: ['google'] });
    expect(p.grade).toBe('protected');
    expect(p.checks.filter((c) => c.status === 'bad')).toEqual([]);
  });
  it('calls p=none spoofable and explains the fix', () => {
    const p = evaluate('acme.com', { ...base, txt: ['v=spf1 include:x ~all'], dmarc: ['v=DMARC1; p=none'] });
    expect(p.grade).toBe('spoofable');
    expect(p.checks.find((c) => c.id === 'dmarc')!.fix).toMatch(/quarantine/);
  });
  it('flags missing records, +all and two SPF records', () => {
    expect(evaluate('a.com', base).checks.find((c) => c.id === 'spf')!.status).toBe('bad');
    expect(evaluate('a.com', { ...base, txt: ['v=spf1 +all'] }).checks.find((c) => c.id === 'spf')!.says).toMatch(/every server/);
    expect(evaluate('a.com', { ...base, txt: ['v=spf1 -all', 'v=spf1 ~all'] }).checks[0]!.says).toMatch(/two SPF/);
  });
  it('quarantine is partial', () => {
    expect(evaluate('a.com', { ...base, txt: ['v=spf1 -all'], dmarc: ['v=DMARC1; p=quarantine'] }).grade).toBe('partial');
  });
  it('cleans what people type', () => {
    expect(cleanDomain('Bob@Acme.COM')).toBe('acme.com');
    expect(cleanDomain('https://www.acme.co.uk/login?x=1')).toBe('www.acme.co.uk');
    expect(cleanDomain('not a domain')).toBeNull();
  });
  it('reads Google DNS answers', async () => {
    const answers: Record<string, unknown> = {
      'acme.com&type=TXT': { Answer: [{ type: 16, data: '"v=spf1 -all"' }] },
      '_dmarc.acme.com&type=TXT': { Answer: [{ type: 16, data: '"v=DMARC1; p=reject"' }] },
      'acme.com&type=MX': { Answer: [{ type: 15, data: '10 mx.acme.com.' }] },
      'google._domainkey.acme.com&type=TXT': { Answer: [{ type: 16, data: '"v=DKIM1; k=rsa; p=MIIB"' }] },
    };
    const p = await lookupPosture('acme.com', async (u) => ({ ok: true, json: async () => answers[u.split('name=')[1]!] ?? {} }));
    expect(p.grade).toBe('protected');
    expect(p.checks.find((c) => c.id === 'dkim')!.found).toBe('google._domainkey');
    expect(p.checks.find((c) => c.id === 'mx')!.found).toBe('mx.acme.com');
  });
});

describe('lessons', () => {
  it('match finding ids, preferring the most specific', () => {
    expect(lessonFor('sender-lookalike')!.id).toBe('look-alike-domains');
    expect(lessonFor('landing-fake-login-abc123')!.id).toBe('fake-sign-in-pages');
    expect(lessonFor('link-text-mismatch')!.id).toBe('link-text-mismatch');
    expect(lessonFor('link-lookalike')!.id).toBe('look-alike-domains');
    expect(lessonFor('office-macros')!.id).toBe('dangerous-attachments');
    expect(lessonFor('dmarc-pass')).toBeNull();
  });
  it('have unique ids and say what to do', () => {
    expect(new Set(LESSONS.map((l) => l.id)).size).toBe(LESSONS.length);
    for (const l of LESSONS) expect(l.todo.length).toBeGreaterThan(10);
  });
});
