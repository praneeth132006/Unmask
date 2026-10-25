import { analyzeRawEmail } from '../src/core/analyze';
import { readArcChain } from '../src/analyzers/arc';
import { splitRawMessage } from '../src/lib/rawMessage';
import { makeKey, message, seal, sign } from './signing';

const key = makeKey();
const base = message(['From: News <news@example.com>', 'To: list@lists.example.org', 'Subject: Weekly', 'Date: Mon, 19 Oct 2026 16:00:00 +0000'], 'Hello\r\n');

describe('ARC', () => {
  it('reads a real two-step chain', async () => {
    let m = await sign(base, { key });
    m = await seal(m, { domain: 'lists.example.org', key, authResults: 'mx.lists.example.org; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com', instance: 1 });
    m = await seal(m, { domain: 'forward.example.net', key, authResults: 'mx.forward.example.net; dkim=fail header.d=example.com; arc=pass', instance: 2 });
    const { sets, problem } = readArcChain(splitRawMessage(m));
    expect(problem).toBeNull();
    expect(sets.map((s) => [s.instance, s.cv, s.domain])).toEqual([[1, 'none', 'lists.example.org'], [2, 'pass', 'forward.example.net']]);
    expect(sets[0]!.results).toMatchObject({ dkim: 'pass', dmarc: 'pass' });
  });

  it('explains a DMARC failure that passed before forwarding, and flags a broken chain', async () => {
    let m = await seal(await sign(base, { key }), { domain: 'lists.example.org', key, authResults: 'mx.lists.example.org; dkim=pass header.d=example.com; dmarc=pass header.from=example.com', instance: 1 });
    m = m.replace(/cv=none/, 'cv=fail');
    m = `Authentication-Results: mx.google.com; dkim=fail header.d=example.com; dmarc=fail header.from=example.com\r\n${m}`;
    const r = await analyzeRawEmail(m);
    expect(r.forensics.arcProblem).toMatch(/cv=fail/);
    expect(r.findings.map((f) => f.id)).toEqual(expect.arrayContaining(['arc-broken', 'arc-passed-earlier']));
  });
});
