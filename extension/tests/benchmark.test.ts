/**
 * The public benchmark: how much real phishing Unmask catches, and how often
 * it raises a false alarm on real legitimate email. Skipped unless the
 * corpora were downloaded (node scripts/benchmark/fetch.mjs), so ordinary
 * test runs are unaffected. CI runs it on every push to main.
 *
 *   UNMASK_BENCH_DIR=.cache/benchmark UNMASK_BENCH_OUT=.cache/benchmark/result \
 *     pnpm --filter unmask-extension exec vitest run tests/benchmark.test.ts
 *
 * A false alarm is a legitimate email rated Suspicious or High risk.
 * UNMASK_BENCH_MAX_FALSE_ALARM_PCT and UNMASK_BENCH_MIN_CAUGHT_PCT turn the
 * numbers into a pass/fail gate.
 */
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { analyzeRawEmail } from '../src/core/analyze';

const dir = process.env.UNMASK_BENCH_DIR ? resolve(__dirname, '..', '..', process.env.UNMASK_BENCH_DIR) : '';
const enabled = !!dir && existsSync(join(dir, 'phish')) && existsSync(join(dir, 'ham'));

interface Row { file: string; verdict: string; score: number; ms: number; top: string[]; checks: string[]; subject: string }

async function run(sub: 'phish' | 'ham'): Promise<Row[]> {
  const files = readdirSync(join(dir, sub)).filter((f) => f.endsWith('.eml')).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  const rows: Row[] = [];
  for (const f of files) {
    const t0 = performance.now();
    try {
      const r = await analyzeRawEmail(readFileSync(join(dir, sub, f)));
      rows.push({ file: f, verdict: r.verdict, score: r.score, ms: performance.now() - t0, top: r.findings.filter((x) => x.points > 0).slice(0, 4).map((x) => checkId(x.id)), checks: [...new Set(r.findings.filter((x) => x.points > 0).map((x) => checkId(x.id)))], subject: r.email.subject.slice(0, 90) });
    } catch (e) {
      rows.push({ file: f, verdict: 'error', score: 0, ms: performance.now() - t0, top: [String(e).slice(0, 120)], checks: [], subject: '' });
    }
  }
  return rows;
}

/** Finding ids carry a per-item suffix (link-3, vt-<hash>); the check is the part before it. */
const checkId = (id: string) => id.replace(/[0-9a-f]{12}$/, '*').replace(/[-:]\d+$/, '');

export interface CheckPrecision { id: string; phish: number; ham: number; phishPct: number; hamPct: number; precision: number }

/**
 * How well each check separates phishing from real mail. Precision is
 * weighted for the corpora's different sizes: the chance a firing is on
 * phishing if the two kinds of mail were equally common.
 */
function perCheck(phish: Row[], ham: Row[]): CheckPrecision[] {
  const count = (rows: Row[]) => { const n: Record<string, number> = {}; for (const r of rows) for (const c of r.checks) n[c] = (n[c] ?? 0) + 1; return n; };
  const p = count(phish), h = count(ham);
  return [...new Set([...Object.keys(p), ...Object.keys(h)])].map((id) => {
    const phishRate = (p[id] ?? 0) / Math.max(1, phish.length), hamRate = (h[id] ?? 0) / Math.max(1, ham.length);
    return { id, phish: p[id] ?? 0, ham: h[id] ?? 0, phishPct: pct(p[id] ?? 0, phish.length), hamPct: pct(h[id] ?? 0, ham.length), precision: phishRate + hamRate ? Math.round((phishRate / (phishRate + hamRate)) * 1000) / 10 : 0 };
  }).filter((c) => c.phish + c.ham >= 3).sort((a, b) => b.ham - a.ham || b.phish - a.phish);
}

const pct = (n: number, d: number) => (d ? Math.round((n / d) * 1000) / 10 : 0);
const flagged = (r: Row) => r.verdict === 'high' || r.verdict === 'suspicious';
function signals(rows: Row[]): [string, number][] {
  const n: Record<string, number> = {};
  for (const r of rows) for (const s of r.top) n[s] = (n[s] ?? 0) + 1;
  return Object.entries(n).sort((a, b) => b[1] - a[1]).slice(0, 12);
}

describe.skipIf(!enabled)('public benchmark', () => {
  it('measures detection and false alarms', async () => {
    const phish = await run('phish');
    const ham = await run('ham');
    const all = [...phish, ...ham].map((r) => r.ms).sort((a, b) => a - b);
    const falseAlarms = ham.filter(flagged);
    const summary = {
      phish: { total: phish.length, caught: phish.filter(flagged).length, high: phish.filter((r) => r.verdict === 'high').length, caughtPct: pct(phish.filter(flagged).length, phish.length) },
      ham: { total: ham.length, falseAlarms: falseAlarms.length, highRisk: ham.filter((r) => r.verdict === 'high').length, falseAlarmPct: pct(falseAlarms.length, ham.length) },
      errors: [...phish, ...ham].filter((r) => r.verdict === 'error').length,
      medianMs: Math.round(all[Math.floor(all.length / 2)]! * 10) / 10,
      slowestMs: Math.round(all[all.length - 1]!),
      source: existsSync(join(dir, 'phish-source.txt')) ? readFileSync(join(dir, 'phish-source.txt'), 'utf8').trim() : '',
    };
    const checks = perCheck(phish, ham);
    const result = { summary, checks, phishSignals: signals(phish.filter(flagged)), falseAlarmSignals: signals(falseAlarms), falseAlarms: falseAlarms.map(({ file, verdict, score, top, subject }) => ({ file, verdict, score, top, subject })), missed: phish.filter((r) => r.verdict === 'clear').map(({ file, score, subject }) => ({ file, score, subject })) };
    const md = [
      '| | Emails | Result |',
      '|---|---|---|',
      `| Real phishing ([phishing_pot](https://github.com/rf-peixoto/phishing_pot)) | ${summary.phish.total} | **${summary.phish.caughtPct}% caught** (${summary.phish.caught}), ${summary.phish.high} rated High risk |`,
      `| Real legitimate email ([SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/)) | ${summary.ham.total} | **${summary.ham.falseAlarmPct}% false alarms** (${summary.ham.falseAlarms} rated Suspicious or High risk, ${summary.ham.highRisk} High risk) |`,
      `| Speed | ${summary.phish.total + summary.ham.total} | median ${summary.medianMs} ms per email, slowest ${summary.slowestMs} ms, ${summary.errors} errors |`,
    ].join('\n');
    const checksMd = ['| Check | Fires on phishing | Fires on real mail | Precision |', '|---|---|---|---|', ...checks.map((c) => `| \`${c.id}\` | ${c.phishPct}% (${c.phish}) | ${c.hamPct}% (${c.ham}) | ${c.precision}% |`)].join('\n');
    if (process.env.UNMASK_BENCH_OUT) {
      const out = resolve(__dirname, '..', '..', process.env.UNMASK_BENCH_OUT);
      mkdirSync(out, { recursive: true });
      writeFileSync(join(out, 'benchmark.json'), JSON.stringify(result, null, 2));
      writeFileSync(join(out, 'benchmark.md'), `${md}\n`);
      writeFileSync(join(out, 'checks.md'), `${checksMd}\n`);
    }
    process.stdout.write(`\nBENCHMARK ${JSON.stringify(summary)}\n${md}\n`);
    expect(summary.errors).toBe(0);
    const maxFp = Number(process.env.UNMASK_BENCH_MAX_FALSE_ALARM_PCT ?? 100);
    const minCaught = Number(process.env.UNMASK_BENCH_MIN_CAUGHT_PCT ?? 0);
    expect(summary.ham.falseAlarmPct, `false alarms ${summary.ham.falseAlarmPct}% > ${maxFp}%`).toBeLessThanOrEqual(maxFp);
    expect(summary.phish.caughtPct, `caught ${summary.phish.caughtPct}% < ${minCaught}%`).toBeGreaterThanOrEqual(minCaught);
  }, 1_800_000);
});
