/**
 * Measures Unmask against a folder of real phishing emails (for example a
 * checkout of https://github.com/rf-peixoto/phishing_pot). Skipped unless
 * UNMASK_CORPUS_DIR is set, so ordinary test runs and CI are unaffected:
 *
 *   UNMASK_CORPUS_DIR=/path/to/email UNMASK_CORPUS_LIMIT=400 \
 *   UNMASK_CORPUS_OUT=/tmp/eval.json pnpm --filter unmask-extension exec vitest run tests/corpusEval.test.ts
 *
 * The samples are never copied into this repository. Every sample in such a
 * corpus is phishing, so "clear" results are the ones worth reading: each is
 * a signal Unmask missed.
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeRawEmail } from '../src/core/analyze';
import { hypotheses } from '../src/core/assessment';

const dir = process.env.UNMASK_CORPUS_DIR;
const limit = Number(process.env.UNMASK_CORPUS_LIMIT ?? 300);

describe.skipIf(!dir)('real-world phishing corpus', () => {
  it('reports how many are caught, and which are missed', async () => {
    const files = readdirSync(dir!).filter((f) => f.endsWith('.eml')).sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).slice(0, limit);
    const rows: { file: string; verdict: string; score: number; subject: string; from: string; top: string[]; kinds: string[]; ms: number; files: number; error?: string }[] = [];
    for (const f of files) {
      const t0 = Date.now();
      try {
        const r = await analyzeRawEmail(readFileSync(join(dir!, f)));
        rows.push({ file: f, verdict: r.verdict, score: r.score, subject: r.email.subject.slice(0, 80), from: r.email.from?.address ?? '', top: r.findings.filter((x) => x.points > 0).slice(0, 4).map((x) => x.id), kinds: hypotheses(r).map((h) => h.kind), ms: Date.now() - t0, files: r.attachments.filter((a) => a.forensics && !a.inline).length });
      } catch (e) {
        rows.push({ file: f, verdict: 'error', score: 0, subject: '', from: '', top: [], kinds: [], ms: Date.now() - t0, files: 0, error: String(e).slice(0, 200) });
      }
    }
    const by = (v: string) => rows.filter((r) => r.verdict === v).length;
    const summary = { total: rows.length, high: by('high'), suspicious: by('suspicious'), clear: by('clear'), errors: by('error'), caughtPct: Math.round(((by('high') + by('suspicious')) / rows.length) * 1000) / 10, slowestMs: Math.max(...rows.map((r) => r.ms)), withFiles: rows.filter((r) => r.files).length };
    const kinds: Record<string, number> = {};
    for (const r of rows) for (const k of r.kinds) kinds[k] = (kinds[k] ?? 0) + 1;
    const signals: Record<string, number> = {};
    for (const r of rows) for (const s of r.top) signals[s.replace(/[0-9a-f]{12}$/, '*')] = (signals[s.replace(/[0-9a-f]{12}$/, '*')] ?? 0) + 1;
    const out = { summary, kinds, topSignals: Object.entries(signals).sort((a, b) => b[1] - a[1]).slice(0, 25), missed: rows.filter((r) => r.verdict === 'clear').map(({ file, subject, from, score }) => ({ file, subject, from, score })), errors: rows.filter((r) => r.error).map(({ file, error }) => ({ file, error })) };
    if (process.env.UNMASK_CORPUS_OUT) writeFileSync(process.env.UNMASK_CORPUS_OUT, JSON.stringify(out, null, 2));
    process.stdout.write(`\nCORPUS ${JSON.stringify(out.summary)}\n`);
    expect(summary.errors).toBe(0);
  }, 900_000);
});
