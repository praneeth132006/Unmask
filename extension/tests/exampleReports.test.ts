/**
 * Builds the example reports shown on the website from real phishing emails.
 * Skipped unless UNMASK_EXAMPLES is set:
 *
 *   UNMASK_EXAMPLES="slug=/path/to/sample.eml,slug2=/path/to/other.eml" UNMASK_EXAMPLES_OUT=../site/examples \
 *   pnpm --filter unmask-extension exec vitest run tests/exampleReports.test.ts
 *
 * Only the analysis is published, with indicators defanged; the original
 * email is never copied into this repository.
 */
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeRawEmail } from '../src/core/analyze';
import { buildCaseReport, renderHtml, renderPdf } from '../src/report';

const spec = process.env.UNMASK_EXAMPLES;

describe.skipIf(!spec)('example reports from real phishing emails', () => {
  it('writes an HTML and a PDF report for each', async () => {
    const out = process.env.UNMASK_EXAMPLES_OUT ?? 'examples';
    mkdirSync(out, { recursive: true });
    for (const item of spec!.split(',')) {
      const [slug, path] = item.split('=') as [string, string];
      const raw = readFileSync(path);
      const report = await analyzeRawEmail(raw);
      const doc = buildCaseReport(report, {
        version: process.env.UNMASK_VERSION ?? 'dev',
        now: new Date(process.env.UNMASK_EXAMPLES_DATE ?? Date.now()),
        meta: { preparedBy: 'Unmask (example report)', organisation: 'Built from a public phishing sample', tlp: 'CLEAR', notes: 'Example report built from a real phishing email in the public phishing_pot research collection (github.com/rf-peixoto/phishing_pot). The original email is not redistributed; indicators are defanged.' },
        evidence: { emlSha256: createHash('sha256').update(raw).digest('hex'), emlSize: raw.length },
      });
      writeFileSync(join(out, `${slug}.html`), renderHtml(doc));
      writeFileSync(join(out, `${slug}.pdf`), renderPdf(doc));
      process.stdout.write(`${slug}: ${report.verdict} ${report.score}\n`);
    }
  }, 120_000);
});
