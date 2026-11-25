/**
 * unmask: Unmask's engine on the command line, for security teams and mail pipelines.
 *
 *   unmask check suspicious.eml            plain-language verdict
 *   unmask check *.eml --json              one JSON object per line (NDJSON)
 *   unmask check - --fail-on suspicious    read stdin; exit 1 if Suspicious or worse
 *   unmask report mail.eml -f stix -o x    write a report: html, pdf, docx or stix
 *   unmask domain example.com              is the domain spoofable?
 *
 * Everything runs locally; only `domain` makes network requests (Google Public DNS).
 */
import '../../extension/src/lib/domShim';
import { readFileSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { analyzeRawEmail } from '../../extension/src/core/analyze';
import { plainSummary } from '../../extension/src/core/plain';
import { verdictLabel } from '../../extension/src/core/facts';
import { scoreBreakdown } from '../../extension/src/core/breakdown';
import { buildReportFile, type ReportFormat } from '../../extension/src/report';
import { cleanDomain, lookupPosture } from '../../extension/src/lib/domainPosture';
import { collectIocs } from '../../extension/src/report';

const VERSION = process.env.UNMASK_VERSION ?? '0.6.0';
const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const red = c('31;1'), yellow = c('33;1'), green = c('32;1'), dim = c('2'), bold = c('1');
const RANK = { clear: 0, suspicious: 1, high: 2 } as const;

const HELP = `unmask ${VERSION}: see what a suspicious email is really hiding

Usage:
  unmask check <file.eml ...|-> [--json] [--fail-on suspicious|high] [--quiet]
  unmask report <file.eml> --format html|pdf|docx|stix [--out path]
  unmask domain <domain> [--json]
  unmask --version

Exit codes: 0 ok, 1 an email reached --fail-on, 2 usage or read error.`;

function read(file: string): string {
  return file === '-' ? readFileSync(0, 'latin1') : readFileSync(file, 'latin1');
}

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function check(args: string[]): Promise<number> {
  const files = args.filter((a, i) => !a.startsWith('--') && !['--fail-on'].includes(args[i - 1] ?? ''));
  if (!files.length) throw new UsageError('check needs at least one file, or - for stdin');
  const json = args.includes('--json');
  const quiet = args.includes('--quiet');
  const failOn = flag(args, '--fail-on') as keyof typeof RANK | undefined;
  if (failOn && !(failOn in RANK)) throw new UsageError('--fail-on takes suspicious or high');
  let worst = 0;
  for (const file of files) {
    const r = await analyzeRawEmail(read(file));
    worst = Math.max(worst, RANK[r.verdict]);
    const s = plainSummary(r);
    if (json) {
      const iocs = collectIocs(r);
      process.stdout.write(`${JSON.stringify({ file, verdict: r.verdict, score: r.score, subject: r.email.subject, from: r.email.from?.address ?? null, headline: s.headline, reasons: s.reasons, action: s.action, findings: r.findings.map(({ id, severity, points, title, detail }) => ({ id, severity, points, title, detail })), iocs })}\n`);
      continue;
    }
    const color = r.verdict === 'high' ? red : r.verdict === 'suspicious' ? yellow : green;
    console.log(`${color(`${verdictLabel(r)} · ${r.score}/100`)}  ${dim(file === '-' ? 'stdin' : basename(file))}`);
    if (quiet) continue;
    console.log(`  ${bold(r.email.subject || '(no subject)')}  ${dim(r.email.from?.address ?? '')}`);
    console.log(`  ${s.headline}`);
    for (const reason of s.reasons) console.log(`   • ${reason}`);
    const b = scoreBreakdown(r);
    if (b.raised.length) console.log(dim(`  ${b.raised.slice(0, 6).map((p) => `+${p.points} ${p.title}`).join('\n  ')}`));
    console.log(`  ${s.action}\n`);
  }
  return failOn && worst >= RANK[failOn] ? 1 : 0;
}

async function report(args: string[]): Promise<number> {
  const file = args.find((a, i) => !a.startsWith('-') && !['--format', '-f', '--out', '-o'].includes(args[i - 1] ?? ''));
  const format = (flag(args, '--format') ?? flag(args, '-f') ?? 'html') as ReportFormat;
  if (!file) throw new UsageError('report needs a file');
  if (!['html', 'pdf', 'docx', 'stix'].includes(format)) throw new UsageError('--format takes html, pdf, docx or stix');
  const r = await analyzeRawEmail(read(file));
  const out = await buildReportFile(r, format, { version: VERSION } as never);
  const data = typeof out.data === 'string' ? out.data : out.data instanceof Uint8Array ? out.data : new Uint8Array(await new Blob([out.data]).arrayBuffer());
  const path = flag(args, '--out') ?? flag(args, '-o') ?? `${basename(file).replace(/\.[^.]+$/, '')}.${out.ext}`;
  writeFileSync(path, data);
  console.error(`wrote ${path}`);
  return 0;
}

async function domain(args: string[]): Promise<number> {
  const d = cleanDomain(args.find((a) => !a.startsWith('--')) ?? '');
  if (!d) throw new UsageError('domain needs a domain, e.g. example.com');
  const p = await lookupPosture(d);
  if (args.includes('--json')) { console.log(JSON.stringify(p)); return 0; }
  const color = p.grade === 'protected' ? green : p.grade === 'partial' ? yellow : red;
  console.log(color(p.headline));
  for (const ch of p.checks) {
    const mark = ch.status === 'good' ? green('✓') : ch.status === 'bad' ? red('✕') : ch.status === 'warn' ? yellow('!') : dim('i');
    console.log(` ${mark} ${bold(ch.label)}  ${ch.says}`);
    if (ch.fix) console.log(dim(`     Fix: ${ch.fix}`));
  }
  return 0;
}

class UsageError extends Error {}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') { console.log(HELP); return cmd ? 0 : 2; }
  if (cmd === '-v' || cmd === '--version') { console.log(VERSION); return 0; }
  if (cmd === 'check') return check(rest);
  if (cmd === 'report') return report(rest);
  if (cmd === 'domain') return domain(rest);
  throw new UsageError(`unknown command "${cmd}"`);
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e: unknown) => {
    console.error(e instanceof UsageError ? `unmask: ${e.message}\n\n${HELP}` : `unmask: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(2);
  },
);
