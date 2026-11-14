/**
 * "Was this right?": a report of a wrong verdict that the user sends themself,
 * as a GitHub issue. Nothing is sent by Unmask. Only what the user sees in the
 * preview is shared: the verdict, the score, the ids of the checks that fired
 * and the version, plus the sender's domain only when the user ticks it.
 * Finding titles are left out: they can contain addresses and names.
 */
import type { Report } from '../core/types';

export const ISSUE_URL = 'https://github.com/praneeth132006/Unmask/issues/new';

export type Mistake = 'missed' | 'false-alarm';

export interface FeedbackOptions {
  mistake: Mistake;
  includeDomain: boolean;
  version: string;
}

const VERDICT: Record<Report['verdict'], string> = { high: 'High risk', suspicious: 'Suspicious', clear: 'No red flags found' };

/** Default guess: a warned email the user disagrees with is a false alarm, a clear one a miss. */
export function likelyMistake(report: Report): Mistake {
  return report.verdict === 'clear' ? 'missed' : 'false-alarm';
}

export function feedbackText(report: Report, opts: FeedbackOptions): { title: string; score: string; why: string } {
  const fired = report.findings.filter((f) => f.points !== 0).map((f) => `${f.id.replace(/-[0-9a-f]{12}$/, '-*').replace(/-\d+$/, '')} (${f.points > 0 ? '+' : ''}${f.points})`);
  const domain = opts.includeDomain && report.email.from?.domain ? report.email.from.domain : null;
  const title = `${opts.mistake === 'missed' ? 'Missed phishing' : 'False alarm'}: ${VERDICT[report.verdict]} (${report.score})${domain ? ` from ${domain}` : ''}`;
  const why = [
    `Checks that fired: ${fired.length ? [...new Set(fired)].join(', ') : 'none'}`,
    domain ? `Sender's domain: ${domain}` : 'Sender’s domain: not shared',
    `Unmask version: ${opts.version}`,
    '',
    opts.mistake === 'missed' ? 'Why I think this is phishing: ' : 'Why I think this email is legitimate: ',
  ].join('\n');
  return { title, score: `${report.score}, ${VERDICT[report.verdict]}`, why };
}

/** A link to the "Wrong verdict" issue form, filled in with exactly the preview. */
export function feedbackUrl(report: Report, opts: FeedbackOptions): string {
  const t = feedbackText(report, opts);
  const q = new URLSearchParams({
    template: 'detection.yml',
    title: t.title,
    kind: opts.mistake === 'missed' ? 'Missed phishing (scored too low)' : 'False alarm (legitimate email scored too high)',
    score: t.score,
    why: t.why,
  });
  return `${ISSUE_URL}?${q.toString()}`;
}
