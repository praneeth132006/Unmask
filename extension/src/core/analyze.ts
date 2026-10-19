import { parseEmail } from './parse';
import { mergeFindings, scoreFindings, sortFindings } from './score';
import type { Finding, Report } from './types';
import { analyzeAuth } from '../analyzers/auth';
import { analyzeSender } from '../analyzers/sender';
import { analyzeContent } from '../analyzers/content';
import { analyzeLinks } from '../analyzers/links';
import { analyzeAttachments } from '../analyzers/attachments';
import { analyzeTrackers } from '../analyzers/trackers';
import { analyzeBec } from '../analyzers/bec';
import { historyFindings, type SenderHistory } from '../analyzers/history';

export interface AnalyzeOptions {
  /** Who normally emails this user, for "first contact" and impersonation checks. */
  history?: SenderHistory;
}

/**
 * Full local analysis of a raw email. Makes no network requests: everything
 * here runs on the user's machine. Online checks are added later with
 * `withExtraFindings`.
 */
export async function analyzeRawEmail(raw: string | ArrayBuffer | Uint8Array, opts: AnalyzeOptions = {}): Promise<Report> {
  const email = await parseEmail(raw);
  const { auth, findings: authFindings } = analyzeAuth(email);
  const senderFindings = analyzeSender(email);
  const content = analyzeContent(email);
  const { attachments, findings: attachmentFindings, links: fileLinks } = await analyzeAttachments(email.attachments);
  const { links, findings: linkFindings } = analyzeLinks([...content.links, ...fileLinks], email.from?.domain ?? '');
  const { trackers, findings: trackerFindings } = analyzeTrackers(email.html, links.filter((l) => l.source === 'html' || l.source === 'text'));
  const becFindings = analyzeBec(email, content.visibleText);
  const pastFindings = opts.history ? historyFindings(email, opts.history) : [];

  const findings = sortFindings([...authFindings, ...senderFindings, ...content.findings, ...linkFindings, ...attachmentFindings, ...trackerFindings, ...becFindings, ...pastFindings]);
  const { score, verdict } = scoreFindings(findings);

  return {
    email,
    auth,
    links,
    attachments,
    hidden: content.hidden,
    trackers,
    annotatedHtml: content.annotatedHtml,
    findings,
    score,
    verdict,
  };
}

export function withExtraFindings(report: Report, extra: Finding[]): Report {
  const findings = mergeFindings(report.findings, extra);
  return { ...report, findings, ...scoreFindings(findings) };
}
