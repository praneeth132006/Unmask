import { parseEmail } from './parse';
import { mergeFindings, scoreFindings, sortFindings } from './score';
import type { Finding, Report } from './types';
import { analyzeAuth } from '../analyzers/auth';
import { analyzeSender } from '../analyzers/sender';
import { analyzeContent } from '../analyzers/content';
import { analyzeLinks } from '../analyzers/links';
import { analyzeAttachments } from '../analyzers/attachments';

/**
 * Full local analysis of a raw email. Makes no network requests: everything
 * here runs on the user's machine. Online checks are added later with
 * `withExtraFindings`.
 */
export async function analyzeRawEmail(raw: string | ArrayBuffer | Uint8Array): Promise<Report> {
  const email = await parseEmail(raw);
  const { auth, findings: authFindings } = analyzeAuth(email);
  const senderFindings = analyzeSender(email);
  const content = analyzeContent(email);
  const { links, findings: linkFindings } = analyzeLinks(content.links, email.from?.domain ?? '');
  const { attachments, findings: attachmentFindings } = await analyzeAttachments(email.attachments);

  const findings = sortFindings([...authFindings, ...senderFindings, ...content.findings, ...linkFindings, ...attachmentFindings]);
  const { score, verdict } = scoreFindings(findings);

  return {
    email,
    auth,
    links,
    attachments,
    hidden: content.hidden,
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
