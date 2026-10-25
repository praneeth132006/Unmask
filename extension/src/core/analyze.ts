import { parseEmail } from './parse';
import { mergeFindings, scoreFindings, sortFindings } from './score';
import type { Finding, Forensics, Report } from './types';
import { analyzeAuth } from '../analyzers/auth';
import { analyzeSender } from '../analyzers/sender';
import { analyzeContent } from '../analyzers/content';
import { analyzeLinks } from '../analyzers/links';
import { analyzeAttachments } from '../analyzers/attachments';
import { analyzeTrackers } from '../analyzers/trackers';
import { analyzeBec } from '../analyzers/bec';
import { historyFindings, type SenderHistory } from '../analyzers/history';
import { findBrandLogos, logoFindings } from '../analyzers/logos';
import { protectionFindings, type ProtectionList } from '../analyzers/protection';
import { findQrCodes, qrFindings, qrLinks, type ImageDecoder } from '../analyzers/qr';
import { deliveryPath, entryHop, originIp, receivedFindings } from '../analyzers/received';
import { dkimFindings } from '../analyzers/dkim';
import { arcFindings, readArcChain } from '../analyzers/arc';
import { identityFindings } from '../analyzers/identity';
import { replayFindings } from '../analyzers/replay';
import { archivePasswordFindings, callbackFindings, clickFixFindings, consentLureFindings, platformAbuseFindings } from '../analyzers/techniques';
import { publicInfo, readDkimSignatures } from '../lib/dkim';
import { splitRawMessage } from '../lib/rawMessage';
import { getHeaders } from './parse';

export interface AnalyzeOptions {
  /** Who normally emails this user, for "first contact" and impersonation checks. */
  history?: SenderHistory;
  /** Your protected brands, protected contacts and trusted senders. */
  protection?: ProtectionList;
  /** Decodes images for QR-code scanning. Without it, only PDF images that need no decoder are scanned. */
  decodeImage?: ImageDecoder;
}

/**
 * Full local analysis of a raw email. Makes no network requests: everything
 * here runs on the user's machine. Online checks are added later with
 * `withExtraFindings`.
 */
export async function analyzeRawEmail(raw: string | ArrayBuffer | Uint8Array, opts: AnalyzeOptions = {}): Promise<Report> {
  const email = await parseEmail(raw);
  const hops = deliveryPath(getHeaders(email, 'received'));
  const { auth, findings: authFindings } = analyzeAuth(email, hops);
  const rawMessage = splitRawMessage(raw);
  const signatures = await readDkimSignatures(rawMessage);
  const arc = readArcChain(rawMessage);
  const forensics: Forensics = { hops, originIp: originIp(hops, getHeaders(email, 'x-originating-ip')[0]), dkim: signatures.map(publicInfo), arc: arc.sets, arcProblem: arc.problem };
  const pathFindings = [...receivedFindings(hops, email.date), ...dkimFindings(signatures, rawMessage, auth, entryHop(hops)?.time ?? null, email.from?.domain ?? ''), ...arcFindings(arc.sets, arc.problem, auth), ...identityFindings(email, rawMessage, auth)];
  pathFindings.push(...replayFindings(email, auth, signatures, pathFindings));
  // A replayed email passes DMARC by design, so passing proves nothing here.
  if (pathFindings.some((f) => f.id === 'dkim-replay')) authFindings.splice(0, authFindings.length, ...authFindings.filter((f) => f.id !== 'dmarc-pass'));
  // A verified sender whose replies go to webmail is usually a small newsletter, not an impostor:
  // still worth knowing, but not a high-risk sign on its own.
  const senderFindings = analyzeSender(email).map((f) =>
    f.id === 'reply-to-mismatch' && f.severity === 'high' && auth.dmarc === 'pass'
      ? { ...f, severity: 'medium' as const, points: 10, detail: `${f.detail} The sender's domain is verified, so this is common for small newsletters; be careful if it asks for money or details.` }
      : f,
  );
  const content = analyzeContent(email);
  const { attachments, findings: attachmentFindings, links: fileLinks } = await analyzeAttachments(email.attachments);
  const qrCodes = await findQrCodes(email, opts.decodeImage);
  const { links, findings: linkFindings } = analyzeLinks([...content.links, ...fileLinks, ...qrLinks(qrCodes)], email.from?.domain ?? '');
  // Runs on the body already marked for hidden text, and marks each tracking pixel in it too.
  const { trackers, findings: trackerFindings, annotatedHtml } = analyzeTrackers(content.annotatedHtml ?? email.html, links.filter((l) => l.source === 'html' || l.source === 'text'));
  const becFindings = analyzeBec(email, content.visibleText);
  const abuse = platformAbuseFindings(email, content.visibleText, auth, links);
  // The platform-abuse finding already explains the phone number; don't count it twice.
  const techniqueFindings = [...(abuse.length ? [] : callbackFindings(email, content.visibleText, auth)), ...abuse, ...consentLureFindings(content.visibleText, links), ...clickFixFindings(content.visibleText, email, attachments), ...archivePasswordFindings(content.visibleText, email.subject, attachments)];
  const pressure = [...content.findings, ...becFindings].some((f) => ['credential-request', 'html-form', 'urgency', 'bec-bank-change', 'bec-payment', 'bec-gift-card'].includes(f.id));
  const fakeLogoFindings = logoFindings(email, await findBrandLogos(email, opts.decodeImage), pressure);
  const protectFindings = opts.protection ? protectionFindings(email, auth, links, opts.protection) : [];
  const verifiedTrusted = protectFindings.some((f) => f.id === 'trusted-sender' && f.points < 0);
  // A verified trusted sender is by definition not a stranger.
  const pastFindings = (opts.history ? historyFindings(email, opts.history) : []).filter((f) => !(verifiedTrusted && f.id === 'first-contact'));

  const findings = sortFindings([...authFindings, ...pathFindings, ...senderFindings, ...content.findings, ...linkFindings, ...attachmentFindings, ...trackerFindings, ...becFindings, ...techniqueFindings, ...pastFindings, ...qrFindings(qrCodes), ...fakeLogoFindings, ...protectFindings]);
  const { score, verdict } = scoreFindings(findings);

  return {
    email,
    auth,
    forensics,
    links,
    attachments,
    hidden: content.hidden,
    trackers,
    qrCodes,
    previewText: content.visibleText.replace(/\s+/g, ' ').trim().slice(0, 700),
    annotatedHtml: annotatedHtml ?? content.annotatedHtml,
    findings,
    score,
    verdict,
  };
}

export function withExtraFindings(report: Report, extra: Finding[]): Report {
  const findings = mergeFindings(report.findings, extra);
  return { ...report, findings, ...scoreFindings(findings) };
}
