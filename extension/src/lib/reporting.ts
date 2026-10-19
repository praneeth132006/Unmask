/**
 * Reports for people and services outside Unmask: a JSON or PDF report for
 * an IT team, and prefilled reports to anti-phishing services. Nothing is
 * sent automatically: every destination opens in a tab or compose window
 * the user reviews and sends themselves.
 */
import type { LinkInfo, Report, Severity } from '../core/types';
import { SEVERITY_RANK } from '../core/score';
import { buildPdf, type PdfLine } from './pdf';

export const TOOL = 'Unmask (https://github.com/praneeth132006/Unmask)';

/** hxxps://paypa1[.]top/login — readable, but no client will turn it into a link. */
export function defang(url: string): string {
  return url.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}

function worst(l: LinkInfo): number {
  return Math.max(-1, ...l.flags.map((f) => SEVERITY_RANK[f.severity]));
}

/** Links worth reporting: flagged ones first, then any off-domain web link. */
export function suspiciousUrls(report: Report, max = 10): string[] {
  const urls = report.links
    .filter((l) => /^https?:/i.test(l.resolved) && worst(l) >= SEVERITY_RANK.low)
    .sort((a, b) => worst(b) - worst(a))
    .map((l) => l.resolved);
  return [...new Set(urls)].slice(0, max);
}

const VERDICT_TEXT = { high: 'High risk', suspicious: 'Suspicious', clear: 'No red flags found' } as const;

export function buildJsonReport(report: Report, version: string, now = new Date()) {
  const { email } = report;
  return {
    generator: TOOL,
    version,
    generatedAt: now.toISOString(),
    verdict: report.verdict,
    score: report.score,
    email: {
      from: email.from,
      replyTo: email.replyTo,
      returnPath: email.returnPath,
      to: email.to,
      subject: email.subject,
      date: email.date,
      messageId: email.messageId,
    },
    authentication: { ...report.auth, raw: undefined },
    findings: report.findings.map(({ id, category, severity, points, title, detail }) => ({ id, category, severity, points, title, detail })),
    links: report.links.map((l) => ({ href: l.href, resolved: l.resolved, text: l.text, source: l.source, origin: l.origin, domain: l.domain, flags: l.flags.map((f) => f.label) })),
    attachments: report.attachments.map((a) => ({ filename: a.filename, mimeType: a.mimeType, size: a.size, sha256: a.sha256, flags: a.flags.map((f) => f.label), contents: a.contents })),
    qrCodes: report.qrCodes,
    indicators: {
      urls: suspiciousUrls(report, 50),
      domains: [...new Set(report.links.filter((l) => worst(l) >= SEVERITY_RANK.medium).map((l) => l.domain).filter(Boolean))],
      senderDomain: email.from?.domain ?? null,
      sha256: report.attachments.filter((a) => a.flags.length).map((a) => a.sha256),
    },
    headers: email.headers.map((h) => ({ name: h.name, value: h.value })),
  };
}

const SEV_COLOR: Record<Severity, [number, number, number]> = {
  critical: [0.75, 0.1, 0.1],
  high: [0.75, 0.1, 0.1],
  medium: [0.7, 0.42, 0],
  low: [0.6, 0.45, 0.1],
  info: [0.2, 0.35, 0.6],
  good: [0.1, 0.5, 0.25],
};

export function buildPdfReport(report: Report, version: string, now = new Date()): Uint8Array {
  const { email } = report;
  const L: PdfLine[] = [];
  L.push({ kind: 'title', text: 'Unmask email report' });
  L.push({ kind: 'small', text: `Generated ${now.toISOString().replace('T', ' ').slice(0, 16)} UTC by Unmask ${version}. All checks ran locally in the browser unless noted.` });
  L.push({ kind: 'gap' });
  L.push({ kind: 'text', text: `Verdict: ${VERDICT_TEXT[report.verdict]} (risk score ${report.score}/100)`, color: report.verdict === 'high' ? SEV_COLOR.high : report.verdict === 'suspicious' ? SEV_COLOR.medium : SEV_COLOR.good });

  L.push({ kind: 'heading', text: 'Message' });
  L.push({ kind: 'text', text: `Subject: ${email.subject || '(none)'}` });
  L.push({ kind: 'text', text: `From: ${email.from ? `${email.from.name} <${email.from.address}>` : 'missing'}` });
  if (email.replyTo.length) L.push({ kind: 'text', text: `Reply-To: ${email.replyTo.map((r) => r.address).join(', ')}` });
  if (email.returnPath) L.push({ kind: 'text', text: `Return-Path: ${email.returnPath}` });
  L.push({ kind: 'text', text: `Date: ${email.date ?? 'unknown'}` });
  L.push({ kind: 'text', text: `Message-ID: ${email.messageId ?? 'none'}` });
  L.push({ kind: 'text', text: `SPF: ${report.auth.spf}   DKIM: ${report.auth.dkim}   DMARC: ${report.auth.dmarc}${report.auth.server ? `   (checked by ${report.auth.server})` : ''}` });

  L.push({ kind: 'heading', text: `Findings (${report.findings.length})` });
  for (const f of report.findings) {
    L.push({ kind: 'text', text: `[${f.severity.toUpperCase()}] ${f.title}`, color: SEV_COLOR[f.severity] });
    if (f.detail) L.push({ kind: 'small', text: f.detail });
  }

  const urls = suspiciousUrls(report, 30);
  if (urls.length) {
    L.push({ kind: 'heading', text: 'Suspicious links (defanged)' });
    for (const u of urls) L.push({ kind: 'mono', text: defang(u) });
  }
  if (report.attachments.length) {
    L.push({ kind: 'heading', text: 'Attachments' });
    for (const a of report.attachments) {
      L.push({ kind: 'text', text: `${a.filename} (${a.mimeType}, ${a.size} bytes)` });
      L.push({ kind: 'mono', text: `SHA-256 ${a.sha256}` });
      for (const fl of a.flags) L.push({ kind: 'small', text: `- ${fl.label}`, color: SEV_COLOR[fl.severity] });
    }
  }
  if (report.qrCodes.length) {
    L.push({ kind: 'heading', text: 'QR codes' });
    for (const q of report.qrCodes) L.push({ kind: 'mono', text: `${q.origin}: ${/^http/i.test(q.text) ? defang(q.text) : q.text}` });
  }
  L.push({ kind: 'heading', text: 'Delivery headers' });
  for (const h of email.headers.filter((x) => ['received', 'authentication-results', 'received-spf', 'dkim-signature', 'arc-authentication-results', 'x-originating-ip'].includes(x.key)).slice(0, 25)) {
    L.push({ kind: 'mono', text: `${h.name}: ${h.value.replace(/\s+/g, ' ')}` });
  }
  return buildPdf(L, `Unmask report - ${email.subject.slice(0, 60)}`);
}

/** Plain-text summary for report emails and web forms. */
export function reportSummary(report: Report): string {
  const { email } = report;
  const lines = [
    `Reported with ${TOOL}`,
    '',
    `Verdict: ${VERDICT_TEXT[report.verdict]} (${report.score}/100)`,
    `From: ${email.from?.address ?? 'unknown'}${email.from?.name ? ` ("${email.from.name}")` : ''}`,
    `Subject: ${email.subject}`,
    `Date: ${email.date ?? 'unknown'}`,
    `Message-ID: ${email.messageId ?? 'none'}`,
    '',
    'Top findings:',
    ...report.findings.filter((f) => f.points > 0).slice(0, 6).map((f) => `- ${f.title}`),
  ];
  const urls = suspiciousUrls(report, 8);
  if (urls.length) lines.push('', 'Suspicious URLs (defanged):', ...urls.map((u) => `- ${defang(u)}`));
  return lines.join('\n');
}

export type ReportService = 'apwg' | 'netcraft';

export const REPORT_ADDRESS: Record<ReportService, string> = {
  apwg: 'reportphishing@apwg.org',
  netcraft: 'scam@netcraft.com',
};

/**
 * A compose window to a reporting address. In Gmail, a Gmail compose page for
 * the same account; elsewhere, mailto:. The body asks the user to attach the
 * downloaded .eml, which is what these services need to trace the sender.
 */
export function composeUrl(service: ReportService, report: Report, gmailAccount: string | null): string {
  const subject = `Phishing report: ${report.email.subject}`.slice(0, 180);
  const body = `${reportSummary(report)}\n\nThe original message is attached as an .eml file.\n`.slice(0, 1800);
  const to = REPORT_ADDRESS[service];
  if (gmailAccount !== null) {
    return `https://mail.google.com/mail/u/${encodeURIComponent(gmailAccount)}/?view=cm&fs=1&to=${encodeURIComponent(to)}&su=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  }
  return `mailto:${to}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}

/** Web forms for reporting a single URL. Only Google's accepts the URL prefilled. */
export function urlReportPage(service: 'google' | 'phishtank' | 'netcraft', url: string): string {
  if (service === 'google') return `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(url)}`;
  if (service === 'phishtank') return 'https://phishtank.org/add_web_phish.php';
  return 'https://report.netcraft.com/report';
}

export function safeFileName(s: string): string {
  return (s.replace(/[^\w.-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 60) || 'email').toLowerCase();
}
