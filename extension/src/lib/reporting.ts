/**
 * Reports for people and services outside Unmask: a JSON or PDF report for
 * an IT team, and prefilled reports to anti-phishing services. Nothing is
 * sent automatically: every destination opens in a tab or compose window
 * the user reviews and sends themselves.
 */
import type { LinkInfo, Report, Severity } from '../core/types';
import { SEVERITY_RANK } from '../core/score';
import { buildPdf, type PdfLine } from './pdf';
import { hypotheses, limitations } from '../core/assessment';
import { phoneNumbers } from '../analyzers/techniques';
import { entryHop } from '../analyzers/received';
import { registrableDomain } from './domain';

export const TOOL = 'Unmask (https://github.com/praneeth132006/Unmask)';

/** hxxps://paypa1[.]top/login — readable, but no client will turn it into a link. */
export function defang(url: string): string {
  return url.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}

/** 185[.]220[.]101[.]4, billing[@]paypa1-support[.]xyz: safe to paste into tickets and chats. */
export function defangText(s: string): string {
  return s.replace(/\./g, '[.]').replace(/@/g, '[@]');
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

export interface Indicators {
  senderAddress: string | null;
  senderDomain: string | null;
  replyTo: string[];
  returnPath: string | null;
  originIp: string | null;
  /** The server that handed the email to your provider, as your provider saw it. */
  deliveringServer: string | null;
  dkimDomains: string[];
  urls: string[];
  domains: string[];
  sha256: string[];
  phones: string[];
}

/** Indicators of compromise, the list an analyst blocks and searches for across the mailbox. */
export function indicators(report: Report, maxUrls = 50): Indicators {
  const { email } = report;
  const entry = entryHop(report.forensics.hops);
  const callback = report.findings.some((f) => f.id === 'callback-phishing' || f.id === 'platform-abuse');
  return {
    senderAddress: email.from?.address ?? null,
    senderDomain: email.from?.domain ?? null,
    replyTo: email.replyTo.map((r) => r.address),
    returnPath: email.returnPath,
    originIp: report.forensics.originIp,
    deliveringServer: entry ? [entry.rdns && entry.rdns !== 'unknown' ? entry.rdns : entry.helo, entry.ip && `[${entry.ip}]`].filter(Boolean).join(' ') || null : null,
    dkimDomains: [...new Set(report.forensics.dkim.map((d) => d.domain))],
    urls: suspiciousUrls(report, maxUrls),
    // Exact hosts: blocking a registrable domain like pages.dev or blogspot.com would block a whole hosting platform.
    domains: [...new Set(report.links.filter((l) => worst(l) >= SEVERITY_RANK.medium).map((l) => l.host).filter(Boolean))],
    sha256: report.attachments.filter((a) => a.flags.length).map((a) => a.sha256),
    phones: callback ? phoneNumbers(report.previewText) : [],
  };
}

/** Indicators as defanged lines, ready to paste into a ticket. */
export function indicatorText(report: Report): string {
  const i = indicators(report);
  const lines: string[] = [];
  const add = (label: string, values: (string | null)[], fang = true) => {
    for (const v of values) if (v) lines.push(`${label}\t${fang ? defangText(v) : v}`);
  };
  add('sender', [i.senderAddress]);
  add('reply-to', i.replyTo);
  add('return-path', [i.returnPath]);
  add('origin-ip', [i.originIp]);
  add('delivered-by', [i.deliveringServer]);
  add('dkim-domain', i.dkimDomains);
  for (const u of i.urls) lines.push(`url\t${defang(u)}`);
  add('host', i.domains);
  add('sha256', i.sha256, false);
  add('phone', i.phones, false);
  return lines.join('\n');
}

/**
 * A plain-text case write-up in the order a SOC analyst works: verdict and
 * attack type, identifiers, authentication, delivery path, findings,
 * indicators, and what was not checked.
 */
export function analystReport(report: Report, version: string, now = new Date()): string {
  const { email, auth, forensics } = report;
  const kinds = hypotheses(report);
  const out: string[] = [];
  const section = (title: string) => out.push('', `## ${title}`);
  out.push(`# Phishing analysis: ${email.subject || '(no subject)'}`, `Generated ${now.toISOString()} by ${TOOL} ${version}. All checks ran on the analyst's computer unless noted.`);

  section('Verdict');
  out.push(`${VERDICT_TEXT[report.verdict]}, risk score ${report.score}/100.`);
  for (const h of kinds) out.push(`- ${h.label} (${h.confidence} confidence): ${h.meaning}`);

  section('Message');
  out.push(`From: ${email.from ? `${email.from.name ? `"${email.from.name}" ` : ''}<${email.from.address}>` : 'missing'}`);
  if (email.replyTo.length) out.push(`Reply-To: ${email.replyTo.map((r) => r.address).join(', ')}`);
  if (email.returnPath) out.push(`Return-Path: ${email.returnPath}`);
  out.push(`To: ${email.to.map((t) => t.address).join(', ') || 'none'}`, `Date: ${email.date ?? 'unknown'}`, `Message-ID: ${email.messageId ?? 'none'}`);

  section('Authentication');
  out.push(`Provider verdict${auth.server ? ` (${auth.server})` : ''}: SPF ${auth.spf}${auth.spfDomain ? ` (${auth.spfDomain})` : ''}, DKIM ${auth.dkim}${auth.dkimDomains.length ? ` (${auth.dkimDomains.join(', ')})` : ''}, DMARC ${auth.dmarc}${auth.dmarcDomain ? ` (${auth.dmarcDomain})` : ''}.`);
  for (const d of forensics.dkim) {
    out.push(`- DKIM d=${d.domain} s=${d.selector} ${d.algorithm}${d.keyBits ? ` ${d.keyBits}-bit` : ''}: body ${d.bodyHash}, signature ${d.signature ?? 'not verified'}${d.bodyLength !== null ? `, l=${d.bodyLength}` : ''}${d.signedAt ? `, signed ${new Date(d.signedAt).toISOString()}` : ''}${d.reason ? ` (${d.reason})` : ''}`);
  }
  for (const a of forensics.arc) out.push(`- ARC i=${a.instance} by ${a.domain}, cv=${a.cv}: ${Object.entries(a.results).map(([m, r]) => `${m}=${r}`).join(' ')}`);
  if (forensics.arcProblem) out.push(`- ARC problem: ${forensics.arcProblem}`);

  if (forensics.hops.length) {
    section('Delivery path (origin first)');
    for (const h of forensics.hops) {
      const when = h.time ? new Date(h.time).toISOString() : 'no time';
      out.push(`${h.n}. ${h.helo ?? h.rdns ?? (h.trusted ? 'internal step at your provider' : 'unknown')}${h.ip ? ` [${h.ip}]` : ''}${h.rdns && h.rdns !== h.helo ? ` rDNS ${h.rdns}` : ''} -> ${h.by ?? '?'} at ${when}${h.delaySec !== null ? ` (+${h.delaySec}s)` : ''}${h.trusted ? '' : ' [unverifiable]'}`);
    }
    if (forensics.sender) out.push(`Delivering server network: ${[forensics.sender.network, forensics.sender.asn && `AS${forensics.sender.asn}`, forensics.sender.country].filter(Boolean).join(', ')}`);
  }

  section(`Findings (${report.findings.filter((f) => f.points > 0).length} red flags)`);
  for (const f of report.findings) out.push(`- [${f.severity.toUpperCase()}${f.points ? ` ${f.points > 0 ? '+' : ''}${f.points}` : ''}] ${f.title}${f.detail ? `\n  ${f.detail}` : ''}`);

  const iocs = indicatorText(report);
  if (iocs) {
    section('Indicators (defanged)');
    out.push(iocs);
  }

  const limits = limitations(report);
  if (limits.length) {
    section('Not checked');
    for (const l of limits) out.push(`- ${l}`);
  }
  section('Recommended actions');
  if (report.verdict === 'high') {
    out.push('- Do not click, reply or open files. Report it and delete it.', '- Search other mailboxes for the sender, Reply-To, URLs and hashes above, and block them.', '- If anyone clicked or replied: reset their password, revoke sessions and app consents, and check their mailbox rules.');
  } else if (report.verdict === 'suspicious') {
    out.push('- Confirm with the sender through a known channel (phone, official app) before acting.', '- Run a sandbox scan of the links and a VirusTotal check of the files.');
  } else {
    out.push('- No action needed from these checks. Still verify unexpected payment or password requests out of band.');
  }
  return out.join('\n');
}

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
    assessment: hypotheses(report).map(({ kind, label, confidence, evidence }) => ({ kind, label, confidence, evidence })),
    notChecked: limitations(report),
    forensics: report.forensics,
    indicators: indicators(report),
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

  for (const h of hypotheses(report)) L.push({ kind: 'small', text: `${h.label} (${h.confidence} confidence): ${h.meaning}` });

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
  const limits = limitations(report);
  if (limits.length) {
    L.push({ kind: 'heading', text: 'Not checked' });
    for (const l of limits) L.push({ kind: 'small', text: `- ${l}` });
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
