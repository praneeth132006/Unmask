/**
 * The investigation report as plain data: an executive part for leaders and
 * non-technical staff, and a very detailed technical part for security teams.
 * PDF, Word, HTML and STIX renderers all draw from this one model, so every
 * format says exactly the same thing.
 */
import { hypotheses, limitations, type AttackKind } from '../core/assessment';
import { plainSummary } from '../core/plain';
import { SEVERITY_RANK } from '../core/score';
import type { AttachmentInfo, Finding, LinkInfo, Report, Severity } from '../core/types';
import { defang as defangUrl, defangText, indicators } from '../lib/reporting';
import type { Anomaly, FileForensics } from '../forensics/types';

export type Tlp = 'CLEAR' | 'GREEN' | 'AMBER' | 'AMBER+STRICT' | 'RED';
export type Audience = 'both' | 'executive' | 'technical';

export interface ReportMeta {
  caseId?: string;
  preparedBy?: string;
  organisation?: string;
  tlp?: Tlp;
  notes?: string;
}

/** Facts about the saved original message, computed by the caller. */
export interface Evidence {
  emlSha256?: string;
  emlSize?: number;
}

export type Tone = 'bad' | 'warn' | 'good' | 'info';

export type Block =
  | { t: 'h3'; text: string }
  | { t: 'p'; text: string; small?: boolean }
  | { t: 'ul'; items: string[] }
  | { t: 'checklist'; items: string[] }
  | { t: 'kv'; rows: [string, string][] }
  | { t: 'table'; head: string[]; rows: string[][]; widths?: number[]; mono?: boolean[]; tones?: (Tone | undefined)[] }
  | { t: 'code'; text: string }
  | { t: 'callout'; tone: Tone; title: string; text: string };

export interface Section {
  id: string;
  title: string;
  part: 'executive' | 'technical' | 'appendix';
  /** One line under the title saying who it is for. */
  lead?: string;
  blocks: Block[];
}

export interface CaseDoc {
  title: string;
  subtitle: string;
  generatedAt: string;
  tool: string;
  version: string;
  verdict: { label: string; tone: Tone; score: number };
  meta: [string, string][];
  tlp: Tlp;
  sections: Section[];
  /** For the STIX and JSON exports. */
  evidence: Evidence;
}

const TOOL = 'Unmask (https://github.com/praneeth132006/Unmask)';
const VERDICT = { high: { label: 'High risk', tone: 'bad' }, suspicious: { label: 'Suspicious', tone: 'warn' }, clear: { label: 'No red flags found', tone: 'good' } } as const;
const SEV_TONE: Record<Severity, Tone | undefined> = { critical: 'bad', high: 'bad', medium: 'warn', low: 'warn', info: 'info', good: 'good' };
const cap = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}…` : s);
const utc = (ms: number | null | undefined) => (ms ? new Date(ms).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '—');
const sevLabel = (s: Severity) => s.toUpperCase();
/** "19 Oct 2026, 16:00 UTC" for a date header, or the original text when it can't be read. */
const niceDate = (d: string | null | undefined): string => {
  const ms = d ? Date.parse(d) : NaN;
  return Number.isNaN(ms) ? (d ?? 'unknown') : `${new Date(ms).toISOString().slice(8, 10).replace(/^0/, '')} ${['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][new Date(ms).getUTCMonth()]} ${new Date(ms).getUTCFullYear()}, ${new Date(ms).toISOString().slice(11, 16)} UTC`;
};

/** A short, stable id for a case, from the message id and subject. */
export function autoCaseId(report: Report, now: Date): string {
  let h = 2166136261;
  for (const ch of `${report.email.messageId ?? ''}|${report.email.subject}|${report.email.from?.address ?? ''}`) h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0;
  return `UNM-${now.toISOString().slice(0, 10).replace(/-/g, '')}-${h.toString(16).toUpperCase().padStart(8, '0')}`;
}

/* ------------------------------------------------------------ MITRE ATT&CK */

export const ATTACK_NAMES: Record<string, string> = {
  'T1566.001': 'Phishing: Spearphishing Attachment',
  'T1566.002': 'Phishing: Spearphishing Link',
  'T1598.003': 'Phishing for Information: Spearphishing Link',
  'T1204.001': 'User Execution: Malicious Link',
  'T1204.002': 'User Execution: Malicious File',
  'T1059': 'Command and Scripting Interpreter',
  'T1059.007': 'Command and Scripting Interpreter: JavaScript',
  'T1027': 'Obfuscated Files or Information',
  'T1027.002': 'Obfuscated Files or Information: Software Packing',
  'T1027.009': 'Obfuscated Files or Information: Embedded Payloads',
  'T1036.008': 'Masquerading: Masquerade File Type',
  'T1221': 'Template Injection',
  'T1187': 'Forced Authentication',
  'T1203': 'Exploitation for Client Execution',
  'T1559.002': 'Inter-Process Communication: Dynamic Data Exchange',
  'T1056': 'Input Capture',
  'T1656': 'Impersonation',
  'T1672': 'Email Spoofing',
  'T1078': 'Valid Accounts',
};

interface Technique {
  id: string;
  evidence: string[];
}

function techniques(report: Report): Technique[] {
  const map = new Map<string, Set<string>>();
  const add = (id: string, why: string) => {
    if (!map.has(id)) map.set(id, new Set());
    map.get(id)!.add(why);
  };
  const kinds = new Set(hypotheses(report).map((h) => h.kind));
  const files = report.attachments.filter((a) => !a.inline);
  if (files.some((a) => a.flags.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high))) add('T1566.001', 'Attachment with high-risk characteristics');
  if (kinds.has('credential-phishing')) { add('T1566.002', 'Link or form built to collect sign-in details'); add('T1598.003', 'Credential harvesting lure'); add('T1078', 'Possible use of stolen credentials after a successful lure'); }
  if (kinds.has('malware')) add('T1204.002', 'Lure to open or run a harmful file');
  if (report.links.some((l) => l.flags.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high))) add('T1204.001', 'High-risk link in the message');
  if (kinds.has('impersonation')) add('T1656', 'Pretends to be a trusted person or company');
  if (kinds.has('spoofing')) add('T1672', 'Sender address forged or not authenticated');
  for (const a of files) for (const an of a.forensics?.anomalies ?? []) if (an.attack) add(an.attack, `${a.filename}: ${an.title}`);
  return [...map.entries()].map(([id, e]) => ({ id, evidence: [...e].slice(0, 4) })).sort((a, b) => a.id.localeCompare(b.id));
}

export type IocType = 'sender' | 'reply-to' | 'return-path' | 'origin-ip' | 'dkim-domain' | 'url' | 'domain' | 'file-ip' | 'file-email' | 'file-url' | 'program' | 'command' | 'filename' | 'sha256' | 'sha1' | 'md5' | 'phone';

export interface Ioc {
  type: IocType;
  /** The exact value, never defanged. */
  value: string;
}

/** Every indicator worth blocking or hunting for, with exact values. */
export function collectIocs(report: Report, limit = 100): Ioc[] {
  const ind = indicators(report, limit);
  const files = report.attachments.filter((a) => !a.inline);
  const fileIocs = files.flatMap((a) => (a.forensics ? [a.forensics.iocs, ...a.forensics.children.map((c) => c.forensics.iocs)] : []));
  const out: Ioc[] = [];
  const seen = new Set<string>();
  const push = (type: IocType, vals: (string | null | undefined)[]) => {
    for (const v of vals.slice(0, limit)) {
      if (!v || seen.has(`${type}\u0000${v}`)) continue;
      seen.add(`${type}\u0000${v}`);
      out.push({ type, value: v });
    }
  };
  push('sender', [ind.senderAddress]);
  push('reply-to', ind.replyTo);
  push('return-path', [ind.returnPath]);
  push('origin-ip', [ind.originIp]);
  push('dkim-domain', ind.dkimDomains);
  push('url', ind.urls);
  push('domain', [...ind.domains, ...fileIocs.flatMap((i) => i.domains)]);
  push('file-ip', fileIocs.flatMap((i) => i.ips));
  push('file-email', fileIocs.flatMap((i) => i.emails));
  push('file-url', files.flatMap((a) => a.forensics?.links.map((l) => l.url) ?? []));
  push('program', fileIocs.flatMap((i) => i.executables));
  push('command', fileIocs.flatMap((i) => i.commands));
  push('filename', files.map((a) => a.filename));
  push('sha256', files.flatMap((a) => [a.sha256, ...(a.forensics?.children.map((c) => c.forensics.hashes.sha256) ?? [])]));
  push('sha1', files.map((a) => a.forensics?.hashes.sha1));
  push('md5', files.map((a) => a.forensics?.hashes.md5));
  push('phone', ind.phones);
  return out;
}

/* ---------------------------------------------------------------- helpers */

const findingsOf = (report: Report, ...cats: Finding['category'][]) => report.findings.filter((f) => cats.includes(f.category));
const worstFlag = (l: LinkInfo) => l.flags.reduce<Severity>((w, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[w] ? f.severity : w), 'good');
const docs = (report: Report): AttachmentInfo[] => report.attachments.filter((a) => !a.inline);
const kindsOf = (report: Report): AttackKind[] => hypotheses(report).map((h) => h.kind);
const worstOf = (f: FileForensics): Severity => f.anomalies.reduce<Severity>((w, a) => (SEVERITY_RANK[a.severity] > SEVERITY_RANK[w] ? a.severity : w), 'good');

function intelFindingsOf(report: Report): Finding[] {
  return report.findings.filter((f) => /^(vt-|ha-|mb-|urlscan|urlhaus|phishtank|gdoc-)/.test(f.id));
}

/* -------------------------------------------------------- executive part */

const BUSINESS_RISK: Record<AttackKind, { risk: string; impact: string; level: 'High' | 'Medium' }> = {
  'credential-phishing': { risk: 'Stolen passwords', impact: 'Someone who enters a password on the fake page hands attackers the account. From there they can read mail and files, send more phishing from a trusted address and reach other systems.', level: 'High' },
  malware: { risk: 'Malware or ransomware', impact: 'Opening the file or link can install harmful software: data theft, locked files, downtime and recovery costs.', level: 'High' },
  'payment-fraud': { risk: 'Financial loss', impact: 'Payments to fraudsters are usually very hard to recover. Fake invoices, changed bank details and gift-card requests are among the costliest email scams.', level: 'High' },
  callback: { risk: 'Phone scam', impact: 'Staff who phone the number are talked into installing remote-access tools or paying "refunds".', level: 'High' },
  consent: { risk: 'Silent account access', impact: 'Approving the request gives an attacker lasting access to the account without ever needing the password, and it can survive a password change.', level: 'High' },
  'account-takeover': { risk: 'A trusted account may be hacked', impact: 'The sender is someone you know but is behaving differently. Their account may be controlled by an attacker, which puts partners and customers at risk.', level: 'High' },
  impersonation: { risk: 'Trust and brand abuse', impact: 'Staff, customers or partners are tricked by a convincing fake of a person or company they trust.', level: 'Medium' },
  spoofing: { risk: 'Forged sender', impact: 'The email pretends to come from a real address. If it uses your own domain, it also points to a gap in your email protections.', level: 'Medium' },
  replay: { risk: 'Genuine email re-sent by an attacker', impact: 'A real, signed email is re-sent so it passes checks, which makes it look trustworthy.', level: 'Medium' },
};

function confidenceText(report: Report): string {
  if (report.verdict === 'high') return 'High. Several independent signals agree, so this conclusion is strong.';
  if (report.verdict === 'suspicious') return 'Medium. The signs are concerning but not conclusive, so the sender should be checked another way.';
  return 'Moderate. No red flags were found, but no check can prove an email is safe.';
}

function executiveSections(report: Report, now: Date): Section[] {
  const { email } = report;
  const plain = plainSummary(report);
  const kinds = hypotheses(report);
  const verdict = VERDICT[report.verdict];
  const files = docs(report);
  const from = email.from ? `${email.from.name ? `“${email.from.name}” ` : ''}<${defangText(email.from.address)}>` : 'missing';
  const risky = report.links.filter((l) => SEVERITY_RANK[worstFlag(l)] >= SEVERITY_RANK.high).length;
  const flagged = files.filter((a) => a.flags.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high)).length;

  const glance: Section = {
    id: 'summary',
    title: 'Summary for leaders and non-technical staff',
    part: 'executive',
    lead: 'Plain language, no technical background needed.',
    blocks: [
      { t: 'callout', tone: verdict.tone, title: `${verdict.label}. ${plain.headline}`, text: plain.action },
      {
        t: 'kv',
        rows: [
          ['Email subject', email.subject || '(no subject)'],
          ['Appears to be from', from],
          ['Date on the email', niceDate(email.date)],
          ['Overall rating', `${verdict.label} (${report.score} out of 100)`],
          ['Type of attack', kinds.length ? kinds.slice(0, 3).map((k) => k.label).join('; ') : 'None identified'],
          ['Attachments', files.length ? `${files.length}${flagged ? ` (${flagged} dangerous)` : ''}` : 'None'],
          ['Links', report.links.length ? `${report.links.length}${risky ? ` (${risky} dangerous)` : ''}` : 'None'],
          ['Report prepared', now.toISOString().slice(0, 10)],
        ],
      },
    ],
  };

  const happened: Section = {
    id: 'what-happened',
    title: 'What happened',
    part: 'executive',
    blocks: [
      { t: 'p', text: `An email with the subject “${email.subject || '(no subject)'}” arrived from ${from}. It was examined entirely on the analyst's computer: its sender details, its links, its attachments and the way it was delivered.` },
      ...(kinds.length
        ? [{ t: 'p' as const, text: kinds.slice(0, 3).map((k) => `It looks like ${k.label.toLowerCase()} (${k.confidence} confidence): ${k.meaning}`).join(' ') }]
        : [{ t: 'p' as const, text: 'Nothing about it matched a known type of email attack.' }]),
      ...(plain.reasons.length ? [{ t: 'h3' as const, text: 'The main reasons' }, { t: 'ul' as const, items: plain.reasons }] : []),
    ],
  };

  const riskRows = [...new Set(kindsOf(report))].map((k) => BUSINESS_RISK[k]).map((r) => [r.risk, r.impact, r.level]);
  const tracking = report.trackers.pixels.length;
  if (tracking) riskRows.push(['Privacy', `The email contains ${tracking} hidden tracking pixel${tracking === 1 ? '' : 's'}. When the email is opened, the sender learns it was read and roughly where.`, 'Low']);
  const impact: Section = {
    id: 'business-impact',
    title: 'Why it matters to the organisation',
    part: 'executive',
    blocks: riskRows.length
      ? [{ t: 'table', head: ['Risk', 'What could happen', 'Level'], rows: riskRows, widths: [22, 66, 12], tones: riskRows.map((r) => (r[2] === 'High' ? 'bad' : r[2] === 'Medium' ? 'warn' : 'info')) }]
      : [{ t: 'p', text: 'No business risk was indicated by these checks. Email that unexpectedly asks for money, passwords or urgent action should still be verified through another channel.' }],
  };

  const actions: Section = {
    id: 'actions',
    title: 'What to do now',
    part: 'executive',
    blocks: [
      { t: 'h3', text: 'Everyone' },
      { t: 'ul', items: report.verdict === 'clear' ? ['No action is required from these checks.', 'Stay cautious with unexpected requests for money, passwords or urgent action: confirm them by phone or in person.'] : ['Do not click links, open attachments, scan QR codes or reply to this email.', 'Do not forward it to colleagues. Report it using the steps below, then delete it.', 'If you are unsure whether it is genuine, contact the supposed sender using a phone number or website you already know, never the details in the email.'] },
      ...(report.verdict !== 'clear'
        ? [
            { t: 'h3' as const, text: 'If someone already clicked, opened a file, replied or typed a password' },
            { t: 'ul' as const, items: ['Tell the IT or security team immediately. Speed matters more than embarrassment.', 'Change the password for that account, and for any other account that uses the same password, from a different device.', 'If a file was opened, disconnect the computer from the network and wait for IT before using it again.', 'If money was sent or bank details were shared, call the bank at once and ask for the payment to be recalled.'] },
            { t: 'h3' as const, text: 'For the IT and security team' },
            { t: 'ul' as const, items: ['Block the sender, the domains and the links listed in the technical part, and search every mailbox for the same email.', 'Remove copies from all mailboxes that received it.', 'For anyone who interacted with it: reset passwords, sign them out everywhere, review app approvals and check for new mailbox rules or forwarding.'] },
          ]
        : []),
      ...(kindsOf(report).includes('payment-fraud') || kindsOf(report).includes('callback')
        ? [{ t: 'h3' as const, text: 'For finance and management' }, { t: 'ul' as const, items: ['Do not act on any payment or bank-detail change from this email. Confirm it by calling a number you already trust.', 'Pause any related payment that has not yet been released.'] }]
        : []),
    ],
  };

  const notify: Section = {
    id: 'notify',
    title: 'Who to tell',
    part: 'executive',
    blocks: [
      { t: 'ul', items: ['Your internal IT or security team (first, always).', 'Anti-Phishing Working Group (APWG): reportphishing@apwg.org', 'Netcraft: scam@netcraft.com, for takedown of the fake sites', 'Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/', 'United States: https://reportfraud.ftc.gov and https://www.ic3.gov', 'United Kingdom: report@phishing.gov.uk (NCSC)', 'India: https://cybercrime.gov.in and incident@cert-in.org.in (CERT-In)', 'Elsewhere: your national CERT or cybercrime reporting centre. Serious losses should also be reported to the police and the bank.'] },
      { t: 'p', small: true, text: 'Unmask never sends anything by itself. Every report above is something a person chooses to send.' },
    ],
  };

  const limits = limitations(report);
  const confidence: Section = {
    id: 'confidence',
    title: 'How sure are we?',
    part: 'executive',
    blocks: [{ t: 'p', text: confidenceText(report) }, ...(limits.length ? [{ t: 'p' as const, text: 'Things the automatic checks could not look at:' }, { t: 'ul' as const, items: limits.slice(0, 5) }] : [])],
  };
  return [glance, happened, impact, actions, notify, confidence];
}

/* -------------------------------------------------------- technical part */

function fileSections(a: AttachmentInfo): Block[] {
  const f = a.forensics;
  const out: Block[] = [];
  out.push({ t: 'kv', rows: [['File name', defangText(a.filename)], ['Declared type', a.mimeType], ['Detected type', f ? f.magic.label : 'not analysed'], ['Size', `${a.size.toLocaleString()} bytes`], ['SHA-256', a.sha256], ...(f ? ([['SHA-1', f.hashes.sha1], ['MD5', f.hashes.md5], ['Entropy', `${f.entropy} / 8`]] as [string, string][]) : [])] });
  const flagRows = a.flags.map((fl) => [sevLabel(fl.severity), fl.label]);
  if (flagRows.length) out.push({ t: 'table', head: ['Severity', 'Finding'], rows: flagRows, widths: [16, 84], tones: a.flags.map((fl) => SEV_TONE[fl.severity]) });
  if (!f) return out;
  if (f.anomalies.length) {
    out.push({ t: 'h3', text: 'Structural findings (read on the analyst computer, never opened or run)' });
    out.push({ t: 'table', head: ['Severity', 'Finding', 'Where / detail', 'ATT&CK'], rows: f.anomalies.map((x: Anomaly) => [sevLabel(x.severity), x.title, cap([x.where, x.detail].filter(Boolean).join(' — '), 220), x.attack ?? '']), widths: [11, 33, 44, 12], tones: f.anomalies.map((x) => SEV_TONE[x.severity]) });
  }
  if (f.pdf) {
    const p = f.pdf;
    out.push({ t: 'h3', text: 'PDF structure (pdfid-style keyword counts)' });
    out.push({ t: 'table', head: ['Keyword', 'Count', 'Hidden in streams', 'Disguised (#xx)'], rows: p.id.filter((r) => r.count || r.hiddenInStreams || r.risk === 'danger').map((r) => [r.keyword, String(r.count), String(r.hiddenInStreams), String(r.obfuscated)]), widths: [34, 16, 26, 24], tones: p.id.filter((r) => r.count || r.hiddenInStreams || r.risk === 'danger').map((r) => (r.risk === 'danger' && (r.count || r.hiddenInStreams) ? 'bad' : undefined)) });
    out.push({ t: 'kv', rows: [['Version', p.version ?? '—'], ['Pages / objects', `${p.pages} / ${p.objects}`], ['Encrypted', p.encrypted ? 'yes' : 'no'], ['%%EOF markers / bytes after the last', `${p.eofCount} / ${p.bytesAfterEof}`], ['Entropy (total / in streams / outside)', `${p.entropy.total} / ${p.entropy.insideStreams} / ${p.entropy.outsideStreams}`], ['Object streams unpacked', String(p.objectStreamsUnpacked)], ...Object.entries(p.metadata).map(([k, v]): [string, string] => [`Metadata: ${k}`, v]), ['Page text (approximate)', p.textPreview || '—']] });
    for (const j of p.javascript) out.push({ t: 'code', text: `JavaScript in ${j.obj}, runs ${j.trigger}${j.indicators.length ? `\n// ${j.indicators.join('; ')}` : ''}\n${cap(j.preview, 700)}` });
    if (p.actions.length) out.push({ t: 'table', head: ['Action', 'Runs', 'Where', 'Target'], rows: p.actions.map((x) => [x.type, x.trigger, x.obj, defangText(x.target ?? '')]), widths: [16, 30, 22, 32] });
    if (p.embedded.length) out.push({ t: 'table', head: ['Embedded file', 'Type', 'Size', 'SHA-256'], rows: p.embedded.map((e) => [defangText(e.name), e.type, String(e.size), e.sha256]), widths: [20, 22, 10, 48], mono: [false, false, false, true] });
  }
  const macroInfo = f.ooxml?.macros ?? f.ole?.macros;
  if (macroInfo?.present) {
    out.push({ t: 'h3', text: 'Macros' });
    out.push({ t: 'kv', rows: [['Runs automatically', macroInfo.autoExec.join(', ') || 'no'], ['Capabilities', macroInfo.suspicious.join('; ') || 'none flagged'], ['Excel 4.0 macro sheets', macroInfo.xlmSheets.map((s) => `${s.name}${s.hidden !== 'visible' ? ` (${s.hidden})` : ''}`).join(', ') || 'none'], ['Obfuscation hints', `${macroInfo.obfuscation.chrCalls} Chr() calls, ${macroInfo.obfuscation.longStrings} very long strings, ${macroInfo.obfuscation.base64Blobs} base64-like blobs`]] });
    for (const m of macroInfo.modules.slice(0, 4)) out.push({ t: 'code', text: `Module ${m.name} (${m.length} characters)\n${cap(m.preview, 600)}` });
  }
  if (f.ooxml) {
    const o = f.ooxml;
    out.push({ t: 'kv', rows: [['Application type', o.app], ['Parts in package', String(o.parts)], ...Object.entries(o.metadata).map(([k, v]): [string, string] => [`Metadata: ${k}`, v]), ['Hidden sheets / slides', `${o.hiddenSheets.join(', ') || 'none'} / ${o.hiddenSlides}`], ['Lure phrases', o.lurePhrases.join(', ') || 'none'], ['Text (start)', o.textPreview || '—']] });
    if (o.externalRefs.length) out.push({ t: 'table', head: ['Loaded from outside the file', 'Part'], rows: o.externalRefs.slice(0, 25).map((r) => [`${r.type}: ${defangUrl(r.target)}`, r.part]), widths: [64, 36] });
    if (o.fields.length) out.push({ t: 'table', head: ['Field', 'Instruction'], rows: o.fields.slice(0, 20).map((x) => [x.type, cap(x.instr, 160)]), widths: [20, 80] });
  }
  if (f.ole) out.push({ t: 'kv', rows: [...Object.entries(f.ole.metadata).map(([k, v]): [string, string] => [`Metadata: ${k}`, v]), ['Streams', `${f.ole.streams.length}: ${f.ole.streams.slice(0, 12).map((s) => s.path.replace(/[\x00-\x1f]/g, '?')).join(', ')}`]] });
  if (f.rtf?.objects.length) out.push({ t: 'table', head: ['Embedded object', 'Detected as', 'Bytes'], rows: f.rtf.objects.map((o) => [o.cls || 'object', o.type, String(o.hexBytes)]), widths: [30, 50, 20] });
  if (f.zip) out.push({ t: 'table', head: ['File in the archive', 'Detected as', 'Size', 'Encrypted'], rows: f.zip.files.slice(0, 40).map((x) => [defangText(x.name), x.type ?? '—', String(x.size), x.encrypted ? 'yes' : 'no']), widths: [40, 34, 14, 12] });
  if (f.links.length) out.push({ t: 'table', head: ['Link found inside the file', 'Where', 'How it is used'], rows: f.links.slice(0, 40).map((l) => [defangUrl(l.url), cap(l.where, 60), l.how + (l.coversPage ? ' (covers whole page)' : '')]), widths: [52, 28, 20] });
  for (const c of f.children) out.push({ t: 'p', text: `Nested file ${defangText(c.path)}: ${c.forensics.magic.label}, ${c.forensics.anomalies.length} finding(s), worst ${worstOf(c.forensics)}. SHA-256 ${c.forensics.hashes.sha256}` });
  const iocs = f.iocs;
  const extra = [['Domains', iocs.domains], ['IP addresses', iocs.ips], ['Email addresses', iocs.emails], ['Programs/scripts named', iocs.executables], ['Commands', iocs.commands]] as [string, string[]][];
  const shown = extra.filter(([, v]) => v.length);
  if (shown.length) out.push({ t: 'kv', rows: shown.map(([k, v]): [string, string] => [k, cap(v.slice(0, 12).map(defangText).join(', '), 400)]) });
  return out;
}

function caseRows(report: Report, meta: ReportMeta, evidence: Evidence, now: Date, version: string): [string, string][] {
  const rows: [string, string][] = [
    ['Case ID', meta.caseId || autoCaseId(report, now)],
    ['Prepared by', meta.preparedBy || '—'],
    ['Organisation', meta.organisation || '—'],
    ['Classification (TLP)', meta.tlp ?? 'AMBER'],
    ['Generated', `${now.toISOString().replace('T', ' ').slice(0, 19)} UTC`],
    ['Tool', `${TOOL} ${version}`],
    ['Where analysis ran', 'On the analyst’s own computer, inside the browser. The email and its files were not sent to the tool’s author or to any server. Online lookups (if any, listed below) were started by the analyst and sent only a hash, a domain name or a link.'],
  ];
  if (evidence.emlSha256) rows.push(['Original message (.eml) SHA-256', evidence.emlSha256], ['Original message size', `${evidence.emlSize?.toLocaleString() ?? '?'} bytes`]);
  else rows.push(['Original message', 'Not saved with this report. Download the .eml from the Report card and keep it with the case.']);
  if (meta.notes) rows.push(['Analyst notes', meta.notes]);
  return rows;
}

function technicalSections(report: Report, meta: ReportMeta, evidence: Evidence, now: Date, version: string): Section[] {
  const { email, auth, forensics } = report;
  const verdict = VERDICT[report.verdict];
  const kinds = hypotheses(report);
  const files = docs(report);
  const sections: Section[] = [];
  const S = (id: string, title: string, blocks: Block[], lead?: string) => sections.push({ id, title, part: 'technical', blocks, lead });

  /* case information */
  S('case', 'Case information', [
    { t: 'kv', rows: caseRows(report, meta, evidence, now, version) },
    { t: 'p', small: true, text: 'Chain of custody: record who handled the original message and when. The hash above identifies the exact evidence analysed.' },
  ], 'For security analysts, incident responders and investigators.');

  /* verdict */
  const byCat = new Map<string, { n: number; points: number }>();
  for (const f of report.findings) {
    const c = byCat.get(f.category) ?? { n: 0, points: 0 };
    c.n++;
    c.points += f.points;
    byCat.set(f.category, c);
  }
  S('verdict', 'Verdict and scoring', [
    { t: 'callout', tone: verdict.tone, title: `${verdict.label}: risk score ${report.score}/100`, text: kinds.length ? `Assessment: ${kinds.map((k) => `${k.label} (${k.confidence})`).join('; ')}.` : 'No known attack pattern matched.' },
    { t: 'table', head: ['Category', 'Findings', 'Points'], rows: [...byCat.entries()].sort((a, b) => b[1].points - a[1].points).map(([c, v]) => [c, String(v.n), String(v.points)]), widths: [50, 25, 25] },
    ...(kinds.length ? [{ t: 'table' as const, head: ['Attack type', 'Confidence', 'Meaning', 'Evidence (finding ids)'], rows: kinds.map((k) => [k.label, k.confidence, k.meaning, k.evidence.slice(0, 6).join(', ')]), widths: [20, 12, 40, 28] }] : []),
    { t: 'p', small: true, text: 'Scoring: findings add points by severity (critical 35-40, high about 20, medium about 10, low about 4); reassuring signals subtract. 20 and above is Suspicious, 50 and above is High risk.' },
  ]);

  /* message and sender */
  S('message', 'Message and sender analysis', [
    { t: 'kv', rows: [['Subject', email.subject || '—'], ['From (display name / address)', email.from ? `${email.from.name || '—'} / ${defangText(email.from.address)}` : 'missing'], ['Sender header', email.sender ? defangText(email.sender.address) : '—'], ['Reply-To', email.replyTo.map((r) => defangText(r.address)).join(', ') || '—'], ['Return-Path', email.returnPath ? defangText(email.returnPath) : '—'], ['To', email.to.map((t) => defangText(t.address)).join(', ') || '—'], ['Date', email.date ? `${niceDate(email.date)} (header: ${email.date})` : '—'], ['Message-ID', email.messageId ?? '—'], ['Sender domain', email.from?.domain ? defangText(email.from.domain) : '—']] },
    ...tableOfFindings(findingsOf(report, 'sender')),
  ]);

  /* authentication */
  S('authentication', 'Authentication (SPF, DKIM, DMARC, ARC)', [
    { t: 'table', head: ['Check', 'Result', 'Domain', 'Meaning'], rows: [['SPF', auth.spf, auth.spfDomain ?? '—', 'Was the sending server allowed to send for this domain?'], ['DKIM', auth.dkim, auth.dkimDomains.join(', ') || '—', 'Is there a valid cryptographic signature from the domain?'], ['DMARC', auth.dmarc, auth.dmarcDomain ?? '—', 'Does the visible From domain match what SPF or DKIM verified?']], widths: [14, 16, 30, 40], tones: [auth.spf, auth.dkim, auth.dmarc].map((r) => (r === 'pass' ? 'good' : r === 'fail' || r === 'softfail' ? 'bad' : 'warn')) },
    { t: 'p', small: true, text: `Provider verdict from ${auth.server ?? 'the receiving server'}. Unmask also re-checks DKIM body hashes locally.` },
    ...(forensics.dkim.length ? [{ t: 'table' as const, head: ['Signing domain', 'Selector', 'Algorithm', 'Body hash', 'Signature', 'Signed', 'Expires'], rows: forensics.dkim.map((d) => [d.domain, d.selector, `${d.algorithm}${d.keyBits ? ` ${d.keyBits}-bit` : ''}`, d.bodyHash, d.signature ?? 'not verified', utc(d.signedAt), utc(d.expiresAt)]), widths: [20, 10, 16, 12, 14, 15, 13] }] : []),
    ...(forensics.arc.length ? [{ t: 'table' as const, head: ['ARC set', 'Added by', 'Chain status', 'Results'], rows: forensics.arc.map((a) => [String(a.instance), a.domain, a.cv, Object.entries(a.results).map(([k, v]) => `${k}=${v}`).join(' ')]), widths: [10, 26, 16, 48] }] : []),
    ...(forensics.arcProblem ? [{ t: 'callout' as const, tone: 'warn' as const, title: 'ARC problem', text: forensics.arcProblem }] : []),
    ...tableOfFindings(findingsOf(report, 'auth')),
  ]);

  /* delivery path */
  if (forensics.hops.length) {
    S('delivery', 'Delivery path (origin first)', [
      { t: 'table', head: ['#', 'Server announced (HELO / rDNS)', 'IP', 'Received by', 'Protocol', 'Time', 'Delay', 'Trust'], rows: forensics.hops.map((h) => [String(h.n), defangText(h.helo ?? h.rdns ?? 'unknown'), h.ip ? defangText(h.ip) : '—', defangText(h.by ?? '?'), h.protocol ?? '—', utc(h.time), h.delaySec === null ? '—' : `${h.delaySec}s`, h.trusted ? 'your provider' : 'unverifiable']), widths: [4, 24, 14, 20, 9, 14, 6, 9] },
      { t: 'kv', rows: [['Origin IP', forensics.originIp ? defangText(forensics.originIp) : 'not determined'], ...(forensics.sender ? ([['Delivering network', [forensics.sender.network, forensics.sender.asn && `AS${forensics.sender.asn}`, forensics.sender.country].filter(Boolean).join(', ') || '—']] as [string, string][]) : [])] },
      { t: 'p', small: true, text: 'Only the hops written by your own mail provider can be trusted. Hops below the first trusted one were written by servers you cannot check, possibly including the sender.' },
    ]);
  }

  /* content */
  S('content', 'Content analysis', [
    ...(report.hidden.length ? [{ t: 'table' as const, head: ['Hidden text', 'How it is hidden'], rows: report.hidden.slice(0, 15).map((h) => [cap(h.text, 200), h.reason]), widths: [65, 35] }] : [{ t: 'p' as const, text: 'No hidden text found.' }]),
    ...(report.qrCodes.length ? [{ t: 'table' as const, head: ['QR code found in', 'Decoded content'], rows: report.qrCodes.map((q) => [q.origin, /^https?:/i.test(q.text) ? defangUrl(q.text) : q.text]), widths: [30, 70] }] : []),
    ...(report.trackers.pixels.length ? [{ t: 'table' as const, head: ['#', 'Tracker', 'Host', 'Size', 'Position'], rows: report.trackers.pixels.map((p) => [String(p.n), p.service ?? 'unknown', defangText(p.host), p.size ?? '—', `${p.positionPct}% through the text, image ${p.imageIndex} of ${p.imageCount}`]), widths: [5, 22, 30, 10, 33] }] : []),
    ...tableOfFindings(findingsOf(report, 'content', 'privacy')),
  ]);

  /* links */
  const linkRows = report.links.filter((l) => l.source !== 'attachment').concat(report.links.filter((l) => l.source === 'attachment'));
  S('links', `Link analysis (${report.links.length})`, [
    linkRows.length
      ? { t: 'table', head: ['#', 'Shown as', 'Real destination', 'Source', 'Findings'], rows: linkRows.slice(0, 80).map((l, i) => [String(i + 1), cap(l.text || '—', 40), defangUrl(cap(l.resolved, 160)), l.source === 'attachment' ? `file: ${l.origin ?? ''}` : l.source, l.flags.map((f) => f.label).join('; ') || '—']), widths: [4, 18, 36, 12, 30], tones: linkRows.slice(0, 80).map((l) => SEV_TONE[worstFlag(l)]) }
      : { t: 'p', text: 'The email contains no links.' },
    ...(report.links.some((l) => l.unwrappedVia.length) ? [{ t: 'p' as const, small: true, text: 'Redirect wrappers (such as Google or Microsoft safe-link redirects) were peeled off locally to show the real destination.' }] : []),
  ]);

  /* attachments */
  S('attachments', `Attachment and file forensics (${files.length})`, files.length
    ? files.flatMap((a): Block[] => [{ t: 'h3', text: `${defangText(a.filename)} (${a.forensics ? a.forensics.magic.label : a.mimeType})` }, ...fileSections(a)])
    : [{ t: 'p', text: 'The email has no attachments.' }]);

  /* intel */
  const intel = intelFindingsOf(report);
  S('intel', 'Threat-intelligence lookups', intel.length
    ? [{ t: 'table', head: ['Result', 'Detail'], rows: intel.map((f) => [`${sevLabel(f.severity)}: ${f.title}`, cap(f.detail ?? '', 240)]), widths: [50, 50], tones: intel.map((f) => SEV_TONE[f.severity]) }, { t: 'p', small: true, text: 'Lookups send only a file hash, a domain or a link and run only when the analyst clicks. Files are never uploaded. “No record” means unknown, not safe.' }]
    : [{ t: 'p', text: 'No online lookups were run for this report. Hash, link and domain lookups (VirusTotal, Hybrid Analysis, MalwareBazaar, urlscan.io, URLhaus, PhishTank) can be started from the Documents and Links tabs; their results are included here once run.' }]);

  /* ATT&CK */
  const tech = techniques(report);
  if (tech.length) S('attack', 'MITRE ATT&CK mapping', [{ t: 'table', head: ['Technique', 'Name', 'Evidence'], rows: tech.map((t) => [t.id, ATTACK_NAMES[t.id] ?? '', t.evidence.join('; ')]), widths: [14, 36, 50] }, { t: 'p', small: true, text: 'Mapped from observed behaviour only. See https://attack.mitre.org/ for definitions.' }]);

  /* timeline */
  const events: { at: number; what: string }[] = [];
  const dateMs = email.date ? Date.parse(email.date) : NaN;
  if (!Number.isNaN(dateMs)) events.push({ at: dateMs, what: 'Date header on the email' });
  for (const d of forensics.dkim) if (d.signedAt) events.push({ at: d.signedAt, what: `Signed by ${d.domain} (DKIM)` });
  for (const h of forensics.hops) if (h.time) events.push({ at: h.time, what: `Hop ${h.n}: received by ${h.by ?? '?'}${h.trusted ? ' (your provider)' : ''}` });
  events.sort((a, b) => a.at - b.at);
  if (events.length) S('timeline', 'Timeline', [{ t: 'table', head: ['Time (UTC)', 'Event'], rows: events.map((e) => [utc(e.at), e.what]), widths: [28, 72] }]);

  /* IOCs */
  const iocs = collectIocs(report);
  const LABEL: Record<IocType, string> = { sender: 'sender address', 'reply-to': 'reply-to', 'return-path': 'return-path', 'origin-ip': 'origin IP', 'dkim-domain': 'DKIM domain', url: 'URL', domain: 'domain', 'file-ip': 'IP address in files', 'file-email': 'email address in files', 'file-url': 'URL in files', program: 'program or script named', command: 'command', filename: 'file name', sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5', phone: 'phone number' };
  const shown = (i: Ioc) => (i.type === 'url' || i.type === 'file-url' ? defangUrl(i.value) : ['sha256', 'sha1', 'md5', 'phone'].includes(i.type) ? i.value : i.type === 'command' ? cap(i.value, 160) : defangText(i.value));
  const iocRows = iocs.map((i) => [LABEL[i.type], shown(i)]);
  S('iocs', `Indicators of compromise (${iocRows.length})`, [iocRows.length ? { t: 'table', head: ['Type', 'Value (defanged: safe to paste)'], rows: iocRows, widths: [24, 76], mono: [false, true] } : { t: 'p', text: 'No indicators to block.' }, { t: 'p', small: true, text: 'Defanged values replace "." with "[.]" and "http" with "hxxp" so they cannot be clicked by accident. The STIX and JSON exports carry the exact values for tools.' }]);

  /* detection */
  const ind = indicators(report, 100);
  const sd = ind.senderDomain;
  const hashes = [...new Set(files.map((a) => a.sha256))];
  const rawUrls = ind.urls.slice(0, 5);
  S('detection', 'Detection and hunting suggestions', [
    { t: 'p', small: true, text: 'Queries contain real values for pasting into your tools. Do not open them in a browser.' },
    ...(sd ? [{ t: 'code' as const, text: `// Microsoft Defender / Sentinel (KQL)\nEmailEvents\n| where SenderFromDomain == "${sd}" or SenderMailFromDomain == "${sd}"\n| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction` }] : []),
    ...(rawUrls.length ? [{ t: 'code' as const, text: `// Microsoft Defender / Sentinel (KQL): who received these links\nEmailUrlInfo\n| where Url in~ (${rawUrls.map((u) => `"${u}"`).join(', ')})\n| join EmailEvents on NetworkMessageId` }] : []),
    ...(hashes.length ? [{ t: 'code' as const, text: `// Attachments with these hashes\nEmailAttachmentInfo\n| where SHA256 in~ (${hashes.map((h) => `"${h}"`).join(', ')})` }] : []),
    ...(sd ? [{ t: 'code' as const, text: `# Google Workspace / Gmail search (Admin console email log search or Vault)\nfrom:(${sd})${email.messageId ? `\nrfc822msgid:${email.messageId.replace(/[<>]/g, '')}` : ''}` }] : []),
    { t: 'ul', items: ['Add the sender, Reply-To and the domains above to your mail gateway block list.', 'Add the URLs and domains to web proxy and DNS filtering.', 'Add the file hashes to endpoint protection block lists.', 'Search mail logs for other messages with the same sender infrastructure, subject pattern or Message-ID domain.'] },
  ]);

  /* remediation */
  S('response', 'Containment and remediation checklist', [
    { t: 'checklist', items: ['Preserve the original message (.eml) and this report before deleting anything.', 'Identify every recipient (mail logs) and who clicked or opened attachments (proxy, DNS and endpoint logs).', 'Purge the message from all mailboxes and quarantine matching ones.', 'Block the sender, domains, URLs and hashes listed above.', ...(kinds.some((k) => ['credential-phishing', 'consent', 'account-takeover'].includes(k.kind)) ? ['For affected users: reset passwords, revoke sessions and refresh tokens, review OAuth app consents, MFA methods, mailbox rules, forwarding and delegates.'] : []), ...(files.some((a) => a.flags.some((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.high)) ? ['For anyone who opened the attachment: isolate the device, run an endpoint scan, collect a triage image and review for persistence.'] : []), ...(kinds.some((k) => k.kind === 'payment-fraud') ? ['Verify any related payment by phone with a known number; ask the bank to recall funds if money moved.'] : []), 'Report externally (APWG, Netcraft, national CERT) and notify any impersonated brand.', 'Run a short awareness note to staff with the key signs from this email.', 'Record the outcome and close the case.'] },
  ]);

  /* limitations & method */
  const lim = limitations(report);
  S('method', 'Method, limits and references', [
    { t: 'h3', text: 'What was checked' },
    { t: 'ul', items: ['Sender identity, header consistency and authentication (SPF, DKIM, DMARC, ARC), including a local DKIM body-hash re-check.', 'Delivery path and timing from Received headers.', 'Links: real destinations, lookalike domains, redirects, hosting services, QR codes.', 'Body: hidden text, obfuscation, urgency and payment language, tracking pixels.', 'Attachments: file type by content, structure of PDFs, Office files, RTF and archives, macros, embedded files, links and indicators, hashes.'] },
    ...(lim.length ? [{ t: 'h3' as const, text: 'Not checked' }, { t: 'ul' as const, items: lim }] : []),
    { t: 'h3', text: 'References and credits' },
    { t: 'ul', items: ['File analysis follows the ideas of Didier Stevens’ pdfid.py, pdf-parser.py, oledump.py, rtfdump.py and zipdump.py (https://github.com/DidierStevens/DidierStevensSuite), reimplemented in TypeScript for the browser. Source code was not copied.', 'MITRE ATT&CK: https://attack.mitre.org/', 'SPF RFC 7208, DKIM RFC 6376, DMARC RFC 7489, ARC RFC 8617.', 'Anti-Phishing Working Group: https://apwg.org/ · Netcraft: https://www.netcraft.com/', 'Traffic Light Protocol: https://www.first.org/tlp/'] },
    { t: 'p', small: true, text: 'Automated analysis supports, but does not replace, human judgement. Unknown or “no record” results never mean a file or link is safe.' },
  ]);

  /* appendix */
  sections.push({
    id: 'appendix-findings',
    title: 'Appendix A: all findings',
    part: 'appendix',
    blocks: [{ t: 'table', head: ['Severity', 'Points', 'Category', 'Finding'], rows: report.findings.map((f) => [sevLabel(f.severity), String(f.points), f.category, cap(f.title + (f.detail ? ` — ${f.detail}` : ''), 300)]), widths: [11, 8, 13, 68], tones: report.findings.map((f) => SEV_TONE[f.severity]) }],
  });
  sections.push({
    id: 'appendix-headers',
    title: 'Appendix B: message headers',
    part: 'appendix',
    blocks: [{ t: 'code', text: cap(email.headers.map((h) => `${h.name}: ${h.value.replace(/\s+/g, ' ')}`).join('\n'), 24000) }],
  });
  sections.push({
    id: 'appendix-glossary',
    title: 'Appendix C: glossary',
    part: 'appendix',
    blocks: [{ t: 'table', head: ['Term', 'Meaning'], rows: [['SPF', 'A list published by a domain of the servers allowed to send its email.'], ['DKIM', 'A digital signature added by the sending domain, proving the message was not changed.'], ['DMARC', 'A policy tying SPF and DKIM to the visible From address.'], ['ARC', 'A record that preserves authentication results when email is forwarded.'], ['IOC', 'Indicator of compromise: a fact (address, domain, hash) that identifies an attack.'], ['Hash (SHA-256)', 'A fingerprint of a file. The same file always has the same hash; sharing it reveals nothing about the content.'], ['Entropy', 'How random a file’s bytes look. Near 8 suggests encrypted or packed data.'], ['Macro', 'A small program inside an Office file that can run when you click Enable Content.'], ['Defanged', 'Rewritten (hxxp, [.]) so a link or address cannot be clicked by accident.'], ['TLP', 'Traffic Light Protocol: how widely the report may be shared (CLEAR, GREEN, AMBER, RED).']], widths: [24, 76] }],
  });
  return sections;
}

function tableOfFindings(fs: Finding[]): Block[] {
  if (!fs.length) return [];
  return [{ t: 'table', head: ['Severity', 'Finding'], rows: fs.map((f) => [sevLabel(f.severity), cap(f.title + (f.detail ? ` — ${f.detail}` : ''), 300)]), widths: [14, 86], tones: fs.map((f) => SEV_TONE[f.severity]) }];
}

/* ------------------------------------------------------------------ build */

export function buildCaseReport(report: Report, opts: { version: string; now?: Date; meta?: ReportMeta; audience?: Audience; evidence?: Evidence } = { version: 'dev' }): CaseDoc {
  const now = opts.now ?? new Date();
  const meta = opts.meta ?? {};
  const audience = opts.audience ?? 'both';
  const evidence = opts.evidence ?? {};
  const verdict = VERDICT[report.verdict];
  const sections: Section[] = [];
  if (audience !== 'technical') sections.push(...executiveSections(report, now));
  if (audience !== 'executive') sections.push(...technicalSections(report, meta, evidence, now, opts.version));
  return {
    title: 'Unmask email report',
    subtitle: report.email.subject || '(no subject)',
    generatedAt: now.toISOString(),
    tool: TOOL,
    version: opts.version,
    verdict: { label: verdict.label, tone: verdict.tone, score: report.score },
    meta: [['Case ID', meta.caseId || autoCaseId(report, now)], ['Classification', `TLP:${meta.tlp ?? 'AMBER'}`], ['Prepared by', [meta.preparedBy, meta.organisation].filter(Boolean).join(', ') || '—'], ['Generated', `${now.toISOString().replace('T', ' ').slice(0, 16)} UTC`]],
    tlp: meta.tlp ?? 'AMBER',
    sections,
    evidence,
  };
}

/** Plain-text rendering of the model: used by tests and for a quick copy. */
export function docText(doc: CaseDoc): string {
  const out: string[] = [doc.title, doc.subtitle, ''];
  for (const s of doc.sections) {
    out.push(`## ${s.title}`);
    for (const b of s.blocks) {
      if (b.t === 'p' || b.t === 'h3' || b.t === 'code') out.push(b.text);
      else if (b.t === 'ul' || b.t === 'checklist') out.push(...b.items.map((i) => `- ${i}`));
      else if (b.t === 'kv') out.push(...b.rows.map(([k, v]) => `${k}: ${v}`));
      else if (b.t === 'table') out.push(b.head.join(' | '), ...b.rows.map((r) => r.join(' | ')));
      else out.push(`${b.title}: ${b.text}`);
    }
    out.push('');
  }
  return out.join('\n');
}
