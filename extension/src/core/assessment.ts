/**
 * The analyst's conclusion on top of the individual findings: which kind of
 * attack the evidence points to, how strongly, and what couldn't be
 * checked. Built only from the findings and the report, so it never claims
 * more than the evidence.
 */
import type { Report } from './types';

export type AttackKind = 'spoofing' | 'impersonation' | 'credential-phishing' | 'malware' | 'payment-fraud' | 'callback' | 'replay' | 'account-takeover' | 'consent';

export interface Hypothesis {
  kind: AttackKind;
  label: string;
  /** What this attack does to you, in one sentence. */
  meaning: string;
  confidence: 'low' | 'medium' | 'high';
  /** Finding ids supporting it, strongest first. */
  evidence: string[];
}

const KINDS: { kind: AttackKind; label: string; meaning: string; match: (id: string) => boolean }[] = [
  { kind: 'replay', label: 'Replayed genuine email', meaning: 'A real, signed email re-sent by someone else so it passes authentication.', match: (id) => ['dkim-replay', 'replay-addressee', 'dkim-old-signature', 'arc-passed-earlier'].includes(id) },
  { kind: 'spoofing', label: 'Forged sender address', meaning: 'The From address is faked: the email did not come from where it says.', match: (id) => ['dmarc-fail', 'spf-fail', 'auth-results-forged', 'multiple-from', 'webmail-forged', 'trusted-spoof', 'dkim-body-altered'].includes(id) || id.startsWith('dkim-added-') || id.startsWith('dkim-verify-fail-') || id.startsWith('dkim-no-key-') },
  { kind: 'impersonation', label: 'Impersonation', meaning: 'It pretends to be a company or person you trust, from an address that isn\'t theirs.', match: (id) => ['display-name-email', 'sender-lookalike', 'brand-impersonation', 'freemail-org', 'history-brand-mismatch', 'contact-impersonation', 'protected-contact', 'protected-brand', 'protected-lookalike', 'disguised-from'].includes(id) || id.startsWith('fake-logo-') },
  { kind: 'credential-phishing', label: 'Password phishing', meaning: 'It wants you to sign in on a fake page or type your password.', match: (id) => ['html-form', 'credential-request', 'link-lookalike', 'link-text-mismatch', 'link-brand-in-domain', 'link-victim-email', 'link-userinfo', 'protected-link-lookalike', 'qr-code', 'image-only', 'attachment:phishing-page'].includes(id) },
  { kind: 'consent', label: 'Account access trick', meaning: 'It tries to make you approve an app or device that then gets into your account, with no password needed.', match: (id) => ['device-code-lure', 'oauth-consent-link'].includes(id) },
  { kind: 'malware', label: 'Malware delivery', meaning: 'It tries to get a harmful program onto your computer.', match: (id) => ['clickfix', 'archive-password-in-body', 'link-download', 'link-dangerous-scheme', 'attachment:malware'].includes(id) || id.startsWith('clickfix-attachment-') || id.startsWith('vt-') },
  { kind: 'callback', label: 'Callback scam', meaning: 'It wants you to phone "support", where the scam happens.', match: (id) => ['callback-phishing', 'platform-abuse'].includes(id) },
  { kind: 'payment-fraud', label: 'Payment fraud', meaning: 'It wants you to send money, change payment details or buy gift cards.', match: (id) => id.startsWith('bec-') || id === 'money-lure' },
  { kind: 'account-takeover', label: 'Possibly a hacked account', meaning: 'A sender you know, but sending differently than usual: their account may be in someone else\'s hands.', match: (id) => ['fingerprint-changed'].includes(id) },
];

const WEIGHT = { critical: 3, high: 2, medium: 1, low: 0.5, info: 0, good: 0 } as const;

/** Attachment findings are named after the file's hash; what kind of file it is decides the attack. */
const PHISHING_FILE_FLAGS = new Set(['html', 'html-credential', 'html-obfuscated', 'pdf-lure', 'pdf-submit', 'pdf-bad-link']);

function kindKey(report: Report, id: string): string {
  if (!id.startsWith('attachment-')) return id;
  const att = report.attachments.find((a) => id === `attachment-${a.sha256.slice(0, 12)}`);
  if (!att) return 'attachment:malware';
  const flags = att.flags.map((f) => f.id);
  return flags.length && flags.every((f) => PHISHING_FILE_FLAGS.has(f) || f === 'double-extension' || f === 'mime-mismatch') ? 'attachment:phishing-page' : 'attachment:malware';
}

export function hypotheses(report: Report): Hypothesis[] {
  const findings = report.findings;
  const out: Hypothesis[] = [];
  for (const k of KINDS) {
    const ev = findings.filter((f) => f.points > 0 && k.match(kindKey(report, f.id)));
    if (!ev.length) continue;
    const weight = ev.reduce((n, f) => n + WEIGHT[f.severity], 0);
    if (weight < 1) continue;
    out.push({ kind: k.kind, label: k.label, meaning: k.meaning, confidence: weight >= 3 ? 'high' : weight >= 2 ? 'medium' : 'low', evidence: ev.map((f) => f.id) });
  }
  const rank = { high: 3, medium: 2, low: 1 };
  return out.sort((a, b) => rank[b.confidence] - rank[a.confidence] || b.evidence.length - a.evidence.length);
}

/** What the checks could not see, so a clean result isn't read as a guarantee. */
export function limitations(report: Report): string[] {
  const out: string[] = [];
  if (!report.auth.raw) out.push('No authentication results: the email’s original headers were missing (a forwarded, pasted or Outlook page copy), so the sender couldn’t be verified. Paste the full message source for header checks.');
  const unverified = report.forensics.dkim.filter((d) => !d.signature || d.signature === 'error' || d.signature === 'unsupported');
  if (unverified.length) out.push(`${unverified.length === 1 ? 'A DKIM signature was' : `${unverified.length} DKIM signatures were`} not verified with the signer’s key${unverified.some((d) => !d.signature) ? ' (turn on “Check certificate history and mail records” in Settings)' : ''}.`);
  const untrusted = report.forensics.hops.filter((h) => !h.trusted).length;
  if (untrusted && report.forensics.hops.some((h) => h.trusted)) out.push(`${untrusted} delivery step${untrusted === 1 ? ' was' : 's were'} recorded before your provider received the email and can’t be verified.`);
  const web = report.links.filter((l) => /^https?:/i.test(l.resolved)).length;
  if (web) out.push(`${web} link${web === 1 ? ' was' : 's were'} checked by address only. What the page does is unknown until you run a sandbox scan from the Links tab.`);
  if (report.attachments.some((a) => !a.inline)) out.push('Files were read, not run. A sandbox or VirusTotal check (Files tab) can tell you more.');
  if (report.trackers.remoteImages) out.push('Remote images were not loaded, so text inside them wasn’t read.');
  return out;
}
