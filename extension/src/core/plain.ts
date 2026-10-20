/**
 * "Explain it like I'm five": one short, friendly verdict for people who
 * don't want SPF, DKIM or redirect chains. Built only from the findings the
 * analyzers already produced, so it never says more than the evidence.
 */
import type { Finding, Report } from './types';
import { brandsMentionedIn } from '../analyzers/brands';
import { detectLookalike } from '../analyzers/lookalike';

export interface PlainSummary {
  /** One sentence: what this email is. */
  headline: string;
  /** Up to three reasons, each a short everyday sentence. */
  reasons: string[];
  /** What to do now. */
  action: string;
}

function claimedBrand(report: Report): string | null {
  const from = report.email.from;
  if (!from) return null;
  return brandsMentionedIn(from.name)[0]?.name ?? detectLookalike(from.domain)?.brand.name ?? null;
}

/** An everyday sentence for a finding, or null if it isn't worth saying to a non-expert. */
export function plainReason(f: Finding, report: Report): string | null {
  const brand = claimedBrand(report);
  const id = f.id;
  if (id === 'protected-contact') return f.plain ?? 'It pretends to be someone you know, but it isn’t from their real address.';
  if (id === 'protected-brand' || id === 'protected-lookalike') return f.plain ?? 'It pretends to be a company you use, but that company didn’t send it.';
  if (id === 'protected-link-lookalike') return 'A link leads to a fake copy of a website you use.';
  if (id === 'trusted-spoof') return 'It uses the address of someone you trust, but it wasn’t really sent by them.';
  if (id === 'contact-impersonation') return 'It uses the name of someone you know, from an address they don’t use.';
  if (id === 'sender-lookalike' || id === 'brand-impersonation' || id === 'history-brand-mismatch' || id.startsWith('fake-logo-')) {
    return brand ? `It pretends to be ${brand}, but ${brand} didn’t send it.` : 'The sender is pretending to be someone else.';
  }
  if (id === 'display-name-email') return 'The sender’s name hides a different email address.';
  if (id === 'freemail-org') return 'It claims to be a company but comes from a free personal email account.';
  if (id === 'reply-to-mismatch') {
    const to = report.email.replyTo.find((r) => r.address)?.address;
    return to ? `If you reply, your answer goes to ${to}, not to the address it came from.` : 'If you reply, your answer goes to a different address than the one it came from.';
  }
  if (id === 'dmarc-fail') return 'Its sender address could not be confirmed as real.';
  if (id === 'link-lookalike' || id === 'link-brand-in-domain') return 'A link leads to a fake website made to look like a real one.';
  if (id === 'link-text-mismatch') return 'A link says one website but really goes to another.';
  if (id === 'link-dangerous-scheme' || id === 'link-userinfo' || id === 'link-ip-host') return 'A link is built to trick you about where it goes.';
  if (id === 'link-shortener') return 'A link hides where it really goes.';
  if (id === 'qr-code') return 'It asks you to scan a QR code, which hides where it leads.';
  if (id === 'html-form') return 'It asks you to type a password or details right inside the email.';
  if (id === 'credential-request') return 'It asks you to log in or confirm your account details.';
  if (id === 'urgency') return 'It tries to rush or scare you into acting fast.';
  if (id === 'bec-bank-change') return 'It says bank details have changed, a common way to steal payments.';
  if (id === 'bec-gift-card') return 'It asks you to buy gift cards, which is always a scam.';
  if (id === 'bec-payment' || id === 'bec-pattern') return 'It asks you to send money.';
  if (id.startsWith('attachment-') && (f.severity === 'high' || f.severity === 'critical')) return 'It has an attached file that could harm your computer.';
  if (id.startsWith('cert-') || id.startsWith('age-')) return f.severity === 'high' || f.severity === 'medium' ? 'It comes from, or links to, a website that was set up only days ago.' : null;
  if (id === 'first-contact' && f.points > 0) return 'You have never received an email from this sender before.';
  if (id.startsWith('vt-') && f.points > 0) return 'Antivirus companies have flagged something in it as dangerous.';
  return null;
}

/** Findings that describe the same problem; only the most serious one is said. */
const SAME_PROBLEM: Record<string, string> = {
  'protected-link-lookalike': 'fake-site',
  'link-lookalike': 'fake-site',
  'link-brand-in-domain': 'fake-site',
  'protected-contact': 'impostor-person',
  'contact-impersonation': 'impostor-person',
  'bec-payment': 'money',
  'bec-pattern': 'money',
  'credential-request': 'login',
  'html-form': 'login',
};

export function plainSummary(report: Report): PlainSummary {
  const reasons: string[] = [];
  const said = new Set<string>();
  for (const f of report.findings) {
    if (f.points <= 0) continue;
    const r = plainReason(f, report);
    const group = SAME_PROBLEM[f.id] ?? r;
    if (!r || !group || said.has(group) || reasons.includes(r)) continue;
    said.add(group);
    reasons.push(r);
    if (reasons.length >= 3) break;
  }
  const trusted = report.findings.some((f) => f.id === 'trusted-sender');
  const known = report.findings.some((f) => f.id === 'known-sender');

  if (report.verdict === 'high') {
    return {
      headline: 'This email looks like a scam.',
      reasons: reasons.length ? reasons : ['Several things about it are typical of scam emails.'],
      action: 'Don’t click its links, don’t open its files and don’t reply. You can delete it or report it.',
    };
  }
  if (report.verdict === 'suspicious') {
    return {
      headline: 'Be careful with this email.',
      reasons: reasons.length ? reasons : ['Some things about it are unusual.'],
      action: 'Before you click anything or send money, check with the sender another way, such as a phone call or their official app.',
    };
  }
  return {
    headline: trusted ? 'This email is from a sender on your trusted list.' : reasons.length ? 'Nothing serious found. Worth knowing:' : 'Nothing looks wrong with this email.',
    reasons: reasons.length ? reasons : known ? ['You often get email from this sender.'] : [],
    action: 'That isn’t a guarantee. If it asks for money or a password out of the blue, double-check first.',
  };
}
