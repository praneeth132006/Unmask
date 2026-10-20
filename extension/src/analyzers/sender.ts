import type { Finding, ParsedEmail } from '../core/types';
import { brandsMentionedIn, FREE_MAIL_DOMAINS, isBrandDomain, senderClaim } from './brands';
import { detectLookalike } from './lookalike';
import { registrableDomain, sameOrg } from '../lib/domain';

const ORG_WORDS = /\b(support|security|billing|account|accounts|service|services|team|admin|administrator|helpdesk|help desk|it department|payroll|hr|bank|verification|compliance|notification|alert|customer care)\b/i;
const EMAIL_IN_TEXT = /[\w.+-]+@[\w-]+(\.[\w-]+)+/;

export function analyzeSender(email: ParsedEmail): Finding[] {
  const findings: Finding[] = [];
  const from = email.from;
  if (!from) {
    findings.push({ id: 'from-missing', category: 'sender', severity: 'medium', points: 10, title: 'The email has no valid From address' });
    return findings;
  }
  const fromOrg = registrableDomain(from.domain);

  // 1. Display name that contains a *different* email address: "PayPal <service@paypal.com>" <evil@x.xyz>
  const nameEmail = from.name.match(EMAIL_IN_TEXT)?.[0];
  if (nameEmail && nameEmail.toLowerCase() !== from.address.toLowerCase()) {
    findings.push({
      id: 'display-name-email',
      category: 'sender',
      severity: 'high',
      points: 25,
      title: 'Display name shows a different email address',
      detail: `The name says "${nameEmail}", but the email was really sent from ${from.address}.`,
    });
  }

  // 2. Lookalike sender domain (paypa1.com, pаypal.com with Cyrillic а, ...)
  const look = detectLookalike(from.domain);
  if (look) {
    const strong = look.kind === 'homoglyph' || look.kind === 'typo';
    findings.push({
      id: 'sender-lookalike',
      category: 'sender',
      severity: strong ? 'critical' : 'high',
      points: strong ? 35 : 20,
      title: `Sender domain imitates ${look.brand.name}`,
      detail: `${from.domain} ${look.explanation}.`,
    });
  }

  // 3. Display name claims a brand, but the domain isn't that brand's.
  const claimed = brandsMentionedIn(senderClaim(from.name, from.domain)).filter((b) => !isBrandDomain(b, fromOrg));
  const explainedByLookalike = look !== null && claimed.some((b) => b.name === look.brand.name);
  if (claimed.length && !explainedByLookalike) {
    findings.push({
      id: 'brand-impersonation',
      category: 'sender',
      severity: 'high',
      points: 25,
      title: `Claims to be ${claimed.map((b) => b.name).join(' / ')}, but isn't sent from their domain`,
      detail: `Sent from ${from.domain}. ${claimed[0]!.name} sends from ${claimed[0]!.domains.slice(0, 3).join(', ')}.`,
    });
  } else if (claimed.length) {
    // Already explained by the lookalike finding; still note the brand claim at low weight.
    findings.push({ id: 'brand-impersonation', category: 'sender', severity: 'medium', points: 10, title: `Display name uses the ${claimed[0]!.name} brand` });
  }

  // 4. Free webmail pretending to be an organisation.
  if (FREE_MAIL_DOMAINS.has(fromOrg) && (claimed.length || ORG_WORDS.test(from.name))) {
    findings.push({
      id: 'freemail-org',
      category: 'sender',
      severity: 'medium',
      points: 15,
      title: `"${from.name}" is writing from a free ${fromOrg} account`,
      detail: 'Real companies and IT departments do not send official notices from personal webmail.',
    });
  }

  // 5. Replies go somewhere else.
  const reply = email.replyTo.find((r) => r.domain && !sameOrg(r.domain, from.domain));
  if (reply) {
    const freemail = FREE_MAIL_DOMAINS.has(registrableDomain(reply.domain));
    findings.push({
      id: 'reply-to-mismatch',
      category: 'sender',
      severity: freemail ? 'high' : 'medium',
      points: freemail ? 20 : 12,
      title: 'Replies go to a different address',
      target: { kind: 'header', key: 'reply-to' },
      detail: `If you hit Reply, your answer goes to ${reply.address} instead of ${from.address}.`,
    });
  }

  // 6. Bounce address on an unrelated domain — common for mailing services, so low weight.
  const rpDomain = email.returnPath?.split('@')[1];
  if (rpDomain && !sameOrg(rpDomain, from.domain)) {
    findings.push({
      id: 'return-path-mismatch',
      category: 'sender',
      severity: 'low',
      points: 3,
      title: 'Bounce address is on a different domain',
      target: { kind: 'header', key: 'return-path' },
      detail: `Return-Path is ${email.returnPath}. Normal for newsletters sent through mailing services.`,
    });
  }

  // Everything else is about the From line.
  return findings.map((f) => ({ target: { kind: 'sender' } as const, ...f }));
}
