/**
 * Sender history: who normally emails this user. Kept only in this browser
 * (extension storage), never sent anywhere. Everything here is pure so it can
 * be tested and run in both the side panel and the Gmail content script.
 */
import type { Finding, ParsedEmail } from '../core/types';
import { brandsMentionedIn, FREE_MAIL_DOMAINS, isBrandDomain, senderClaim, type Brand } from './brands';
import { detectLookalike } from './lookalike';
import { registrableDomain } from '../lib/domain';
import { addTraits, fingerprintFindings, type SenderTraits, type TraitCounts } from './fingerprint';

export interface SenderRecord {
  address: string;
  /** Last display name seen for this address. */
  name: string;
  /** Registrable domain (eTLD+1) of the address. */
  domain: string;
  count: number;
  firstSeen: number;
  lastSeen: number;
  /** Recent message keys, so re-opening the same email doesn't count twice. */
  ids: string[];
  /** How this sender's emails are usually signed, routed and built. Missing in histories from before fingerprints. */
  traits?: TraitCounts;
}

export interface SenderHistory {
  senders: Record<string, SenderRecord>;
}

export const EMPTY_HISTORY: SenderHistory = { senders: {} };

/** Below this many known senders the history is too thin for "first contact" to mean anything. */
export const LEARNING_THRESHOLD = 10;
const MAX_SENDERS = 5000;
const MAX_IDS = 20;

/** A stable key for one email, even when it has no Message-ID. */
export function emailKey(email: ParsedEmail): string {
  return email.messageId ?? `${email.from?.address ?? ''}|${email.date ?? ''}|${email.subject}`;
}

/** Display names compared loosely: case, punctuation and "Last, First" order don't matter. */
export function normalizeName(name: string): string {
  const words = name
    .toLowerCase()
    .replace(/["'()<>]/g, ' ')
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .trim()
    .split(' ')
    .filter(Boolean);
  return words.sort().join(' ');
}

/** Adds this email's sender to the history. Returns a new object; the input is not changed. */
export function recordSender(history: SenderHistory, email: ParsedEmail, now = Date.now(), traits?: SenderTraits): SenderHistory {
  const from = email.from;
  if (!from?.address) return history;
  const address = from.address.toLowerCase();
  const key = emailKey(email);
  const prev = history.senders[address];
  if (prev?.ids.includes(key)) return history;
  const rec: SenderRecord = prev
    ? { ...prev, name: from.name || prev.name, count: prev.count + 1, lastSeen: now, ids: [...prev.ids, key].slice(-MAX_IDS) }
    : { address, name: from.name, domain: registrableDomain(from.domain), count: 1, firstSeen: now, lastSeen: now, ids: [key] };
  if (traits) rec.traits = addTraits(prev?.traits, traits);
  const senders = { ...history.senders, [address]: rec };
  const keys = Object.keys(senders);
  if (keys.length > MAX_SENDERS) {
    // Forget the senders not heard from for the longest time.
    keys
      .sort((a, b) => senders[a]!.lastSeen - senders[b]!.lastSeen)
      .slice(0, keys.length - MAX_SENDERS)
      .forEach((k) => delete senders[k]);
  }
  return { senders };
}

/** How many earlier emails (not counting this one) came from a record. */
function priorCount(rec: SenderRecord | undefined, key: string): number {
  if (!rec) return 0;
  return rec.count - (rec.ids.includes(key) ? 1 : 0);
}

function monthYear(ts: number): string {
  return new Date(ts).toLocaleDateString('en', { month: 'short', year: 'numeric' });
}

/** Brands this sender appears to claim: from its display name, or a domain imitating one. */
function claimedBrands(email: ParsedEmail): Brand[] {
  const from = email.from!;
  const out = brandsMentionedIn(senderClaim(from.name, from.domain));
  const look = detectLookalike(from.domain);
  if (look && !out.includes(look.brand)) out.push(look.brand);
  return out;
}

export function historyFindings(email: ParsedEmail, history: SenderHistory, traits?: SenderTraits): Finding[] {
  const from = email.from;
  if (!from?.address) return [];
  const findings: Finding[] = [];
  const key = emailKey(email);
  const address = from.address.toLowerCase();
  const domain = registrableDomain(from.domain);
  const all = Object.values(history.senders);
  const learning = all.filter((r) => r.address !== address).length < LEARNING_THRESHOLD;
  const target = { kind: 'sender' } as const;

  const prior = priorCount(history.senders[address], key);
  const domainPrior = all.filter((r) => r.domain === domain).reduce((n, r) => n + priorCount(r, key), 0);

  // 1. "Your PayPal emails usually come from paypal.com."
  for (const brand of claimedBrands(email)) {
    if (isBrandDomain(brand, domain)) continue;
    const usual = new Map<string, number>();
    for (const r of all) if (r.address !== address && isBrandDomain(brand, r.domain)) usual.set(r.domain, (usual.get(r.domain) ?? 0) + r.count);
    const [usualDomain, n] = [...usual].sort((a, b) => b[1] - a[1])[0] ?? [];
    if (usualDomain) {
      findings.push({
        id: 'history-brand-mismatch',
        category: 'sender',
        severity: 'high',
        points: 25,
        target,
        title: `Your ${brand.name} emails usually come from ${usualDomain}`,
        detail: `You've received ${n} email${n === 1 ? '' : 's'} from ${usualDomain}. This one is from ${domain}${domainPrior === 0 ? ', which has never emailed you before' : ''}.`,
      });
      break;
    }
  }

  // 2. Display name matches someone you know, from a different address.
  const name = normalizeName(from.name);
  if (name.length >= 5 && !brandsMentionedIn(from.name).length) {
    const contact = all
      .filter((r) => r.address !== address && r.domain !== domain && priorCount(r, key) >= 2 && normalizeName(r.name) === name)
      .sort((a, b) => b.count - a.count)[0];
    if (contact) {
      const free = FREE_MAIL_DOMAINS.has(domain);
      findings.push({
        id: 'contact-impersonation',
        category: 'sender',
        severity: 'high',
        points: free ? 30 : 25,
        target,
        title: `Uses the name of your contact ${contact.name}, from a different address`,
        detail: `${contact.name} normally writes from ${contact.address} (${contact.count} emails). This came from ${from.address}. Confirm with them another way before acting on it.`,
      });
    }
  }

  // 3. First contact / known sender.
  if (prior === 0 && domainPrior === 0) {
    if (!learning) {
      const strong = findings.length > 0;
      findings.push({
        id: 'first-contact',
        category: 'sender',
        severity: strong ? 'medium' : 'low',
        points: strong ? 10 : 5,
        target,
        title: `You've never received mail from ${domain}`,
        detail: 'First emails from an unknown sender deserve extra care, especially if they ask you to log in, pay or open a file.',
      });
    } else {
      findings.push({ id: 'first-contact', category: 'sender', severity: 'info', points: 0, target, title: 'Unmask is still learning who normally emails you', detail: `It has seen ${all.length} sender${all.length === 1 ? '' : 's'} so far. First-contact warnings start after ${LEARNING_THRESHOLD}. This list stays on your device.` });
    }
  } else if (prior === 0) {
    findings.push({ id: 'first-contact', category: 'sender', severity: 'info', points: 0, target, title: `First email from this address, but you know ${domain}`, detail: `You've had ${domainPrior} earlier email${domainPrior === 1 ? '' : 's'} from other addresses at ${domain}.` });
  }

  // 4. A known sender whose emails are suddenly built or sent differently.
  const drift = traits ? fingerprintFindings(address, history.senders[address]?.traits, traits) : [];
  findings.push(...drift);

  if (prior >= 3 && !findings.length) {
    const rec = history.senders[address]!;
    findings.push({ id: 'known-sender', category: 'sender', severity: 'good', points: -5, target, title: `You've had ${prior} emails from this sender`, detail: `Since ${monthYear(rec.firstSeen)}. Senders you hear from often are less likely to be impostors, but accounts do get hacked.` });
  }

  return findings;
}
