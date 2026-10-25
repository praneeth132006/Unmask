/**
 * Sender fingerprints: how a sender's emails are usually built and sent,
 * learned on this device. Analysts compare a suspicious email with a
 * known-good one from the same sender (relay, DKIM signer, Message-ID
 * format, mail program); this does that comparison automatically.
 */
import type { AuthSummary, DeliveryHop, Finding, ParsedEmail } from '../core/types';
import { getHeaders } from '../core/parse';
import { registrableDomain, sameOrg } from '../lib/domain';
import { entryHop } from './received';

export interface SenderTraits {
  /** Domains with a passing DKIM signature. */
  dkim: string[];
  /** Organisation of the server that handed the email to your provider. */
  route: string | null;
  /** Organisation in the Message-ID, e.g. github.com or gmail.com. */
  messageId: string | null;
  /** Mail program, first word of X-Mailer / User-Agent, lowercase. */
  mailer: string | null;
  /** Reply-To organisation when it differs from the From address. */
  replyTo: string | null;
}

/** Up to this many distinct values per trait, with how often each was seen. */
export type TraitCounts = Record<keyof SenderTraits, Record<string, number>>;

const MAX_VALUES = 6;
/** "none" stands for "no value" so a missing signature is remembered too. */
const NONE = 'none';

/** Null when the email has no real headers (Outlook's page view, a pasted body): nothing to compare. */
export function senderTraits(email: ParsedEmail, auth: AuthSummary, hops: DeliveryHop[]): SenderTraits | undefined {
  if (!auth.raw) return undefined;
  const from = email.from?.domain ?? '';
  const entry = entryHop(hops);
  const routeHost = entry?.rdns && entry.rdns !== 'unknown' ? entry.rdns : entry?.helo;
  const idDomain = email.messageId?.replace(/^<|>$/g, '').split('@')[1]?.replace(/>.*$/, '');
  const mailer = [...getHeaders(email, 'x-mailer'), ...getHeaders(email, 'user-agent')][0]?.trim().split(/[\s/(]+/)[0]?.toLowerCase();
  const reply = email.replyTo.find((r) => r.domain && !sameOrg(r.domain, from));
  return {
    dkim: [...new Set(auth.dkimDomains.map(registrableDomain))].sort(),
    route: routeHost && /[a-z]/i.test(routeHost) ? registrableDomain(routeHost) : null,
    messageId: idDomain ? registrableDomain(idDomain) : null,
    mailer: mailer || null,
    replyTo: reply ? registrableDomain(reply.domain) : null,
  };
}

function valueOf(traits: SenderTraits, k: keyof SenderTraits): string {
  const v = traits[k];
  return Array.isArray(v) ? v.join(',') || NONE : v ?? NONE;
}

export function addTraits(counts: TraitCounts | undefined, traits: SenderTraits): TraitCounts {
  const out = { dkim: {}, route: {}, messageId: {}, mailer: {}, replyTo: {}, ...structuredClone(counts ?? {}) } as TraitCounts;
  for (const k of Object.keys(out) as (keyof SenderTraits)[]) {
    const v = valueOf(traits, k);
    out[k][v] = (out[k][v] ?? 0) + 1;
    const entries = Object.entries(out[k]);
    if (entries.length > MAX_VALUES) delete out[k][entries.sort((a, b) => a[1] - b[1])[0]![0]];
  }
  return out;
}

const LABEL: Record<keyof SenderTraits, (v: string) => string> = {
  dkim: (v) => (v === NONE ? 'not signed' : `signed by ${v}`),
  route: (v) => (v === NONE ? 'an unknown server' : `sent through ${v}`),
  messageId: (v) => (v === NONE ? 'no Message-ID' : `Message-ID from ${v}`),
  mailer: (v) => (v === NONE ? 'no mail program named' : `written with ${v}`),
  replyTo: (v) => (v === NONE ? 'replies to the sender' : `replies to ${v}`),
};

/**
 * Compares this email with what the sender's earlier emails looked like.
 * Needs at least `minSeen` earlier emails, so one-off changes don't count.
 */
export function fingerprintFindings(address: string, counts: TraitCounts | undefined, traits: SenderTraits, minSeen = 3): Finding[] {
  if (!counts) return [];
  const seen = Object.values(counts.dkim).reduce((n, c) => n + c, 0);
  if (seen < minSeen) return [];
  const changed: string[] = [];
  let lostSignature = false;
  let newReplyTo = false;
  for (const k of Object.keys(LABEL) as (keyof SenderTraits)[]) {
    const v = valueOf(traits, k);
    const history = counts[k] ?? {};
    if (history[v]) continue;
    const usual = Object.entries(history).sort((a, b) => b[1] - a[1])[0];
    // Only traits that were consistent before: one usual value, seen in most emails.
    if (!usual || usual[1] < Math.ceil(seen * 0.75)) continue;
    if (k === 'mailer' && (v === NONE || usual[0] === NONE)) continue; // often dropped by forwarding and apps
    if (k === 'dkim' && v === NONE) lostSignature = true;
    if (k === 'replyTo' && usual[0] === NONE) newReplyTo = true;
    changed.push(`${LABEL[k](v)} (usually ${LABEL[k](usual[0])})`);
  }
  if (!changed.length) return [];
  const strong = lostSignature || newReplyTo || changed.length >= 2;
  return [
    {
      id: 'fingerprint-changed',
      category: 'sender',
      severity: strong ? 'medium' : 'low',
      points: newReplyTo ? 15 : strong ? 12 : 4,
      title: newReplyTo ? `First time ${address} asks for replies to go somewhere else` : lostSignature ? `${address} always signs their emails; this one isn't signed` : `Not sent the way ${address} usually sends`,
      detail: `Compared with your ${seen} earlier emails from this address, this one is ${changed.join('; ')}. A changed sending setup can mean someone else is using this address (a spoof or a hacked account), or simply that the sender changed providers. Check before paying or sharing anything.`,
      plain: 'It doesn’t look like the emails you usually get from this sender.',
      target: { kind: 'tab', tab: 'headers' },
    },
  ];
}
