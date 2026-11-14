/**
 * Sender fingerprints: how a sender's emails are usually built and sent,
 * learned on this device. Analysts compare a suspicious email with a
 * known-good one from the same sender (relay, DKIM signer, Message-ID
 * format, mail program); this does that comparison automatically.
 */
import type { AuthSummary, DeliveryHop, Finding, LinkInfo, ParsedEmail } from '../core/types';
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
  /** The riskiest kind of body link: 'sign-in' page, 'file-share', or null for neither. */
  link?: string | null;
  /** Time of day on the sender's own clock (Date header): night, morning, afternoon or evening. */
  hour?: string | null;
}

/** Where files are shared from; a hacked account's first message is very often "I shared a document with you". */
const FILE_SHARE = /(?:^|\.)(?:docs\.google\.com|drive\.google\.com|sites\.google\.com|forms\.gle|sharepoint\.com|onedrive\.live\.com|1drv\.ms|dropbox\.com|db\.tt|wetransfer\.com|we\.tl|box\.com|docsend\.com|notion\.site|canva\.com|adobe\.com|acrobat\.adobe\.com|dochub\.com|pandadoc\.com|smash\.gg|mega\.nz|mediafire\.com|files\.fm|ipfs\.io|pages\.dev|workers\.dev|web\.app|firebaseapp\.com|netlify\.app|vercel\.app|github\.io|glitch\.me|wixsite\.com|weebly\.com|square\.site|webflow\.io)$/i;
const SIGN_IN = /\/(?:log-?in|sign-?in|signon|auth(?:enticate|orize)?|verify|validation|account\/(?:update|confirm|recover)|wp-login|owa|adfs|sso|oauth2?)(?:[/?#.]|$)/i;

export function linkKind(links: LinkInfo[]): string | null {
  let kind: string | null = null;
  for (const l of links) {
    if (l.source !== 'html' && l.source !== 'text') continue;
    let url: URL;
    try {
      url = new URL(l.resolved);
    } catch {
      continue;
    }
    if (SIGN_IN.test(url.pathname) || l.flags.some((f) => f.id === 'credential-path')) return 'sign-in';
    if (FILE_SHARE.test(url.hostname)) kind = 'file-share';
  }
  return kind;
}

/** Hour on the sender's clock, from the Date header ("… 03:12:00 +0530"). */
export function hourBand(date: string | null): string | null {
  const m = date?.match(/\b(\d{1,2}):\d{2}(?::\d{2})?\s*(?:[+-]\d{4}|gmt|utc|z)\b/i);
  if (!m) return null;
  const h = Number(m[1]);
  return h < 6 ? 'night' : h < 12 ? 'morning' : h < 18 ? 'afternoon' : 'evening';
}

/** Up to this many distinct values per trait, with how often each was seen. */
export type TraitCounts = Record<'dkim' | 'route' | 'messageId' | 'mailer' | 'replyTo', Record<string, number>> & Partial<Record<'link' | 'hour', Record<string, number>>>;

const MAX_VALUES = 6;
/** "none" stands for "no value" so a missing signature is remembered too. */
const NONE = 'none';

/** Null when the email has no real headers (Outlook's page view, a pasted body): nothing to compare. */
export function senderTraits(email: ParsedEmail, auth: AuthSummary, hops: DeliveryHop[], links?: LinkInfo[]): SenderTraits | undefined {
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
    // Only learned when the links were looked at, so old callers don't record "no link".
    ...(links ? { link: linkKind(links), hour: hourBand(getHeaders(email, 'date')[0] ?? null) } : {}),
  };
}

function valueOf(traits: SenderTraits, k: keyof SenderTraits): string {
  const v = traits[k];
  return Array.isArray(v) ? v.join(',') || NONE : v ?? NONE;
}

export function addTraits(counts: TraitCounts | undefined, traits: SenderTraits): TraitCounts {
  const out = { dkim: {}, route: {}, messageId: {}, mailer: {}, replyTo: {}, ...structuredClone(counts ?? {}) } as TraitCounts;
  for (const k of Object.keys(LABEL) as (keyof SenderTraits)[]) {
    if (!(k in traits)) continue;
    out[k] ??= {};
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
  link: (v) => (v === NONE ? 'no file-share or sign-in links' : v === 'sign-in' ? 'a link to a sign-in page' : 'a file-share link'),
  hour: (v) => (v === NONE ? 'no time given' : `sent in the ${v} (their time)`),
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
  let firstLink: string | null = null;
  let nightTime = false;
  for (const k of Object.keys(LABEL) as (keyof SenderTraits)[]) {
    if (!(k in traits)) continue;
    const v = valueOf(traits, k);
    const history = counts[k] ?? {};
    if (history[v]) continue;
    const usual = Object.entries(history).sort((a, b) => b[1] - a[1])[0];
    // New traits are learned later than the old ones, so they are measured against their own count.
    const traitSeen = k === 'link' || k === 'hour' ? Object.values(history).reduce((n, c) => n + c, 0) : seen;
    if (traitSeen < minSeen) continue;
    // Only traits that were consistent before: one usual value, seen in most emails.
    if (!usual || usual[1] < Math.ceil(traitSeen * 0.75)) continue;
    if (k === 'mailer' && (v === NONE || usual[0] === NONE)) continue; // often dropped by forwarding and apps
    if (k === 'hour' && (v !== 'night' || usual[0] === NONE)) continue; // only a 3 a.m. email stands out
    if (k === 'link') {
      if (usual[0] === NONE) firstLink = v;
      continue; // reported on its own below
    }
    if (k === 'hour') nightTime = true;
    if (k === 'dkim' && v === NONE) lostSignature = true;
    if (k === 'replyTo' && usual[0] === NONE) newReplyTo = true;
    changed.push(`${LABEL[k](v)} (usually ${LABEL[k](usual[0])})`);
  }
  const out: Finding[] = [];
  if (firstLink) {
    const other = changed.length > 0;
    const what = firstLink === 'sign-in' ? 'a link to a sign-in page' : 'a file-share link';
    out.push({
      id: 'contact-first-link',
      category: 'sender',
      severity: other ? 'high' : 'medium',
      points: other ? 22 : 12,
      title: `First time ${address} sends you ${what}`,
      detail: `None of your ${seen} earlier emails from this address had one${other ? `, and this email is also ${changed.join('; ')}` : ''}. When an account is hacked, its first message to the owner’s contacts is usually “I shared a document with you” or “please sign in to view”. Ask the sender another way (a call, a new message you start) before opening it.`,
      plain: `Someone you know has never sent you ${what} before. Their account may have been hacked.`,
      target: { kind: 'tab', tab: 'links' },
    });
  }
  if (!changed.length) return out;
  const strong = lostSignature || newReplyTo || changed.length >= 2 || (nightTime && !!firstLink);
  return [
    ...out,
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
