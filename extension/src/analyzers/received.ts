/**
 * The delivery path, read the way an analyst reads it: Received headers from
 * the bottom up, trusting only the ones written by your own mail provider.
 *
 * Each server adds a Received line above the others, so the top lines come
 * from your provider and are reliable. Lines below the point where your
 * provider took the email were written by servers you can't check; the
 * sender can write fake ones before sending.
 */
import type { DeliveryHop, Finding } from '../core/types';
import { registrableDomain } from '../lib/domain';
import { stripComments, unfold } from '../lib/rawMessage';

const KEYWORDS = new Set(['from', 'by', 'via', 'with', 'id', 'for']);

interface Clause {
  value: string;
  comments: string[];
}

/** Splits "from a (b [1.2.3.4]) by c with ESMTPS id x" into keyword clauses with their comments. */
function clauses(text: string): Record<string, Clause> {
  const out: Record<string, Clause> = {};
  let current: Clause | null = null;
  let word = '';
  let comment = '';
  let depth = 0;
  const endWord = () => {
    if (!word) return;
    const k = word.toLowerCase();
    if (KEYWORDS.has(k) && !(k in out) && (!current || current.value)) {
      current = { value: '', comments: [] };
      out[k] = current;
    } else if (current && !current.value) current.value = word;
    word = '';
  };
  for (const ch of text) {
    if (ch === '(') {
      if (depth === 0) endWord();
      else comment += ch;
      depth++;
    } else if (ch === ')' && depth > 0) {
      depth--;
      if (depth === 0) {
        (current as Clause | null)?.comments.push(comment.trim());
        comment = '';
      } else comment += ch;
    } else if (depth > 0) comment += ch;
    else if (/\s/.test(ch)) endWord();
    else word += ch;
  }
  endWord();
  return out;
}

const IPV4 = /\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b/;
const IPV6 = /(?:^|[\s[(])((?:IPv6:)?[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7})(?=$|[\s\])])/i;

function findIp(text: string): string | null {
  const v4 = text.match(IPV4)?.[1];
  if (v4) return v4;
  return text.match(IPV6)?.[1]?.replace(/^IPv6:/i, '').toLowerCase() ?? null;
}

export function isPrivateIp(ip: string): boolean {
  if (ip.includes(':')) return /^(::1$|f[cd]|fe[89ab])/i.test(ip);
  const [a = 0, b = 0] = ip.split('.').map(Number);
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
}

const isIpLiteral = (s: string) => /^\[?(IPv6:)?[0-9a-f.:]+\]?$/i.test(s) && (IPV4.test(s) || s.includes(':'));
const looksLikeHost = (s: string) => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.?$/i.test(s);

/** Parses one Received header value. */
export function parseReceivedLine(value: string): Omit<DeliveryHop, 'n' | 'delaySec' | 'trusted'> {
  const flat = unfold(value).replace(/\s+/g, ' ');
  const semi = flat.lastIndexOf(';');
  const dateText = semi >= 0 ? stripComments(flat.slice(semi + 1)).trim() : '';
  const c = clauses(semi >= 0 ? flat.slice(0, semi) : flat);
  const from = c.from;
  let helo: string | null = null;
  let rdns: string | null = null;
  let ip: string | null = null;
  if (from) {
    const comments = from.comments.join(' ');
    // Exim: from [1.2.3.4] (helo=name). Sendmail/Postfix/Gmail: from helo (rdns [1.2.3.4]).
    helo = isIpLiteral(from.value) ? (comments.match(/helo=([^\s)\]]+)/i)?.[1] ?? null) : from.value || null;
    ip = (isIpLiteral(from.value) ? findIp(from.value) : null) ?? findIp(comments);
    const first = from.comments[0]?.split(/\s+/)[0] ?? '';
    if (/^unknown$/i.test(first) || /^unknown$/i.test(from.value)) rdns = 'unknown';
    else if (looksLikeHost(first) && !/^helo=/i.test(first)) rdns = first.replace(/\.$/, '').toLowerCase();
    const heloComment = comments.match(/\bHELO\s+([^\s)\]]+)/)?.[1];
    if (heloComment) helo = heloComment;
  }
  const time = dateText ? Date.parse(dateText) : NaN;
  return {
    helo: helo?.replace(/\.$/, '').toLowerCase() ?? null,
    rdns,
    ip,
    privateIp: ip ? isPrivateIp(ip) : false,
    by: c.by?.value.replace(/\.$/, '').toLowerCase() || null,
    protocol: c.with?.value || null,
    time: Number.isFinite(time) ? time : null,
  };
}

/** Mail providers whose servers sit under several organisation domains. */
const PROVIDER_FAMILIES: string[][] = [
  ['google.com', '1e100.net', 'gmail.com', 'googlemail.com'],
  ['outlook.com', 'office365.com', 'microsoft.com', 'hotmail.com', 'live.com'],
  ['yahoo.com', 'yahoodns.net', 'yahoo.net', 'aol.com'],
  ['icloud.com', 'apple.com', 'me.com'],
];

export function sameProvider(a: string, b: string): boolean {
  if (a === b) return true;
  return PROVIDER_FAMILIES.some((f) => f.includes(a) && f.includes(b));
}

/**
 * Builds the path from origin (1) to inbox from the Received values in
 * header order (newest first). `receiver` is the authserv-id of the
 * Authentication-Results used, which tells which provider is yours.
 */
export function deliveryPath(receivedValues: string[], receiver: string | null = null): DeliveryHop[] {
  const parsed = receivedValues.map(parseReceivedLine);
  // Your provider is whoever wrote the top line (or the auth results).
  const topBy = parsed.find((h) => h.by && !isIpLiteral(h.by))?.by;
  const providerOrg = receiver && looksLikeHost(receiver) ? registrableDomain(receiver) : topBy ? registrableDomain(topBy) : null;
  let trustedRun = providerOrg !== null;
  const trusted = parsed.map((h) => {
    if (!trustedRun) return false;
    // Internal hops (Gmail's "by 2002:a05:…") count as the provider's own.
    const ok = !h.by || isIpLiteral(h.by) || sameProvider(registrableDomain(h.by), providerOrg!);
    if (!ok) trustedRun = false;
    return ok;
  });
  const hops = parsed
    .map((h, i) => ({ ...h, trusted: trusted[i]! }))
    .reverse()
    .map((h, i) => ({ ...h, n: i + 1, delaySec: null as number | null }));
  for (let i = 1; i < hops.length; i++) {
    const prev = hops[i - 1]!.time;
    const cur = hops[i]!.time;
    if (prev !== null && cur !== null) hops[i]!.delaySec = Math.round((cur - prev) / 1000);
  }
  return hops;
}

/** The first hop your provider wrote: where it took the email from the outside world. */
export function entryHop(hops: DeliveryHop[]): DeliveryHop | null {
  return hops.find((h) => h.trusted) ?? null;
}

/** Public IP of the server that first sent the email, preferring what your provider saw. */
export function originIp(hops: DeliveryHop[], xOriginatingIp?: string | null): string | null {
  const claimed = xOriginatingIp ? findIp(xOriginatingIp) : null;
  if (claimed && !isPrivateIp(claimed)) return claimed;
  return hops.find((h) => h.ip && !h.privateIp)?.ip ?? null;
}

const WORKSTATION = /^(localhost|desktop-[a-z0-9]+|win-[a-z0-9]+|laptop-[a-z0-9]+|user-?pc|[a-z0-9-]+-pc|ubuntu|debian|kali|admin)$/i;

const days = (ms: number) => Math.floor(ms / 86_400_000);
const duration = (sec: number) => (sec >= 86_400 ? `${days(sec * 1000)} days` : sec >= 3600 ? `${Math.round(sec / 3600)} hours` : `${Math.round(sec / 60)} minutes`);

export function receivedFindings(hops: DeliveryHop[], dateHeader: string | null): Finding[] {
  const findings: Finding[] = [];
  const target = { kind: 'tab', tab: 'headers' } as const;
  const entry = entryHop(hops);

  // 1. Clocks running backwards. Forged lines are written by the sender, who has to guess the times.
  const backwards = hops.filter((h) => h.delaySec !== null && h.delaySec < -600);
  if (backwards.length) {
    const worst = Math.min(...backwards.map((h) => h.delaySec!));
    // The earlier hop's line is the one that may be invented.
    const untrusted = backwards.some((h) => !h.trusted || !hops[h.n - 2]?.trusted);
    const big = worst < -6 * 3600;
    findings.push({
      id: 'received-out-of-order',
      category: 'auth',
      severity: big && untrusted ? 'medium' : 'low',
      points: big && untrusted ? 10 : 4,
      title: 'Delivery times are out of order',
      detail: `Hop ${backwards[0]!.n} says it received the email ${duration(-worst)} before the previous server sent it. Usually a wrong server clock; forged delivery lines, which the sender writes before sending, also look like this.`,
      target,
    });
  }

  // 2. How the email reached your provider: from a real mail server, or straight from a computer?
  if (entry && entry.ip && !entry.privateIp && entry.n > 0) {
    const helo = entry.helo ?? '';
    if (WORKSTATION.test(helo) || (helo && isIpLiteral(helo)) || (helo && !helo.includes('.'))) {
      findings.push({
        id: 'received-workstation',
        category: 'auth',
        severity: 'medium',
        points: 10,
        title: 'Sent straight from a computer, not a mail server',
        detail: `The sending machine at ${entry.ip} called itself "${helo}". Companies send through named mail servers; home computers and infected machines announce names like this.`,
        target,
      });
    }
    if (entry.rdns === 'unknown') {
      findings.push({
        id: 'received-no-rdns',
        category: 'auth',
        severity: 'low',
        points: 4,
        title: 'The sending server has no name in DNS',
        detail: `Your provider could not find a hostname for ${entry.ip}. Real mail servers almost always have one.`,
        target,
      });
    }
  }

  // 3. Timeline: when it was written versus when it arrived.
  const sent = dateHeader ? Date.parse(stripComments(dateHeader)) : NaN;
  const arrived = entry?.time ?? hops[hops.length - 1]?.time ?? null;
  if (Number.isFinite(sent) && arrived !== null) {
    const late = arrived - sent;
    if (late < -2 * 3600_000) {
      findings.push({ id: 'date-future', category: 'auth', severity: 'low', points: 5, title: 'The email is dated in the future', detail: `Its Date header is ${duration(-late / 1000)} after it actually arrived. Scam tools sometimes set dates to stay at the top of your inbox.`, target: { kind: 'header', key: 'date' } });
    } else if (late > 3 * 86_400_000) {
      findings.push({ id: 'date-old', category: 'auth', severity: 'low', points: 6, title: `Written ${days(late)} days before it arrived`, detail: 'Its Date header is much older than its delivery. An old, genuinely signed email re-sent to new people (a "replay") looks like this, as do long mail-server delays.', target: { kind: 'header', key: 'date' } });
    }
  }
  return findings;
}
