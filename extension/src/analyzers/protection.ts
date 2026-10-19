/**
 * Your protection list: the brands you actually use (your bank), the people
 * scammers might pretend to be (your boss, your parents), and senders you
 * trust. Anything imitating them gets the strongest warnings. The list lives
 * only in this browser and can be exported to a file and imported on another
 * computer, so one person can set it up for a family or a small team.
 */
import type { Finding, LinkInfo, ParsedEmail, AuthSummary } from '../core/types';
import type { Brand } from './brands';
import { detectLookalike } from './lookalike';
import { normalizeName } from './history';
import { registrableDomain } from '../lib/domain';

export interface ProtectedBrand {
  name: string;
  /** The brand's real domains, e.g. ["hdfcbank.com", "hdfc.bank.in"]. */
  domains: string[];
}

export interface ProtectedContact {
  name: string;
  /** Every real address this person writes from. */
  addresses: string[];
}

export interface ProtectionList {
  version: 1;
  /** Shown after an import, e.g. "Sharma family" or "Acme finance team". */
  label?: string;
  brands: ProtectedBrand[];
  contacts: ProtectedContact[];
  /** Trusted senders: full addresses ("anna@acme.com") or whole domains ("acme.com"). */
  trusted: string[];
}

export const EMPTY_PROTECTION: ProtectionList = { version: 1, brands: [], contacts: [], trusted: [] };

const clean = (s: unknown) => (typeof s === 'string' ? s.trim() : '');
const cleanDomain = (s: string) => clean(s).toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '');
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN = /^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i;

/** Validates and tidies a list from storage or an imported file. Unknown or malformed entries are dropped. */
export function sanitizeProtection(input: unknown): ProtectionList {
  const o = (input && typeof input === 'object' ? input : {}) as Record<string, unknown>;
  const arr = (v: unknown) => (Array.isArray(v) ? v : []);
  const brands = arr(o.brands)
    .map((b) => ({ name: clean((b as ProtectedBrand)?.name).slice(0, 80), domains: arr((b as ProtectedBrand)?.domains).map((d) => cleanDomain(String(d))).filter((d) => DOMAIN.test(d)).slice(0, 20) }))
    .filter((b) => b.name && b.domains.length)
    .slice(0, 100);
  const contacts = arr(o.contacts)
    .map((c) => ({ name: clean((c as ProtectedContact)?.name).slice(0, 80), addresses: arr((c as ProtectedContact)?.addresses).map((a) => clean(String(a)).toLowerCase()).filter((a) => EMAIL.test(a)).slice(0, 20) }))
    .filter((c) => c.name && c.addresses.length)
    .slice(0, 200);
  const trusted = [...new Set(arr(o.trusted).map((t) => clean(String(t)).toLowerCase()).filter((t) => EMAIL.test(t) || DOMAIN.test(t)))].slice(0, 500);
  const label = clean(o.label).slice(0, 80) || undefined;
  return { version: 1, ...(label ? { label } : {}), brands, contacts, trusted };
}

/** Adds an imported list to the current one, without duplicates. */
export function mergeProtection(a: ProtectionList, b: ProtectionList): ProtectionList {
  const brands = [...a.brands];
  for (const nb of b.brands) {
    const same = brands.find((x) => x.name.toLowerCase() === nb.name.toLowerCase());
    if (same) same.domains = [...new Set([...same.domains, ...nb.domains])];
    else brands.push(nb);
  }
  const contacts = [...a.contacts];
  for (const nc of b.contacts) {
    const same = contacts.find((x) => normalizeName(x.name) === normalizeName(nc.name));
    if (same) same.addresses = [...new Set([...same.addresses, ...nc.addresses])];
    else contacts.push(nc);
  }
  return sanitizeProtection({ version: 1, label: a.label ?? b.label, brands, contacts, trusted: [...a.trusted, ...b.trusted] });
}

/** A protected brand as a Brand, so the look-alike detector can watch for it. */
export function asBrand(b: ProtectedBrand): Brand {
  const keywords = new Set<string>();
  const compact = b.name.toLowerCase().replace(/[^a-z0-9]/g, '');
  if (compact.length >= 3) keywords.add(compact);
  const first = b.name.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)[0];
  if (first && first.length >= 4) keywords.add(first);
  for (const d of b.domains) {
    const label = d.split('.')[0]!;
    if (label.length >= 3) keywords.add(label);
  }
  return { name: b.name, keywords: [...keywords], domains: b.domains.map(registrableDomain) };
}

function nameWords(s: string): string[] {
  return normalizeName(s).split(' ').filter(Boolean);
}

/** The display name uses every word of the contact's name ("Rahul Sharma (CEO)" uses "Rahul Sharma"). */
function usesContactName(display: string, contact: string): boolean {
  const want = nameWords(contact);
  if (!want.length || (want.length === 1 && want[0]!.length < 5)) return false;
  const have = new Set(nameWords(display));
  return want.every((w) => have.has(w));
}

function mentions(text: string, brand: ProtectedBrand): boolean {
  const hay = ` ${text.toLowerCase().replace(/[^a-z0-9]+/g, ' ')} `;
  const name = brand.name.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  return name.length >= 3 && hay.includes(` ${name} `);
}

export function isTrusted(list: ProtectionList, address: string): boolean {
  const a = address.toLowerCase();
  const domain = registrableDomain(a.split('@')[1] ?? '');
  return list.trusted.some((t) => t === a || (!t.includes('@') && (t === domain || a.endsWith(`@${t}`) || a.endsWith(`.${t}`))));
}

/** The email really comes from its From domain: DMARC passed, or a DKIM signature from that domain. */
function authenticated(auth: AuthSummary, fromDomain: string): boolean | null {
  if (!auth.raw) return null;
  const org = registrableDomain(fromDomain);
  return auth.dmarc === 'pass' || auth.dkimDomains.some((d) => registrableDomain(d) === org);
}

export function protectionFindings(email: ParsedEmail, auth: AuthSummary, links: LinkInfo[], list: ProtectionList): Finding[] {
  const from = email.from;
  if (!from?.address) return [];
  const findings: Finding[] = [];
  const address = from.address.toLowerCase();
  const org = registrableDomain(from.domain);
  const sender = { kind: 'sender' } as const;

  // People you protect.
  for (const c of list.contacts) {
    if (c.addresses.includes(address)) continue;
    if (!usesContactName(from.name, c.name)) continue;
    findings.push({
      id: 'protected-contact',
      category: 'sender',
      severity: 'critical',
      points: 40,
      target: sender,
      title: `Pretends to be ${c.name}, who is on your protection list`,
      detail: `${c.name} writes from ${c.addresses.join(', ')}. This came from ${from.address}. Check with them by phone before you do anything it asks.`,
      plain: `It pretends to be ${c.name}, but it isn’t from ${c.name}’s real address.`,
    });
    break;
  }

  // Brands you protect: named in the sender or subject, or imitated by a domain.
  const brands = list.brands.map(asBrand);
  list.brands.forEach((b, i) => {
    const brand = brands[i]!;
    if (brand.domains.some((d) => org === d || org.endsWith(`.${d}`))) return;
    if (mentions(from.name, b) || mentions(email.subject, b)) {
      findings.push({
        id: 'protected-brand',
        category: 'sender',
        severity: 'critical',
        points: 35,
        target: sender,
        title: `Claims to be ${b.name}, but isn't from ${b.domains[0]}`,
        detail: `${b.name} is on your protection list and only sends from ${b.domains.join(', ')}. This came from ${org}.`,
        plain: `It pretends to be ${b.name}, but ${b.name} didn’t send it.`,
      });
    }
  });
  const senderLook = detectLookalike(from.domain, brands);
  if (senderLook && !findings.some((f) => f.id === 'protected-brand')) {
    findings.push({
      id: 'protected-lookalike',
      category: 'sender',
      severity: 'critical',
      points: 40,
      target: sender,
      title: `Sender domain imitates ${senderLook.brand.name}, which is on your protection list`,
      detail: `${from.domain} ${senderLook.explanation}. ${senderLook.brand.name} sends from ${senderLook.brand.domains.join(', ')}.`,
      plain: `It pretends to be ${senderLook.brand.name}, but ${senderLook.brand.name} didn’t send it.`,
    });
  }
  const linkHits = links.map((l, i) => ({ i, look: l.host ? detectLookalike(l.host, brands) : null })).filter((x) => x.look);
  if (linkHits.length) {
    const first = linkHits[0]!.look!;
    findings.push({
      id: 'protected-link-lookalike',
      category: 'links',
      severity: 'critical',
      points: 40,
      target: { kind: 'links', indexes: linkHits.map((x) => x.i) },
      title: `Link imitates ${first.brand.name}, which is on your protection list`,
      detail: `${links[linkHits[0]!.i]!.host} ${first.explanation}. The real site is ${first.brand.domains[0]}.`,
      plain: `A link leads to a fake copy of ${first.brand.name}’s website.`,
    });
  }

  // Trusted senders: reassurance only when the email is verified to come from them.
  if (isTrusted(list, address)) {
    const ok = authenticated(auth, from.domain);
    if (ok === true) {
      findings.push({ id: 'trusted-sender', category: 'sender', severity: 'good', points: -10, target: sender, title: 'Sender is on your trusted list, and the email is verified', detail: `${from.address} passed authentication, so it really comes from ${org}.` });
    } else if (ok === false) {
      findings.push({ id: 'trusted-spoof', category: 'sender', severity: 'high', points: 25, target: sender, title: 'Uses a trusted address, but the email is not verified', detail: `${from.address} is on your trusted list, but this email failed authentication. Someone may be faking that address.`, plain: 'It uses the address of someone you trust, but it wasn’t really sent by them.' });
    } else {
      findings.push({ id: 'trusted-sender', category: 'sender', severity: 'info', points: 0, target: sender, title: 'Sender is on your trusted list', detail: 'The email’s authentication results aren’t available here, so Unmask can’t confirm it really came from them.' });
    }
  }
  return findings;
}
