/**
 * Domain intelligence from free public sources. Only the domain name is sent.
 * - Certificate Transparency (crt.sh): when the domain's first TLS
 *   certificate was issued. Phishing sites get their certificate hours
 *   before the campaign starts.
 * - DNS over HTTPS (dns.google): whether the domain has mail records (MX,
 *   SPF, DMARC). Real organisations that send email can also receive it and
 *   publish these records; throwaway domains often don't.
 */
import type { Finding } from '../core/types';

export interface CertInfo {
  domain: string;
  /** Earliest certificate validity start found in CT logs, ISO date. Null if none was ever issued. */
  firstSeen: string | null;
  ageDays: number | null;
  count: number;
}

export interface MailRecords {
  domain: string;
  mx: string[];
  hasAddress: boolean;
  spf: string | null;
  dmarc: string | null;
}

export interface DomainIntel {
  cert?: CertInfo;
  mail?: MailRecords;
}

const TIMEOUT_MS = 12_000;

async function getJson<T>(url: string, signal?: AbortSignal): Promise<T> {
  const timeout = AbortSignal.timeout(TIMEOUT_MS);
  const res = await fetch(url, { signal: signal ? AbortSignal.any([signal, timeout]) : timeout, headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`${new URL(url).hostname} returned HTTP ${res.status}`);
  return (await res.json()) as T;
}

interface CrtEntry {
  not_before?: string;
  entry_timestamp?: string;
}

export function parseCrtSh(domain: string, entries: CrtEntry[], now = Date.now()): CertInfo {
  const times = entries.map((e) => Date.parse(`${e.not_before ?? e.entry_timestamp ?? ''}Z`.replace(/ZZ$/, 'Z'))).filter(Number.isFinite);
  if (!times.length) return { domain, firstSeen: null, ageDays: null, count: 0 };
  const first = Math.min(...times);
  return { domain, firstSeen: new Date(first).toISOString(), ageDays: Math.max(0, Math.floor((now - first) / 86_400_000)), count: entries.length };
}

/**
 * Earliest certificate naming the domain (crt.sh also matches its subdomains).
 * crt.sh is a free community service that often answers 502 under load, so
 * one retry. Other CT APIs only list unexpired certificates, which can't tell
 * a new domain from a renewed one, so there is deliberately no fallback.
 */
export async function lookupCerts(domain: string, signal?: AbortSignal): Promise<CertInfo> {
  const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&deduplicate=Y`;
  for (let attempt = 0; ; attempt++) {
    try {
      return parseCrtSh(domain, await getJson<CrtEntry[]>(url, signal));
    } catch (e) {
      // crt.sh answers 404 when nothing matches: never issued.
      if (e instanceof Error && /HTTP 404/.test(e.message)) return parseCrtSh(domain, []);
      if (attempt >= 1 || signal?.aborted) throw new Error(`Certificate logs (crt.sh) did not answer: ${e instanceof Error ? e.message : String(e)}`);
      await new Promise((r) => setTimeout(r, 2500));
    }
  }
}

interface DohAnswer {
  Status: number;
  Answer?: { type: number; data: string }[];
}

async function doh(name: string, type: 'MX' | 'TXT' | 'A' | 'AAAA', signal?: AbortSignal): Promise<string[]> {
  const r = await getJson<DohAnswer>(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`, signal);
  const code = { MX: 15, TXT: 16, A: 1, AAAA: 28 }[type];
  return (r.Answer ?? []).filter((a) => a.type === code).map((a) => a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
}

export async function lookupMailRecords(domain: string, signal?: AbortSignal): Promise<MailRecords> {
  const [mx, txt, dmarc, a, aaaa] = await Promise.all([
    doh(domain, 'MX', signal),
    doh(domain, 'TXT', signal),
    doh(`_dmarc.${domain}`, 'TXT', signal),
    doh(domain, 'A', signal),
    doh(domain, 'AAAA', signal),
  ]);
  return {
    domain,
    // "0 ." is a null MX: the domain explicitly accepts no mail.
    mx: mx.filter((m) => !/^0\s+\.$/.test(m.trim())),
    hasAddress: a.length + aaaa.length > 0,
    spf: txt.find((t) => /^v=spf1\b/i.test(t)) ?? null,
    dmarc: dmarc.find((t) => /^v=DMARC1\b/i.test(t)) ?? null,
  };
}

const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? '' : 's'}`;

export function certFindings(c: CertInfo, role: 'sender' | 'link'): Finding[] {
  const id = `cert-${role}-${c.domain}`;
  const who = role === 'sender' ? 'Sender domain' : 'Link domain';
  const base = { id, category: role === 'sender' ? ('sender' as const) : ('links' as const), target: role === 'sender' ? ({ kind: 'sender' } as const) : ({ kind: 'tab', tab: 'links' } as const) };
  if (c.ageDays === null) {
    return role === 'link' ? [{ ...base, severity: 'low', points: 4, title: `${who} ${c.domain} has never had a TLS certificate`, detail: 'Certificate Transparency logs have no certificate for it, so it can only be reached over plain http or not at all.' }] : [];
  }
  if (c.ageDays < 7) return [{ ...base, severity: 'high', points: 20, title: `${who} ${c.domain} got its first TLS certificate ${c.ageDays === 0 ? 'today' : `${plural(c.ageDays, 'day')} ago`}`, detail: 'Phishing sites are usually set up hours or days before the emails go out. Established sites have certificate history going back years.' }];
  if (c.ageDays < 30) return [{ ...base, severity: 'medium', points: 10, title: `${who} ${c.domain} got its first TLS certificate ${plural(c.ageDays, 'day')} ago`, detail: `First certificate: ${c.firstSeen?.slice(0, 10)}.` }];
  return [];
}

export function mailRecordFindings(m: MailRecords): Finding[] {
  const base = { id: `mail-records-${m.domain}`, category: 'sender' as const, target: { kind: 'sender' } as const };
  const missing = [!m.mx.length && 'no MX (cannot receive mail)', !m.spf && 'no SPF', !m.dmarc && 'no DMARC'].filter(Boolean) as string[];
  if (!missing.length) return [];
  if (!m.mx.length && !m.hasAddress) {
    return [{ ...base, severity: 'medium', points: 12, title: `Sender domain ${m.domain} has no mail server and no website`, detail: `DNS shows ${missing.join(', ')}. A real organisation's domain can receive replies.` }];
  }
  const serious = !m.mx.length;
  return [{ ...base, severity: serious ? 'medium' : 'low', points: serious ? 8 : missing.length * 2, title: `Sender domain ${m.domain} is missing mail records`, detail: `DNS shows ${missing.join(', ')}. Legitimate senders usually publish all three.` }];
}
