import type { Finding } from '../core/types';

export interface DomainAge {
  domain: string;
  created: string | null;
  ageDays: number | null;
  registrar: string | null;
}

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}
interface RdapEntity {
  roles?: string[];
  vcardArray?: [string, [string, unknown, string, string][]];
}

/** Looks up a domain's registration date via RDAP (the successor to WHOIS). Only the domain name is sent. */
export async function lookupDomainAge(domain: string, signal?: AbortSignal): Promise<DomainAge> {
  const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    headers: { accept: 'application/rdap+json, application/json' },
    signal,
  });
  if (!res.ok) throw new Error(res.status === 404 ? 'Domain not found in RDAP' : `RDAP returned HTTP ${res.status}`);
  const data = (await res.json()) as { events?: RdapEvent[]; entities?: RdapEntity[] };
  return parseRdap(domain, data);
}

export function parseRdap(domain: string, data: { events?: RdapEvent[]; entities?: RdapEntity[] }, now = Date.now()): DomainAge {
  const created = data.events?.find((e) => e.eventAction === 'registration')?.eventDate ?? null;
  const registrarEntity = data.entities?.find((e) => e.roles?.includes('registrar'));
  const fn = registrarEntity?.vcardArray?.[1]?.find((f) => f[0] === 'fn')?.[3] ?? null;
  const ageDays = created ? Math.floor((now - new Date(created).getTime()) / 86_400_000) : null;
  return { domain, created, ageDays: ageDays !== null && Number.isFinite(ageDays) ? ageDays : null, registrar: fn };
}

export function domainAgeFindings(age: DomainAge, role: 'sender' | 'link'): Finding[] {
  if (age.ageDays === null) return [];
  const who = role === 'sender' ? 'Sender domain' : 'Link domain';
  const id = `age-${role}-${age.domain}`;
  const category = role === 'sender' ? 'sender' : 'links';
  if (age.ageDays < 30) {
    return [{ id, category, severity: 'high', points: 25, title: `${who} ${age.domain} was registered ${age.ageDays} day${age.ageDays === 1 ? '' : 's'} ago`, detail: 'Phishing domains are usually brand new. Established companies send from domains that are years old.' }];
  }
  if (age.ageDays < 180) {
    return [{ id, category, severity: 'medium', points: 10, title: `${who} ${age.domain} is only ${Math.round(age.ageDays / 30)} months old`, detail: age.created ? `Registered ${age.created.slice(0, 10)}.` : undefined }];
  }
  return [{ id, category, severity: 'info', points: 0, title: `${who} ${age.domain} has existed for ${(age.ageDays / 365).toFixed(1)} years`, detail: age.created ? `Registered ${age.created.slice(0, 10)}${age.registrar ? ` via ${age.registrar}` : ''}.` : undefined }];
}
