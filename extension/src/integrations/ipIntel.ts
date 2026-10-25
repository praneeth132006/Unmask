/**
 * Who runs the server that handed the email to your provider: its reverse
 * DNS name and the network (ASN) it belongs to, from public DNS only.
 * Team Cymru publishes IP-to-network data as a DNS zone, so this needs no
 * API key. Sends the sending server's IP address to dns.google; off unless
 * you turn it on.
 */
import type { Finding } from '../core/types';
import { doh } from './domainIntel';

export interface IpIntel {
  ip: string;
  /** Reverse DNS name, or null when none. */
  ptr: string | null;
  /** The reverse name resolves back to the same IP (forward-confirmed). */
  confirmed: boolean;
  asn: string | null;
  network: string | null;
  country: string | null;
}

function reverseName(ip: string): string {
  if (!ip.includes(':')) return `${ip.split('.').reverse().join('.')}`;
  // Expand :: and reverse every nibble.
  const [head = '', tail = ''] = ip.split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  const groups = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t].map((g) => g.padStart(4, '0'));
  return groups.join('').split('').reverse().join('.');
}

export async function lookupIp(ip: string): Promise<IpIntel> {
  const v6 = ip.includes(':');
  const rev = reverseName(ip);
  const [ptrs, origin] = await Promise.all([
    doh(`${rev}.${v6 ? 'ip6' : 'in-addr'}.arpa`, 'PTR').catch(() => []),
    doh(`${rev}.${v6 ? 'origin6' : 'origin'}.asn.cymru.com`, 'TXT').catch(() => []),
  ]);
  const ptr = ptrs[0]?.replace(/\.$/, '').toLowerCase() ?? null;
  const [asn = null, , country = null] = (origin[0] ?? '').split('|').map((x) => x.trim() || null);
  const [forward, asInfo] = await Promise.all([
    ptr ? doh(ptr, v6 ? 'AAAA' : 'A').catch(() => []) : Promise.resolve([]),
    asn ? doh(`AS${asn.split(' ')[0]}.asn.cymru.com`, 'TXT').catch(() => []) : Promise.resolve([]),
  ]);
  const network = asInfo[0]?.split('|').pop()?.trim() ?? null;
  return { ip, ptr, confirmed: forward.some((a) => a.toLowerCase() === ip.toLowerCase()), asn: asn?.split(' ')[0] ?? null, network, country };
}

/** Rented-server networks: cheap, anonymous, and where most phishing mail servers live. */
const VPS = /\b(digitalocean|hetzner|contabo|choopa|vultr|constant company|ovh|m247|colocrossing|leaseweb|linode|serverius|stark industries|pq hosting|alexhost|frantech|ponynet|hostkey|datacamp|tier\.net|host sailor|aeza|hostinger)\b/i;
/** Home and mobile connections: real mail servers are never on these. */
const HOME = /(^|[.-])(dyn|dynamic|dynip|dhcp|pool|dsl|adsl|vdsl|xdsl|cable|ppp|pppoe|broadband|residential|mobile)([.-]|\d|$)/i;

export function ipFindings(info: IpIntel, claimsOrg: boolean): Finding[] {
  const base = { category: 'auth' as const, target: { kind: 'tab', tab: 'headers' } as const };
  const findings: Finding[] = [];
  // Only the labels the network chose, not its domain ("dsl" in a hostname, not "dslreports.com").
  if (info.ptr && HOME.test(info.ptr.split('.').slice(0, -2).join('.'))) {
    findings.push({ ...base, id: 'ip-home-connection', severity: 'medium', points: 10, title: 'Sent from a home or mobile internet connection', detail: `The server that delivered it is ${info.ptr} (${info.ip}), a consumer connection${info.network ? ` on ${info.network}` : ''}. Real mail servers don't run on these; infected home computers do.` });
  } else if (info.network && VPS.test(info.network)) {
    findings.push({ ...base, id: 'ip-rented-server', severity: claimsOrg ? 'medium' : 'low', points: claimsOrg ? 8 : 3, title: `Sent from a rented server (${info.network.replace(/,\s*[A-Z]{2}$/, '')})`, detail: `${info.ip} belongs to a cheap server-rental network.${claimsOrg ? ' Large organisations send through their own or well-known mail services, not a rented server.' : ' Small senders use these too, but so do most phishing kits.'}` });
  }
  if (info.ptr && !info.confirmed) {
    findings.push({ ...base, id: 'ip-ptr-unconfirmed', severity: 'low', points: 3, title: 'The sending server\'s DNS name doesn\'t point back to it', detail: `${info.ip} calls itself ${info.ptr}, but ${info.ptr} does not resolve to ${info.ip}. Properly run mail servers match both ways.` });
  }
  return findings;
}
