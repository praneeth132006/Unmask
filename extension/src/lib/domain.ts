import { parse as parseDomain } from 'tldts';
import { toUnicode } from 'punycode/';

export interface HostInfo {
  host: string;
  /** Registrable domain (eTLD+1), or the host itself for IPs / unknown suffixes. */
  domain: string;
  /** The label left of the public suffix, e.g. "paypal" for paypal.co.uk. */
  label: string;
  suffix: string;
  isIp: boolean;
  isPunycode: boolean;
  /** Unicode form of the host when it is punycode-encoded. */
  unicodeHost: string;
  subdomainDepth: number;
}

export function hostInfo(hostOrDomain: string): HostInfo {
  const host = hostOrDomain.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const p = parseDomain(host, { allowPrivateDomains: false });
  const isIp = Boolean(p.isIp);
  const domain = isIp ? host : (p.domain ?? host);
  const isPunycode = host.split('.').some((l) => l.startsWith('xn--'));
  let unicodeHost = host;
  if (isPunycode) {
    try {
      unicodeHost = toUnicode(host);
    } catch {
      unicodeHost = host;
    }
  }
  return {
    host,
    domain,
    label: isIp ? '' : (p.domainWithoutSuffix ?? host.split('.')[0] ?? ''),
    suffix: p.publicSuffix ?? '',
    isIp,
    isPunycode,
    unicodeHost,
    subdomainDepth: p.subdomain ? p.subdomain.split('.').length : 0,
  };
}

export function registrableDomain(host: string): string {
  return hostInfo(host).domain;
}

/** True when both hosts belong to the same organisation domain (eTLD+1). */
export function sameOrg(a: string, b: string): boolean {
  if (!a || !b) return false;
  return registrableDomain(a) === registrableDomain(b);
}

export function safeUrl(input: string): URL | null {
  try {
    return new URL(input);
  } catch {
    return null;
  }
}
