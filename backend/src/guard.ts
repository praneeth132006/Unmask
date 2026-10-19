import { BlockList, isIP } from 'node:net';
import dns from 'node:dns';
import type { LookupFunction } from 'node:net';

/**
 * Addresses the tracer must never connect to. Without this, anyone could use
 * the service to probe internal networks or cloud metadata endpoints (SSRF).
 */
const blocked = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  blocked.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
  ['2001:db8::', 32],
] as const) {
  blocked.addSubnet(net, prefix, 'ipv6');
}

export function isBlockedAddress(address: string): boolean {
  const mapped = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i)?.[1];
  if (mapped) return blocked.check(mapped, 'ipv4');
  const family = isIP(address);
  if (family === 4) return blocked.check(address, 'ipv4');
  if (family === 6) return blocked.check(address, 'ipv6');
  return true;
}

export const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);

export class BlockedError extends Error {}

/** Validates a URL before any request is made. */
export function assertAllowedUrl(url: URL, allowPrivate = false): void {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new BlockedError(`Only http and https links can be traced (got ${url.protocol})`);
  if (!allowPrivate && !ALLOWED_PORTS.has(url.port)) throw new BlockedError(`Port ${url.port} is not allowed`);
  if (url.username || url.password) {
    // Credentials in the URL are a phishing trick; strip rather than send them.
    url.username = '';
    url.password = '';
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (!allowPrivate && isIP(host) && isBlockedAddress(host)) throw new BlockedError('Refusing to connect to a private or reserved address');
  if (!allowPrivate && (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local'))) {
    throw new BlockedError('Refusing to connect to a local hostname');
  }
}

/**
 * DNS lookup used for every outgoing socket. Checking the resolved address at
 * connect time (not just before fetch) also defeats DNS-rebinding tricks.
 */
export const safeLookup: LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err, '', 4);
    const list = addresses as dns.LookupAddress[];
    const bad = list.find((a) => isBlockedAddress(a.address));
    if (bad) return callback(new BlockedError(`${hostname} resolves to a private address (${bad.address})`), '', 4);
    if ((options as { all?: boolean }).all) return (callback as unknown as (e: null, a: dns.LookupAddress[]) => void)(null, list);
    const first = list[0];
    if (!first) return callback(new Error(`No addresses for ${hostname}`), '', 4);
    callback(null, first.address, first.family);
  });
};
