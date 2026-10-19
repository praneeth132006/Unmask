/**
 * Pure helpers for Unmask's built-in redirect tracer (background worker).
 * The parsing mirrors backend/src/trace.ts so both tracers agree.
 */

/** Opening tags named `name`, each cut at its '>' and at most 2 KB: linear time, no ReDoS. */
export function tagsNamed(html: string, name: string, max = 200): string[] {
  const lower = html.toLowerCase();
  const needle = `<${name}`;
  const out: string[] = [];
  for (let i = lower.indexOf(needle); i >= 0 && out.length < max; i = lower.indexOf(needle, i + needle.length)) {
    const end = lower.indexOf('>', i);
    out.push(html.slice(i, Math.min(end < 0 ? html.length : end + 1, i + 2048)));
  }
  return out;
}

function decodeEntities(s: string): string {
  return s.replace(/&amp;/g, '&').replace(/&#x2F;/gi, '/').replace(/&#47;/g, '/');
}

/** A <meta refresh> or simple `location = "…"` redirect in a page, without running it. */
export function findClientRedirect(html: string): { target: string; via: 'meta-refresh' | 'javascript' } | null {
  for (const tag of tagsNamed(html, 'meta')) {
    if (!/http-equiv\s*=\s*["']?refresh/i.test(tag)) continue;
    const url = tag.match(/content\s*=\s*["']?\s*\d*\s*[;,]?\s*url\s*=\s*['"]?([^"'>\s]{1,2048})/i)?.[1];
    if (url) return { target: decodeEntities(url), via: 'meta-refresh' };
  }
  const lower = html.toLowerCase();
  let seen = 0;
  for (let i = lower.indexOf('location'); i >= 0 && seen < 200; i = lower.indexOf('location', i + 8), seen++) {
    const window = html.slice(i, i + 2100);
    const m =
      window.match(/^location(?:\.href)?\s*=\s*["'`]([^"'`]{1,2048})["'`]/i) ??
      window.match(/^location\.(?:replace|assign)\(\s*["'`]([^"'`]{1,2048})["'`]\s*\)/i);
    const target = m?.[1];
    if (target && /^(https?:)?\/\//i.test(target)) return { target: decodeEntities(target), via: 'javascript' };
  }
  return null;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
    n = n * 256 + Number(p);
  }
  return n;
}

const PRIVATE_V4: [string, number][] = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

function isPrivateHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.home.arpa')) return true;
  const v4 = ipv4ToInt(host.replace(/^::ffff:/, ''));
  if (v4 !== null) {
    return PRIVATE_V4.some(([net, bits]) => {
      const base = ipv4ToInt(net)!;
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      return ((v4 & mask) >>> 0) === ((base & mask) >>> 0);
    });
  }
  if (host.includes(':')) return host === '::' || host === '::1' || /^f[cd]/.test(host) || /^fe[89ab]/.test(host) || /^ff/.test(host);
  return false;
}

/**
 * Why a URL must not be fetched from the user's browser, or null if it's fine.
 * Blocks other schemes, unusual ports and anything on the local network, so a
 * phishing link can't make Unmask poke the user's router or other devices.
 * (Hostnames that only *resolve* to private addresses can't be checked from an
 * extension; the fetch carries no cookies, so the risk is limited.)
 */
export function blockedReason(url: string): string | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return 'Not a valid web address';
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return `Only web links can be traced (this is ${u.protocol})`;
  if (!['', '80', '443', '8080', '8443'].includes(u.port)) return `Port ${u.port} is not allowed`;
  if (isPrivateHost(u.hostname)) return 'Refusing to contact an address on your local network';
  return null;
}
