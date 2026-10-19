import { Agent, fetch } from 'undici';
import { assertAllowedUrl, BlockedError, safeLookup } from './guard.js';

export interface TraceHop {
  url: string;
  status: number;
  via?: 'http' | 'meta-refresh' | 'javascript';
}

export interface TraceResult {
  hops: TraceHop[];
  finalUrl: string;
  truncated: boolean;
  error?: string;
}

export interface TraceOptions {
  maxHops?: number;
  timeoutMs?: number;
  /** Only for tests against a local server. */
  allowPrivate?: boolean;
}

const MAX_BODY = 256 * 1024;

// A browser-like UA: many phishing kits and shorteners serve scanners a different page.
const HEADERS = {
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36',
  accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'accept-language': 'en-US,en;q=0.9',
};

const safeAgent = new Agent({ connect: { lookup: safeLookup, timeout: 5_000 }, headersTimeout: 8_000, bodyTimeout: 8_000 });
const testAgent = new Agent({ connect: { timeout: 5_000 } });

/**
 * Opening tags named `name`, each cut at its closing '>' and at most 2 KB long.
 * Linear in the input: open-ended regexes like /<meta[^>]+…/ take quadratic time
 * on crafted pages full of unterminated tags (ReDoS).
 */
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

/** Finds a client-side redirect in the first part of an HTML page, in linear time. */
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

function decodeEntities(s: string): string {
  return s.replace(/&amp;/g, '&').replace(/&#x2F;/gi, '/').replace(/&#47;/g, '/');
}

async function readLimited(body: ReadableStream<Uint8Array> | null): Promise<string> {
  if (!body) return '';
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (size < MAX_BODY) {
    const { done, value } = await reader.read();
    if (done || !value) break;
    chunks.push(value);
    size += value.byteLength;
  }
  await reader.cancel().catch(() => {});
  return new TextDecoder().decode(Buffer.concat(chunks).subarray(0, MAX_BODY));
}

/** Follows HTTP, meta-refresh and simple JavaScript redirects without executing any page code. */
export async function traceUrl(input: string, opts: TraceOptions = {}): Promise<TraceResult> {
  const maxHops = opts.maxHops ?? 10;
  const hops: TraceHop[] = [];
  let current: URL;
  try {
    current = new URL(input);
  } catch {
    return { hops, finalUrl: input, truncated: false, error: 'Not a valid URL' };
  }

  for (let i = 0; i < maxHops; i++) {
    try {
      assertAllowedUrl(current, opts.allowPrivate);
    } catch (e) {
      return { hops, finalUrl: current.href, truncated: false, error: (e as Error).message };
    }

    let res;
    try {
      res = await fetch(current.href, {
        method: 'GET',
        redirect: 'manual',
        headers: HEADERS,
        dispatcher: opts.allowPrivate ? testAgent : safeAgent,
        signal: AbortSignal.timeout(opts.timeoutMs ?? 8_000),
      });
    } catch (e) {
      const cause = (e as { cause?: unknown }).cause;
      const msg = cause instanceof BlockedError ? cause.message : e instanceof Error && e.name === 'TimeoutError' ? 'The site did not respond in time' : `Could not connect: ${(cause as Error)?.message ?? (e as Error).message}`;
      hops.push({ url: current.href, status: 0 });
      return { hops, finalUrl: current.href, truncated: false, error: msg };
    }

    const location = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && location) {
      await res.body?.cancel().catch(() => {});
      hops.push({ url: current.href, status: res.status, via: 'http' });
      current = new URL(location, current);
      continue;
    }

    const type = res.headers.get('content-type') ?? '';
    if (type.includes('html')) {
      const html = await readLimited(res.body as ReadableStream<Uint8Array> | null);
      const client = findClientRedirect(html);
      if (client) {
        let next: URL | null = null;
        try {
          next = new URL(client.target, current);
        } catch {
          next = null;
        }
        if (next && next.href !== current.href) {
          hops.push({ url: current.href, status: res.status, via: client.via });
          current = next;
          continue;
        }
      }
    } else {
      await res.body?.cancel().catch(() => {});
    }
    hops.push({ url: current.href, status: res.status });
    return { hops, finalUrl: current.href, truncated: false };
  }
  hops.push({ url: current.href, status: 0 });
  return { hops, finalUrl: current.href, truncated: true };
}
