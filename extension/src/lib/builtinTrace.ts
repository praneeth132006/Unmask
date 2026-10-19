/**
 * Built-in redirect tracer, run in the background service worker.
 *
 * Each hop is fetched with `credentials: 'omit'` (no cookies, no logins) and is
 * never opened in a tab, so no page code runs. HTTP redirects are followed by
 * fetch itself and observed with chrome.webRequest (they're invisible to fetch);
 * meta-refresh and simple JavaScript redirects are read from the first 256 KB of
 * the final page. Needs the optional "<all_urls>" host permission, requested in
 * the panel the first time the user clicks "Trace redirects".
 */
import type { TraceHop, TraceResult } from '../integrations/trace';
import { blockedReason, findClientRedirect } from './redirects';

interface WebRequestDetails {
  requestId: string;
  url: string;
  tabId: number;
  initiator?: string;
  statusCode?: number;
  redirectUrl?: string;
}

interface WebRequestEvent {
  addListener(cb: (d: WebRequestDetails) => void, filter: { urls: string[] }): void;
  removeListener(cb: (d: WebRequestDetails) => void): void;
}

export interface TraceEnv {
  fetch: typeof fetch;
  onBeforeRequest: WebRequestEvent;
  onBeforeRedirect: WebRequestEvent;
  /** chrome-extension://<id>, the initiator of our own requests. */
  origin: string;
}

const MAX_HOPS = 10;
const MAX_BODY = 256 * 1024;
const TIMEOUT_MS = 10_000;

async function readLimited(res: Response): Promise<string> {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (size < MAX_BODY) {
    const { done, value } = await reader.read();
    if (done || !value) break;
    chunks.push(value);
    size += value.byteLength;
  }
  await reader.cancel().catch(() => {});
  const all = new Uint8Array(Math.min(size, MAX_BODY));
  let off = 0;
  for (const c of chunks) {
    const take = Math.min(c.byteLength, all.length - off);
    all.set(c.subarray(0, take), off);
    off += take;
    if (off >= all.length) break;
  }
  return new TextDecoder().decode(all);
}

/** One fetch, following HTTP redirects, returning every hop it saw. */
async function fetchHop(env: TraceEnv, url: string): Promise<{ hops: TraceHop[]; finalUrl: string; status: number; html: string | null; error?: string }> {
  const target = new URL(url).href;
  const hops: TraceHop[] = [];
  let requestId: string | null = null;
  const abort = new AbortController();
  let blocked: string | null = null;

  const onRequest = (d: WebRequestDetails) => {
    if (requestId || d.tabId !== -1 || !d.initiator?.startsWith(env.origin)) return;
    if (d.url === target) requestId = d.requestId;
  };
  const onRedirect = (d: WebRequestDetails) => {
    if (d.requestId !== requestId) return;
    hops.push({ url: d.url, status: d.statusCode ?? 0, via: 'http' });
    const why = d.redirectUrl ? blockedReason(d.redirectUrl) : null;
    if (why) {
      blocked = `Stopped at ${d.redirectUrl}: ${why}`;
      abort.abort();
    }
  };
  env.onBeforeRequest.addListener(onRequest, { urls: ['<all_urls>'] });
  env.onBeforeRedirect.addListener(onRedirect, { urls: ['<all_urls>'] });
  const timer = setTimeout(() => abort.abort(), TIMEOUT_MS);
  try {
    const res = await env.fetch(target, {
      credentials: 'omit',
      redirect: 'follow',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: abort.signal,
      headers: { accept: 'text/html,application/xhtml+xml,*/*;q=0.8' },
    });
    const finalUrl = res.url || target;
    const html = (res.headers.get('content-type') ?? '').includes('html') ? await readLimited(res) : (await res.body?.cancel().catch(() => {}), null);
    return { hops, finalUrl, status: res.status, html };
  } catch (e) {
    const last = hops.length ? hops[hops.length - 1]!.url : target;
    const error = blocked ?? (abort.signal.aborted ? 'The site did not respond in time' : `Could not connect: ${e instanceof Error ? e.message : String(e)}`);
    return { hops, finalUrl: last, status: 0, html: null, error };
  } finally {
    clearTimeout(timer);
    env.onBeforeRequest.removeListener(onRequest);
    env.onBeforeRedirect.removeListener(onRedirect);
  }
}

export async function traceBuiltin(env: TraceEnv, start: string): Promise<TraceResult> {
  const hops: TraceHop[] = [];
  let current = start;
  for (let round = 0; hops.length < MAX_HOPS; round++) {
    const why = blockedReason(current);
    if (why) return { hops, finalUrl: current, truncated: false, error: why };

    const r = await fetchHop(env, current);
    hops.push(...r.hops);
    if (r.error) {
      hops.push({ url: r.finalUrl, status: 0 });
      return { hops, finalUrl: r.finalUrl, truncated: false, error: r.error };
    }
    const client = r.html ? findClientRedirect(r.html) : null;
    let next: string | null = null;
    if (client) {
      try {
        next = new URL(client.target, r.finalUrl).href;
      } catch {
        next = null;
      }
    }
    if (next && next !== r.finalUrl && round < MAX_HOPS) {
      hops.push({ url: r.finalUrl, status: r.status, via: client!.via });
      current = next;
      continue;
    }
    hops.push({ url: r.finalUrl, status: r.status });
    return { hops, finalUrl: r.finalUrl, truncated: false };
  }
  return { hops, finalUrl: current, truncated: true };
}

/** Runs traces one at a time, so each request id is matched to the right trace. */
let queue: Promise<unknown> = Promise.resolve();
export function traceQueued(env: TraceEnv, url: string): Promise<TraceResult> {
  const run = queue.then(() => traceBuiltin(env, url));
  queue = run.catch(() => {});
  return run;
}

/**
 * Registers the real webRequest listeners once, when the background starts,
 * and hands events to whichever trace is running. Adding listeners per trace
 * raced the first request: Chrome registers them asynchronously, so on a busy
 * machine the first redirects of a trace could be missed.
 */
export function webRequestHub(onBeforeRequest: WebRequestEvent, onBeforeRedirect: WebRequestEvent): Pick<TraceEnv, 'onBeforeRequest' | 'onBeforeRedirect'> {
  const local = () => {
    const subs = new Set<(d: WebRequestDetails) => void>();
    return {
      dispatch: (d: WebRequestDetails) => subs.forEach((cb) => cb(d)),
      event: { addListener: (cb: (d: WebRequestDetails) => void) => void subs.add(cb), removeListener: (cb: (d: WebRequestDetails) => void) => void subs.delete(cb) } satisfies WebRequestEvent,
    };
  };
  const req = local();
  const redir = local();
  onBeforeRequest.addListener(req.dispatch, { urls: ['<all_urls>'] });
  onBeforeRedirect.addListener(redir.dispatch, { urls: ['<all_urls>'] });
  return { onBeforeRequest: req.event, onBeforeRedirect: redir.event };
}
