export interface TraceHop {
  url: string;
  status: number;
  /** How the next hop was reached: an HTTP redirect, a <meta refresh>, or a JS location change. */
  via?: 'http' | 'meta-refresh' | 'javascript';
}

export interface TraceResult {
  hops: TraceHop[];
  finalUrl: string;
  truncated: boolean;
  error?: string;
}

/**
 * Asks the Unmask backend to follow the redirect chain from its own server,
 * so your browser never loads the link.
 */
export async function traceRedirects(backendUrl: string, url: string): Promise<TraceResult> {
  if (!backendUrl) throw new Error('Set the redirect-trace backend URL in Settings (see the README to run or deploy it).');
  const res = await fetch(`${backendUrl}/api/trace?url=${encodeURIComponent(url)}`, { headers: { accept: 'application/json' } });
  const body = (await res.json().catch(() => null)) as (TraceResult & { error?: string }) | null;
  if (!res.ok || !body) throw new Error(body?.error ?? `Trace backend returned HTTP ${res.status}`);
  return body;
}
