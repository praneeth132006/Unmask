import type { Finding } from '../core/types';

export interface UrlscanResult {
  uuid: string;
  finalUrl: string | null;
  domain: string | null;
  ip: string | null;
  country: string | null;
  title: string | null;
  malicious: boolean;
  score: number;
  brands: string[];
  screenshot: string;
  reportUrl: string;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Opens the URL in urlscan.io's sandboxed browser (not yours) and returns
 * where it ended up, a screenshot and urlscan's verdict.
 */
export async function scanUrl(
  apiKey: string,
  url: string,
  visibility: 'public' | 'unlisted' | 'private',
  onProgress?: (message: string) => void,
  { firstWaitMs = 10_000, pollMs = 4_000, maxWaitMs = 150_000 } = {},
): Promise<UrlscanResult> {
  if (!apiKey) throw new Error('Add your free urlscan.io API key in Settings first.');
  onProgress?.('Submitting to urlscan.io…');
  const res = await fetch('https://urlscan.io/api/v1/scan/', {
    method: 'POST',
    headers: { 'API-Key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, visibility }),
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { message?: string; description?: string };
    if (res.status === 401) throw new Error('urlscan.io rejected the API key.');
    if (res.status === 429) throw new Error('urlscan.io limit reached. The free plan allows 1,000 unlisted and 50 private scans per day. Nothing is charged; try again later or switch visibility in Settings.');
    throw new Error(body.description ?? body.message ?? `urlscan.io returned HTTP ${res.status}`);
  }
  const { uuid } = (await res.json()) as { uuid: string };

  const reportUrl = `https://urlscan.io/result/${uuid}/`;

  // Scans take ~10-60s; the result endpoint returns 404 until ready. Unlisted and
  // private results are only visible with the key that submitted them.
  const started = Date.now();
  await sleep(firstWaitMs);
  while (Date.now() - started < maxWaitMs) {
    onProgress?.(`Waiting for the sandbox browser… (${Math.round((Date.now() - started) / 1000)}s)`);
    const r = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, { headers: { 'API-Key': apiKey } });
    if (r.status === 404) {
      await sleep(pollMs);
      continue;
    }
    if (r.status === 429) {
      await sleep(pollMs * 2);
      continue;
    }
    if (!r.ok) throw new Error(`urlscan.io returned HTTP ${r.status}`);
    return parseUrlscan(uuid, await r.json());
  }
  throw new UrlscanPending(reportUrl);
}

/** The scan was submitted but isn't finished yet; the report link will show it. */
export class UrlscanPending extends Error {
  constructor(readonly reportUrl: string) {
    super('urlscan.io is still scanning this link. Its report will be ready shortly.');
  }
}

interface UrlscanJson {
  page?: { url?: string; domain?: string; ip?: string; country?: string; title?: string };
  verdicts?: { overall?: { malicious?: boolean; score?: number; brands?: (string | { name?: string })[] } };
}

export function parseUrlscan(uuid: string, json: UrlscanJson): UrlscanResult {
  const overall = json.verdicts?.overall;
  return {
    uuid,
    finalUrl: json.page?.url ?? null,
    domain: json.page?.domain ?? null,
    ip: json.page?.ip ?? null,
    country: json.page?.country ?? null,
    title: json.page?.title ?? null,
    malicious: Boolean(overall?.malicious),
    score: overall?.score ?? 0,
    brands: (overall?.brands ?? []).map((b) => (typeof b === 'string' ? b : (b.name ?? ''))).filter(Boolean),
    screenshot: `https://urlscan.io/screenshots/${uuid}.png`,
    reportUrl: `https://urlscan.io/result/${uuid}/`,
  };
}

export function urlscanFindings(id: string, result: UrlscanResult): Finding[] {
  if (result.malicious) {
    return [{
      id,
      category: 'links',
      severity: 'critical',
      points: 40,
      title: `urlscan.io marks ${result.domain ?? 'the link'} as malicious`,
      detail: result.brands.length ? `Impersonates: ${result.brands.join(', ')}` : `Final page: ${result.finalUrl ?? 'unknown'}`,
    }];
  }
  return [];
}
