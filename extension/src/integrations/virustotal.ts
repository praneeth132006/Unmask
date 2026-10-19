import type { Finding } from '../core/types';

const API = 'https://www.virustotal.com/api/v3';

export interface VtStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}

export interface VtResult {
  found: boolean;
  stats: VtStats | null;
  label: string | null;
  /** Link to the public report page. */
  permalink: string;
}

function headers(apiKey: string): HeadersInit {
  if (!apiKey) throw new Error('Add your free VirusTotal API key in Settings first.');
  return { 'x-apikey': apiKey, accept: 'application/json' };
}

async function vtError(res: Response): Promise<Error> {
  if (res.status === 401 || res.status === 403) return new Error('VirusTotal rejected the API key.');
  if (res.status === 429) return new Error('VirusTotal limit reached. Free keys allow 4 lookups per minute and 500 per day (resets at 00:00 UTC). Nothing is charged; try again shortly.');
  return new Error(`VirusTotal returned HTTP ${res.status}`);
}

interface VtObject {
  data?: { attributes?: { last_analysis_stats?: VtStats; stats?: VtStats; status?: string; popular_threat_classification?: { suggested_threat_label?: string } } };
}

/** Hash-only lookup: the file never leaves your computer. */
export async function lookupFileHash(apiKey: string, sha256: string): Promise<VtResult> {
  const permalink = `https://www.virustotal.com/gui/file/${sha256}`;
  const res = await fetch(`${API}/files/${sha256}`, { headers: headers(apiKey) });
  if (res.status === 404) return { found: false, stats: null, label: null, permalink };
  if (!res.ok) throw await vtError(res);
  const json = (await res.json()) as VtObject;
  const attrs = json.data?.attributes;
  return { found: true, stats: attrs?.last_analysis_stats ?? null, label: attrs?.popular_threat_classification?.suggested_threat_label ?? null, permalink };
}

/** VirusTotal identifies URLs by unpadded base64url of the URL itself. */
export function vtUrlId(url: string): string {
  const bytes = new TextEncoder().encode(url);
  let bin = '';
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Looks up an existing URL report (does not submit the URL for a new scan). */
export async function lookupUrl(apiKey: string, url: string): Promise<VtResult> {
  const id = vtUrlId(url);
  const permalink = `https://www.virustotal.com/gui/url/${id}`;
  const res = await fetch(`${API}/urls/${id}`, { headers: headers(apiKey) });
  if (res.status === 404) return { found: false, stats: null, label: null, permalink };
  if (!res.ok) throw await vtError(res);
  const json = (await res.json()) as VtObject;
  return { found: true, stats: json.data?.attributes?.last_analysis_stats ?? null, label: null, permalink };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Submits a URL VirusTotal has never seen for a fresh scan and waits for the
 * result. Uses one request to submit plus one per poll; polls every 15 s to
 * stay inside the free 4-per-minute limit.
 */
export async function scanUrlNow(apiKey: string, url: string, onProgress?: (message: string) => void, pollMs = 15_000): Promise<VtResult> {
  const permalink = `https://www.virustotal.com/gui/url/${vtUrlId(url)}`;
  onProgress?.('Sending the link to VirusTotal…');
  const res = await fetch(`${API}/urls`, {
    method: 'POST',
    headers: { ...headers(apiKey), 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ url }).toString(),
  });
  if (!res.ok) throw await vtError(res);
  const analysisId = ((await res.json()) as { data?: { id?: string } }).data?.id;
  if (!analysisId) throw new Error('VirusTotal did not return an analysis id.');

  for (let attempt = 1; attempt <= 8; attempt++) {
    onProgress?.(`70+ security vendors are checking it… (${Math.round((attempt * pollMs) / 1000)}s)`);
    await sleep(pollMs);
    const r = await fetch(`${API}/analyses/${analysisId}`, { headers: headers(apiKey) });
    if (r.status === 429) continue;
    if (!r.ok) throw await vtError(r);
    const attrs = ((await r.json()) as VtObject).data?.attributes;
    if (attrs?.status === 'completed') return { found: true, stats: attrs.stats ?? null, label: null, permalink };
  }
  throw new Error('VirusTotal is still scanning. Open the report link in a minute.');
}

/**
 * Uploads a file for scanning. WARNING: uploaded files can be downloaded by
 * VirusTotal's paying customers, so the UI must get explicit consent first.
 */
export async function uploadFile(
  apiKey: string,
  bytes: Uint8Array,
  filename: string,
  sha256: string,
  onProgress?: (message: string) => void,
  pollMs = 15_000,
): Promise<VtResult> {
  let uploadUrl = `${API}/files`;
  if (bytes.byteLength > 32 * 1024 * 1024) {
    const r = await fetch(`${API}/files/upload_url`, { headers: headers(apiKey) });
    if (!r.ok) throw await vtError(r);
    uploadUrl = ((await r.json()) as { data: string }).data;
  }
  const form = new FormData();
  // The bytes come straight from the email Unmask already read: nothing is saved to disk first.
  form.append('file', new File([bytes as BlobPart], filename, { type: 'application/octet-stream' }));
  onProgress?.(`Sending ${filename} to VirusTotal…`);
  const res = await fetch(uploadUrl, { method: 'POST', headers: headers(apiKey), body: form });
  if (!res.ok) throw await vtError(res);
  const analysisId = ((await res.json()) as { data?: { id?: string } }).data?.id;
  if (!analysisId) throw new Error('VirusTotal did not return an analysis id.');

  // Free keys allow 4 requests/minute, so poll gently.
  for (let attempt = 0; attempt < 16; attempt++) {
    onProgress?.(`Sent. 70+ security vendors are scanning it, usually 1–2 minutes… (${Math.round((attempt * pollMs) / 1000)}s)`);
    await sleep(pollMs);
    const r = await fetch(`${API}/analyses/${analysisId}`, { headers: headers(apiKey) });
    if (r.status === 429) continue;
    if (!r.ok) throw await vtError(r);
    const attrs = ((await r.json()) as VtObject).data?.attributes;
    if (attrs?.status === 'completed') {
      return { found: true, stats: attrs.stats ?? null, label: null, permalink: `https://www.virustotal.com/gui/file/${sha256}` };
    }
  }
  throw new Error('VirusTotal is still scanning. Open the report link later.');
}

export function vtFindings(id: string, subject: string, result: VtResult, category: Finding['category']): Finding[] {
  if (!result.found || !result.stats) {
    return [{ id, category, severity: 'info', points: 0, title: `VirusTotal has never seen ${subject}`, detail: 'Unknown is not the same as safe: new phishing files and links are often unseen.' }];
  }
  const { malicious, suspicious } = result.stats;
  const engines = result.stats.malicious + result.stats.suspicious + result.stats.harmless + result.stats.undetected;
  if (malicious >= 3) {
    return [{ id, category, severity: 'critical', points: 40, title: `VirusTotal: ${malicious}/${engines} security vendors flag ${subject} as malicious`, detail: result.label ? `Threat label: ${result.label}` : undefined }];
  }
  if (malicious + suspicious > 0) {
    return [{ id, category, severity: 'high', points: 20, title: `VirusTotal: ${malicious + suspicious}/${engines} vendors flag ${subject}`, detail: 'A few detections can be false positives, but treat it with caution.' }];
  }
  return [{ id, category, severity: 'info', points: 0, title: `VirusTotal: no vendor flags ${subject} (0/${engines})`, detail: 'Clean results do not prove a file or link is safe.' }];
}
