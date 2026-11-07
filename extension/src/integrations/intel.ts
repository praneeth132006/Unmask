/**
 * Hash-only lookups against malware databases. The file never leaves the
 * computer: only its SHA-256 fingerprint is sent, and only when the user
 * clicks a button.
 */
import { browser } from 'wxt/browser';
import type { Finding } from '../core/types';

export type IntelSource = 'Hybrid Analysis' | 'MalwareBazaar' | 'URLhaus' | 'PhishTank';

export interface IntelHit {
  source: IntelSource;
  found: boolean;
  verdict: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  /** One line for people. */
  summary: string;
  /** Facts for the investigation report. */
  details: Record<string, string>;
  permalink: string;
}

/** Asks for access to the service's website. Must be called straight from a click. */
export async function ensureOrigins(origins: string[]): Promise<boolean> {
  try {
    if (await browser.permissions.contains({ origins })) return true;
    return await browser.permissions.request({ origins });
  } catch {
    return false;
  }
}

export const HYBRID_ORIGINS = ['https://www.hybrid-analysis.com/*'];
export const ABUSE_CH_ORIGINS = ['https://mb-api.abuse.ch/*', 'https://urlhaus-api.abuse.ch/*'];

const HA = 'https://www.hybrid-analysis.com/api/v2';

const str = (v: unknown): string => (typeof v === 'string' || typeof v === 'number' ? String(v) : '');

/** Hybrid Analysis (CrowdStrike Falcon Sandbox) report summary for a SHA-256, by hash only. */
export async function lookupHybridAnalysis(apiKey: string, sha256: string): Promise<IntelHit> {
  const permalink = `https://www.hybrid-analysis.com/sample/${sha256}`;
  if (!apiKey) throw new Error('Add your free Hybrid Analysis API key in Settings first.');
  const res = await fetch(`${HA}/overview/${sha256}`, { headers: { 'api-key': apiKey, accept: 'application/json' } });
  if (res.status === 404) return { source: 'Hybrid Analysis', found: false, verdict: 'unknown', summary: 'Hybrid Analysis has never analyzed this file. Unknown is not the same as safe.', details: {}, permalink };
  if (res.status === 401 || res.status === 403) throw new Error('Hybrid Analysis rejected the API key (or it has not been approved for API use yet).');
  if (res.status === 429) throw new Error('Hybrid Analysis rate limit reached. Try again in a minute.');
  if (!res.ok) throw new Error(`Hybrid Analysis returned HTTP ${res.status}`);
  const j = (await res.json()) as Record<string, unknown>;
  return parseHybrid(j, permalink);
}

export function parseHybrid(j: Record<string, unknown>, permalink: string): IntelHit {
  const verdictRaw = str(j.verdict).toLowerCase();
  const score = str(j.threat_score);
  const family = str(j.vx_family);
  const av = str(j.av_detect);
  const verdict: IntelHit['verdict'] = /malicious/.test(verdictRaw) ? 'malicious' : /suspicious/.test(verdictRaw) ? 'suspicious' : /whitelist|no specific threat|clean/.test(verdictRaw) ? 'clean' : 'unknown';
  const bits = [verdictRaw && `verdict: ${verdictRaw}`, score && `threat score ${score}/100`, av && `${av}% of antivirus engines`, family && `family: ${family}`].filter(Boolean);
  const tags = Array.isArray(j.tags) ? (j.tags as unknown[]).map(str).filter(Boolean).slice(0, 8).join(', ') : '';
  return {
    source: 'Hybrid Analysis',
    found: true,
    verdict,
    summary: bits.length ? `Hybrid Analysis sandbox: ${bits.join(' · ')}` : 'Hybrid Analysis has a report for this file.',
    details: Object.fromEntries(Object.entries({ Verdict: verdictRaw, 'Threat score': score, 'Antivirus detection': av ? `${av}%` : '', Family: family, Tags: tags, 'Last scanned': str(j.last_multi_scan) || str(j.analysis_start_time), 'Submitted as': str(j.submit_name) }).filter(([, v]) => v)),
    permalink,
  };
}

const MB = 'https://mb-api.abuse.ch/api/v1/';

/** MalwareBazaar (abuse.ch) record for a SHA-256, by hash only. Needs a free abuse.ch Auth-Key. */
export async function lookupMalwareBazaar(authKey: string, sha256: string): Promise<IntelHit> {
  const permalink = `https://bazaar.abuse.ch/sample/${sha256}/`;
  if (!authKey) throw new Error('Add your free abuse.ch Auth-Key in Settings first.');
  const res = await fetch(MB, { method: 'POST', headers: { 'Auth-Key': authKey, 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body: new URLSearchParams({ query: 'get_info', hash: sha256 }).toString() });
  if (res.status === 401 || res.status === 403) throw new Error('abuse.ch rejected the Auth-Key.');
  if (!res.ok) throw new Error(`MalwareBazaar returned HTTP ${res.status}`);
  return parseBazaar((await res.json().catch(() => ({}))) as Record<string, unknown>, permalink);
}

export function parseBazaar(j: Record<string, unknown>, permalink: string): IntelHit {
  const status = str(j.query_status);
  if (status === 'hash_not_found' || status === 'no_results') return { source: 'MalwareBazaar', found: false, verdict: 'unknown', summary: 'MalwareBazaar has no record of this file. Unknown is not the same as safe.', details: {}, permalink };
  if (/auth/i.test(status)) throw new Error('abuse.ch rejected the Auth-Key.');
  if (status !== 'ok') throw new Error(`MalwareBazaar answered "${status || 'nothing'}".`);
  const d = ((j.data as Record<string, unknown>[] | undefined) ?? [])[0] ?? {};
  const intel = (d.intelligence ?? {}) as Record<string, unknown>;
  const tags = Array.isArray(d.tags) ? (d.tags as unknown[]).map(str).filter(Boolean).join(', ') : '';
  const family = str(d.signature);
  return {
    source: 'MalwareBazaar',
    found: true,
    verdict: 'malicious',
    summary: `MalwareBazaar lists this exact file as malware${family ? ` (${family})` : ''}${str(d.first_seen) ? `, first seen ${str(d.first_seen).slice(0, 10)}` : ''}.`,
    details: Object.fromEntries(Object.entries({ Family: family, 'File type': str(d.file_type), 'Original name': str(d.file_name), 'First seen': str(d.first_seen), 'Delivered by': str(d.delivery_method), Tags: tags, 'Reported downloads': str(intel.downloads), 'Reporter': str(d.reporter) }).filter(([, v]) => v)),
    permalink,
  };
}

/** Turns lookup results into scored findings, like the VirusTotal helper does. */
export function intelFindings(id: string, subject: string, hit: IntelHit, category: Finding['category']): Finding[] {
  if (hit.verdict === 'malicious') return [{ id, category, severity: 'critical', points: 40, title: `${hit.source}: ${subject} is known malware`, detail: hit.summary }];
  if (hit.verdict === 'suspicious') return [{ id, category, severity: 'high', points: 20, title: `${hit.source}: ${subject} looks suspicious`, detail: hit.summary }];
  if (!hit.found) return [{ id, category, severity: 'info', points: 0, title: `${hit.source} has no record of ${subject}`, detail: hit.summary }];
  return [{ id, category, severity: 'info', points: 0, title: `${hit.source}: no threat found for ${subject}`, detail: 'Clean results do not prove a file is safe.' }];
}
