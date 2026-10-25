/**
 * ARC (RFC 8617): each forwarding server that supports it records the
 * authentication results it saw, numbered i=1, 2, …, and seals them. That
 * shows what the email looked like before it was forwarded, which is how
 * analysts tell a mailing list that broke a signature from a replayed email.
 *
 * This reads the chain's structure and recorded results; it does not verify
 * the seals cryptographically.
 */
import type { ArcSet, AuthSummary, Finding } from '../core/types';
import { parseAuthResults } from './auth';
import { parseTags, unfold, type RawMessage } from '../lib/rawMessage';

export function readArcChain(msg: RawMessage): { sets: ArcSet[]; problem: string | null } {
  const byInstance = new Map<number, { seal?: Record<string, string>; ams?: boolean; aar?: string }>();
  const entry = (i: number) => byInstance.get(i) ?? byInstance.set(i, {}).get(i)!;
  for (const h of msg.headers) {
    if (!h.key.startsWith('arc-')) continue;
    const value = unfold(h.rawValue);
    const i = Number(value.match(/(?:^|;)\s*i\s*=\s*(\d+)/)?.[1] ?? NaN);
    if (!Number.isInteger(i) || i < 1) continue;
    if (h.key === 'arc-seal') entry(i).seal = parseTags(value);
    else if (h.key === 'arc-message-signature') entry(i).ams = true;
    else if (h.key === 'arc-authentication-results') entry(i).aar = value.replace(/^\s*i\s*=\s*\d+\s*;/, '');
  }
  if (!byInstance.size) return { sets: [], problem: null };

  const max = Math.max(...byInstance.keys());
  const sets: ArcSet[] = [];
  let problem: string | null = null;
  for (let i = 1; i <= max; i++) {
    const e = byInstance.get(i);
    if (!e?.seal || !e.ams || e.aar === undefined) {
      problem ??= `ARC set ${i} is ${e ? 'incomplete' : 'missing'}`;
      continue;
    }
    const results: Record<string, string> = {};
    for (const r of parseAuthResults(e.aar).results) results[r.method] ??= r.result;
    const cv = (e.seal.cv ?? '').toLowerCase();
    sets.push({ instance: i, cv, domain: (e.seal.d ?? '').toLowerCase(), results });
    if (cv === 'fail') problem ??= `${e.seal.d ?? 'A forwarding server'} marked the chain as broken (cv=fail) at step ${i}`;
    else if (i === 1 && cv !== 'none') problem ??= 'The first ARC set should have cv=none';
    else if (i > 1 && cv !== 'pass') problem ??= `ARC set ${i} has cv=${cv || 'missing'}`;
  }
  return { sets, problem };
}

export function arcFindings(sets: ArcSet[], problem: string | null, auth: AuthSummary): Finding[] {
  const target = { kind: 'header', key: 'arc-authentication-results' } as const;
  const findings: Finding[] = [];
  if (problem) findings.push({ id: 'arc-broken', category: 'auth', severity: 'low', points: 3, title: 'The forwarding record (ARC) is broken', detail: `${problem}. Forwarders use ARC to vouch for what an email looked like before they passed it on.`, target });

  // What the first server recorded, versus what your provider says now.
  const first = sets[0];
  if (first && sets.length >= 1 && auth.dmarc === 'fail' && (first.results.dmarc === 'pass' || first.results.dkim === 'pass')) {
    findings.push({
      id: 'arc-passed-earlier',
      category: 'auth',
      severity: 'info',
      points: 0,
      title: `Passed authentication at ${first.domain}, failed by the time it reached you`,
      detail: `${first.domain} recorded ${Object.entries(first.results).filter(([m]) => ['dkim', 'spf', 'dmarc'].includes(m)).map(([m, r]) => `${m}=${r}`).join(', ')} when it received the email; your provider says DMARC failed. The email was forwarded or re-sent in between. That is normal for mailing lists, and also how "replayed" genuine emails look.`,
      target,
    });
  }
  return findings;
}
