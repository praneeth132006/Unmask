import type { Finding, Severity, Verdict } from './types';

export const SEVERITY_RANK: Record<Severity, number> = { good: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };

export const VERDICT_THRESHOLDS = { suspicious: 20, high: 50 } as const;

/**
 * Turns findings into a 0–100 score and a verdict.
 * - Points add up, with reassuring signals (negative points) able to offset at most 15.
 * - Any critical finding forces a "high" verdict: one fake login form is enough.
 * - Two or more high findings also force "high".
 */
export function scoreFindings(findings: Finding[]): { score: number; verdict: Verdict } {
  const positive = findings.filter((f) => f.points > 0).reduce((n, f) => n + f.points, 0);
  const negative = Math.max(-15, findings.filter((f) => f.points < 0).reduce((n, f) => n + f.points, 0));
  let score = Math.max(0, Math.min(100, positive + negative));

  const critical = findings.some((f) => f.severity === 'critical');
  const highs = findings.filter((f) => f.severity === 'high').length;
  if (critical || highs >= 2) score = Math.max(score, VERDICT_THRESHOLDS.high + 10);

  const verdict: Verdict = score >= VERDICT_THRESHOLDS.high ? 'high' : score >= VERDICT_THRESHOLDS.suspicious ? 'suspicious' : 'clear';
  return { score, verdict };
}

/** Most severe first, then by points. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.points - a.points);
}

/** Merge enrichment findings (domain age, VirusTotal, ...) into a report's findings, replacing same-id entries. */
export function mergeFindings(base: Finding[], extra: Finding[]): Finding[] {
  const ids = new Set(extra.map((f) => f.id));
  return sortFindings([...base.filter((f) => !ids.has(f.id)), ...extra]);
}
