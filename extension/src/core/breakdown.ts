/**
 * Why the score is what it is: each finding's share of the 0–100 score, in
 * the same order and with the same rules as `scoreFindings`, so the bars
 * always add up to what the ring shows.
 */
import { VERDICT_THRESHOLDS } from './score';
import type { Finding, Report } from './types';

export interface ScorePart {
  id: string;
  title: string;
  /** Points this finding adds (positive) or takes off (negative). */
  points: number;
  severity: Finding['severity'];
}

export interface ScoreBreakdown {
  /** Findings that raised the score, largest first. */
  raised: ScorePart[];
  /** Reassuring findings that lowered it, if they were allowed to count. */
  lowered: ScorePart[];
  /** Reassurance that was ignored because a serious finding is present. */
  ignored: ScorePart[];
  /** Points added because a critical finding or two high findings force a High risk verdict. */
  floor: number;
  /** Points lost because the score cannot go above 100. */
  capped: number;
  score: number;
}

const part = (f: Finding): ScorePart => ({ id: f.id, title: f.title, points: f.points, severity: f.severity });

export function scoreBreakdown(report: Pick<Report, 'findings' | 'score'>): ScoreBreakdown {
  const { findings, score } = report;
  const raised = findings.filter((f) => f.points > 0).map(part).sort((a, b) => b.points - a.points);
  const serious = findings.some((f) => f.severity === 'high' || f.severity === 'critical');
  const reassuring = findings.filter((f) => f.points < 0).map(part).sort((a, b) => a.points - b.points);
  const lowered = serious ? [] : reassuring;
  const ignored = serious ? reassuring : [];

  const positive = raised.reduce((n, p) => n + p.points, 0);
  const negative = Math.max(-15, lowered.reduce((n, p) => n + p.points, 0));
  const raw = Math.max(0, positive + negative);
  const capped = Math.max(0, raw - 100);
  const critical = findings.some((f) => f.severity === 'critical');
  const highs = findings.filter((f) => f.severity === 'high').length;
  const floor = critical || highs >= 2 ? Math.max(0, VERDICT_THRESHOLDS.high + 10 - Math.min(100, raw)) : 0;
  return { raised, lowered, ignored, floor, capped, score };
}
