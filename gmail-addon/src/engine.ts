/** The engine for the Gmail add-on, exposed as a global (Apps Script has no modules). */
import './shims';
import '../../extension/src/lib/domShim';
import { analyzeRawEmail } from '../../extension/src/core/analyze';
import { plainSummary } from '../../extension/src/core/plain';
import { verdictLabel } from '../../extension/src/core/facts';
import { scoreBreakdown } from '../../extension/src/core/breakdown';
import { lessonFor, LESSONS_URL } from '../../extension/src/core/lessons';

export interface AddonResult {
  verdict: 'clear' | 'suspicious' | 'high';
  label: string;
  score: number;
  headline: string;
  reasons: string[];
  action: string;
  flags: { title: string; detail: string; points: number; lesson: string | null }[];
}

export async function check(raw: string): Promise<AddonResult> {
  const r = await analyzeRawEmail(raw);
  const s = plainSummary(r);
  const b = scoreBreakdown(r);
  return {
    verdict: r.verdict,
    label: verdictLabel(r),
    score: r.score,
    headline: s.headline,
    reasons: s.reasons,
    action: s.action,
    flags: b.raised.slice(0, 8).map((p) => {
      const f = r.findings.find((x) => x.id === p.id);
      const l = lessonFor(p.id);
      return { title: p.title, detail: f?.detail ?? '', points: p.points, lesson: l ? `${LESSONS_URL}#${l.id}` : null };
    }),
  };
}
