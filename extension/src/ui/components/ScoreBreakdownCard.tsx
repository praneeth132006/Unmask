import { scoreBreakdown, type ScorePart } from '../../core/breakdown';
import type { Report } from '../../core/types';
import { SEVERITY_STYLE } from './ui';

function Row({ p, max, muted = false }: { p: ScorePart; max: number; muted?: boolean }) {
  const width = Math.max(4, (Math.abs(p.points) / max) * 100);
  const sign = p.points > 0 ? '+' : '−';
  return (
    <li className={`grid grid-cols-[1fr_auto] items-center gap-x-2 gap-y-1 ${muted ? 'opacity-50' : ''}`}>
      <span className="min-w-0 truncate text-[var(--text)]" title={p.title}>{p.title}</span>
      <span className={`font-mono text-[11px] font-semibold ${p.points > 0 ? 'text-[var(--bad)]' : 'text-[var(--good)]'} ${muted ? 'line-through' : ''}`}>
        {sign}{Math.abs(p.points)}
      </span>
      <span className="col-span-2 h-1.5 overflow-hidden rounded-full bg-[var(--surface-2)]">
        <span className={`block h-full rounded-full ${p.points > 0 ? SEVERITY_STYLE[p.severity].bar : 'bg-[var(--good)]'}`} style={{ width: `${width}%` }} />
      </span>
    </li>
  );
}

/** "Why this score": each finding's points as a bar, adding up to the number in the ring. */
export function ScoreBreakdownCard({ report }: { report: Report }) {
  const b = scoreBreakdown(report);
  if (!b.raised.length && !b.lowered.length) return null;
  const max = Math.max(...[...b.raised, ...b.lowered, ...b.ignored].map((p) => Math.abs(p.points)), 1);
  return (
    <details className="mt-3 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-3 text-xs" data-testid="score-breakdown">
      <summary className="cursor-pointer select-none font-medium text-[var(--text)]">
        Why the score is {b.score}
      </summary>
      <ul className="mt-3 space-y-2.5">
        {b.raised.map((p) => <Row key={p.id} p={p} max={max} />)}
        {b.lowered.map((p) => <Row key={p.id} p={p} max={max} />)}
        {b.ignored.map((p) => <Row key={p.id} p={p} max={max} muted />)}
      </ul>
      <div className="mt-3 space-y-1 border-t border-[var(--border)] pt-2 text-[11px] text-[var(--text-2)]">
        {b.ignored.length > 0 && <p>Crossed-out good signs don’t count: they show who sent it, not that it is safe, once something serious is found.</p>}
        {b.lowered.length > 0 && <p>Good signs can take off at most 15 points.</p>}
        {b.floor > 0 && <p>+{b.floor} because a critical finding or two high ones always mean High risk.</p>}
        {b.capped > 0 && <p>The score stops at 100 ({b.capped} more points found).</p>}
      </div>
    </details>
  );
}
