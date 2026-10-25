import type { Finding, Report, TabId } from '../../core/types';
import { Card, SEVERITY_STYLE, SectionTitle } from './ui';
import { Icon } from './Icon';
import { targetHint } from '../targets';
import { plainSummary } from '../../core/plain';
import { concernsHeading, trackerChipLabel, verdictLabel } from '../../core/facts';
import { hypotheses, limitations } from '../../core/assessment';

const VERDICT = {
  high: {
    label: 'High risk',
    ring: 'var(--bad)',
    text: 'text-[var(--bad)]',
    bg: 'bg-[var(--bad-soft)]',
    border: 'border-[var(--bad)]/25',
    note: 'Strong signs of phishing. Don’t click links, open attachments or reply.',
  },
  suspicious: {
    label: 'Suspicious',
    ring: 'var(--warn)',
    text: 'text-[var(--warn)]',
    bg: 'bg-[var(--warn-soft)]',
    border: 'border-[var(--warn)]/25',
    note: 'Some warning signs. Check with the sender another way before acting.',
  },
  clear: {
    label: 'No red flags found',
    ring: 'var(--good)',
    text: 'text-[var(--good)]',
    bg: 'bg-[var(--good-soft)]',
    border: 'border-[var(--good)]/25',
    note: 'Nothing obviously wrong. That isn’t a guarantee, so stay careful with links and files.',
  },
} as const;

function ScoreRing({ score, color }: { score: number; color: string }) {
  const r = 24;
  const c = 2 * Math.PI * r;
  return (
    <svg viewBox="0 0 60 60" className="h-[60px] w-[60px] shrink-0" role="img" aria-label={`Risk score ${score} out of 100`}>
      <circle cx="30" cy="30" r={r} fill="none" strokeWidth="6" stroke="var(--border)" />
      <circle
        cx="30"
        cy="30"
        r={r}
        fill="none"
        strokeWidth="6"
        strokeLinecap="round"
        stroke={color}
        strokeDasharray={`${Math.max(score, 1) / 100 * c} ${c}`}
        transform="rotate(-90 30 30)"
      />
      <text x="30" y="31" textAnchor="middle" dominantBaseline="middle" fill="var(--text)" fontSize="17" fontWeight="700">
        {score}
      </text>
    </svg>
  );
}

export function VerdictCard({ report }: { report: Report }) {
  const v = VERDICT[report.verdict];
  const label = verdictLabel(report);
  const note = label === 'Low risk' ? 'Nothing typical of phishing. A few minor points are listed below; they are worth knowing, not alarming.' : v.note;
  const from = report.email.from;
  return (
    <div className={`rounded-xl border ${v.border} ${v.bg} p-3`}>
      <div className="flex items-center gap-3">
        <ScoreRing score={report.score} color={v.ring} />
        <div className="min-w-0">
          <div className={`text-[15px] font-semibold ${v.text}`}>{label}</div>
          <p className="mt-0.5 text-xs leading-snug text-[var(--text-2)]">{note}</p>
        </div>
      </div>
      <div className="mt-3 border-t border-[var(--border)] pt-2.5 text-xs">
        <div className="truncate font-medium text-[var(--text)]" title={report.email.subject}>
          {report.email.subject || '(no subject)'}
        </div>
        <div className="truncate text-[var(--text-2)]" title={from?.address}>
          {from ? (
            <>
              {from.name && <span>{from.name} · </span>}
              <span className="font-mono text-[11px]">{from.address}</span>
            </>
          ) : (
            'Unknown sender'
          )}
        </div>
      </div>
    </div>
  );
}

function SummaryChips({ report, onOpen }: { report: Report; onOpen: (tab: TabId) => void }) {
  const flaggedLinks = report.links.filter((l) => l.flags.some((f) => f.severity !== 'info' && f.severity !== 'low')).length;
  const riskyFiles = report.attachments.filter((a) => a.flags.length).length;
  const trackers = report.trackers.pixels.length + report.trackers.trackedLinkCount;
  const trackerLabel = trackerChipLabel(report);
  const authOk = report.auth.dmarc === 'pass';
  const authBad = report.auth.dmarc === 'fail' || report.auth.spf === 'fail';
  const chips: { tab: TabId; label: string; tone: 'good' | 'bad' | 'warn' | 'info' }[] = [
    { tab: 'sender', label: authOk ? 'Sender verified' : authBad ? 'Sender not verified' : 'Sender unverified', tone: authOk ? 'good' : authBad ? 'bad' : 'warn' },
    { tab: 'links', label: report.links.length ? `${flaggedLinks}/${report.links.length} links flagged` : 'No links', tone: flaggedLinks ? 'bad' : 'good' },
    { tab: 'attachments', label: report.attachments.length ? `${riskyFiles}/${report.attachments.length} files risky` : 'No files', tone: riskyFiles ? 'bad' : 'good' },
    { tab: 'privacy', label: trackerLabel, tone: trackers ? 'warn' : 'good' },
  ];
  const tone = { good: 'text-[var(--good)]', bad: 'text-[var(--bad)]', warn: 'text-[var(--warn)]', info: 'text-[var(--info)]' };
  const dot = { good: 'bg-[var(--good)]', bad: 'bg-[var(--bad)]', warn: 'bg-[var(--warn)]', info: 'bg-[var(--info)]' };
  return (
    <div className="grid grid-cols-2 gap-1.5">
      {chips.map((c) => (
        <button
          key={c.tab}
          type="button"
          onClick={() => onOpen(c.tab)}
          className="flex items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-2 py-1.5 text-left text-[11px] font-medium shadow-[var(--shadow)] transition-colors hover:border-[var(--border-strong)] hover:bg-[var(--surface-2)]"
        >
          <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${dot[c.tone]}`} />
          <span className={`truncate ${tone[c.tone]}`}>{c.label}</span>
        </button>
      ))}
    </div>
  );
}

function FindingRow({ f, onHover, onOpen }: { f: Finding; onHover: (f: Finding | null) => void; onOpen: (f: Finding) => void }) {
  const s = SEVERITY_STYLE[f.severity];
  const actionable = Boolean(f.target);
  return (
    <li id={`finding-${f.id}`}>
      <button
        type="button"
        disabled={!actionable}
        title={targetHint(f.target)}
        onMouseEnter={() => onHover(f)}
        onMouseLeave={() => onHover(null)}
        onFocus={() => onHover(f)}
        onBlur={() => onHover(null)}
        onClick={() => onOpen(f)}
        className="group flex w-full gap-2.5 px-3 py-2.5 text-left transition-colors enabled:hover:bg-[var(--surface-2)] disabled:cursor-default"
      >
        <span className={`mt-[7px] h-2 w-2 shrink-0 rounded-full ${s.dot}`} title={s.label} />
        <span className="min-w-0 flex-1">
          <span className="block text-[13px] font-medium leading-snug text-[var(--text)]">{f.title}</span>
          {f.detail && <span className="mt-0.5 block break-words text-xs leading-snug text-[var(--text-2)]">{f.detail}</span>}
        </span>
        {actionable && <Icon name="chevron" className="mt-1 h-3.5 w-3.5 shrink-0 text-[var(--text-3)] opacity-0 transition-opacity group-hover:opacity-100" />}
      </button>
    </li>
  );
}

function Group({ title, findings, onHover, onOpen }: { title: string; findings: Finding[]; onHover: (f: Finding | null) => void; onOpen: (f: Finding) => void }) {
  if (!findings.length) return null;
  return (
    <>
      <SectionTitle>{title}</SectionTitle>
      <Card className="!p-0 overflow-hidden">
        <ul className="divide-y divide-[var(--border)]">
          {findings.map((f) => (
            <FindingRow key={f.id} f={f} onHover={onHover} onOpen={onOpen} />
          ))}
        </ul>
      </Card>
    </>
  );
}

/** The analyst's reading: which kind of attack the evidence points to, and what couldn't be checked. */
export function AssessmentCard({ report }: { report: Report }) {
  const kinds = hypotheses(report);
  const limits = limitations(report);
  if (!kinds.length && !limits.length) return null;
  const tone = { high: 'text-[var(--bad)] bg-[var(--bad-soft)]', medium: 'text-[var(--warn)] bg-[var(--warn-soft)]', low: 'text-[var(--text-2)] bg-[var(--surface-2)]' } as const;
  return (
    <Card className="mt-3" aria-label="Assessment">
      {kinds.length > 0 && (
        <>
          <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-3)]">What this looks like</div>
          <ul className="mt-1.5 space-y-1.5">
            {kinds.slice(0, 3).map((h) => (
              <li key={h.kind} className="text-xs leading-snug">
                <span className="font-semibold text-[var(--text)]">{h.label}</span>
                <span className={`ml-1.5 rounded px-1.5 py-px text-[10px] font-semibold ${tone[h.confidence]}`}>{h.confidence} confidence</span>
                <span className="block text-[var(--text-2)]">{h.meaning}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      {limits.length > 0 && (
        <details className={kinds.length ? 'mt-2.5 border-t border-[var(--border)] pt-2' : ''}>
          <summary className="cursor-pointer select-none text-[11px] font-medium text-[var(--accent)]">What Unmask couldn’t check ({limits.length})</summary>
          <ul className="mt-1.5 list-disc space-y-1 pl-4 text-[11px] leading-snug text-[var(--text-2)]">
            {limits.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        </details>
      )}
    </Card>
  );
}

/** "In plain words": the verdict as an everyday sentence, its reasons, and what to do. */
export function PlainCard({ report }: { report: Report }) {
  const p = plainSummary(report);
  const tone = report.verdict === 'high' ? 'var(--bad)' : report.verdict === 'suspicious' ? 'var(--warn)' : 'var(--good)';
  return (
    <Card className="mt-3" aria-label="In plain words">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-3)]">In plain words</div>
      <p className="mt-1 text-[15px] font-semibold leading-snug" style={{ color: tone }}>
        {p.headline}
      </p>
      {p.reasons.length > 0 && (
        <ul className="mt-1.5 space-y-1 text-[13px] leading-snug text-[var(--text)]">
          {p.reasons.map((r) => (
            <li key={r} className="flex gap-2">
              <span className="mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: tone }} />
              {r}
            </li>
          ))}
        </ul>
      )}
      <p className="mt-2 rounded-lg bg-[var(--surface-2)] px-2.5 py-1.5 text-xs leading-snug text-[var(--text-2)]">
        <strong className="text-[var(--text)]">What to do: </strong>
        {p.action}
      </p>
    </Card>
  );
}

export function Overview({
  report,
  onHoverFinding,
  onOpenFinding,
  onOpenTab,
  canHighlight,
  simple = false,
}: {
  simple?: boolean;
  report: Report;
  onHoverFinding: (f: Finding | null) => void;
  onOpenFinding: (f: Finding) => void;
  onOpenTab: (tab: TabId) => void;
  canHighlight: boolean;
}) {
  const red = report.findings.filter((f) => f.points > 0 && f.severity !== 'info' && f.severity !== 'good');
  const good = report.findings.filter((f) => f.severity === 'good');
  const notes = report.findings.filter((f) => !red.includes(f) && !good.includes(f));
  const technical = (
    <>
      <SummaryChips report={report} onOpen={onOpenTab} />
      <AssessmentCard report={report} />
      {red.length > 0 && canHighlight && (
        <p className="mt-3 flex items-center gap-1.5 text-[11px] text-[var(--text-3)]">
          <Icon name="eye" className="h-3.5 w-3.5" /> Hover a red flag to see it in the email. Click it for details.
        </p>
      )}
      <Group title={concernsHeading(report, red.length)} findings={red} onHover={onHoverFinding} onOpen={onOpenFinding} />
      {!red.length && (
        <Card className="mt-4 text-center">
          <Icon name="check" className="mx-auto h-5 w-5 text-[var(--good)]" />
          <p className="mt-1 text-sm font-medium">No red flags from the local checks</p>
          <p className="mt-0.5 text-xs text-[var(--text-2)]">You can still scan links and files with the buttons in the Links and Files tabs.</p>
        </Card>
      )}
      <Group title="Good signs" findings={good} onHover={onHoverFinding} onOpen={onOpenFinding} />
      <Group title="Notes" findings={notes} onHover={onHoverFinding} onOpen={onOpenFinding} />
    </>
  );
  return (
    <div>
      <PlainCard report={report} />
      <div className="mt-3">
        {simple ? (
          <details className="group">
            <summary className="cursor-pointer select-none rounded-lg px-1 py-1.5 text-xs font-medium text-[var(--accent)] hover:bg-[var(--accent-soft)]">Show the technical details ({report.verdict === 'clear' ? `${red.length} point${red.length === 1 ? '' : 's'} worth knowing` : `${red.length} red flag${red.length === 1 ? '' : 's'}`})</summary>
            <div className="mt-2">{technical}</div>
          </details>
        ) : (
          technical
        )}
      </div>
    </div>
  );
}
