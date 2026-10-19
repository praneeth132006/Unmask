import type { Finding, Report } from '../../core/types';
import { Card, SEVERITY_STYLE, SectionTitle } from './ui';

const VERDICT = {
  high: { label: 'High risk', ring: 'stroke-red-600', text: 'text-red-700 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-950/40', note: 'Several strong phishing signs. Do not click links, open attachments or reply.' },
  suspicious: { label: 'Suspicious', ring: 'stroke-amber-500', text: 'text-amber-700 dark:text-amber-400', bg: 'bg-amber-50 dark:bg-amber-950/40', note: 'Some warning signs. Verify with the sender through another channel before acting.' },
  clear: { label: 'No red flags found', ring: 'stroke-emerald-500', text: 'text-emerald-700 dark:text-emerald-400', bg: 'bg-emerald-50 dark:bg-emerald-950/40', note: 'Nothing obviously wrong, but this is not a guarantee. Stay careful with links and attachments.' },
} as const;

function ScoreRing({ score, ringClass }: { score: number; ringClass: string }) {
  const r = 26;
  const c = 2 * Math.PI * r;
  return (
    <svg viewBox="0 0 64 64" className="h-16 w-16 shrink-0 -rotate-90" role="img" aria-label={`Risk score ${score} out of 100`}>
      <circle cx="32" cy="32" r={r} fill="none" strokeWidth="7" className="stroke-slate-200 dark:stroke-slate-800" />
      <circle cx="32" cy="32" r={r} fill="none" strokeWidth="7" strokeLinecap="round" className={ringClass} strokeDasharray={`${(score / 100) * c} ${c}`} />
      <text x="32" y="32" transform="rotate(90 32 32)" textAnchor="middle" dominantBaseline="central" className="fill-slate-900 text-[17px] font-bold dark:fill-slate-100">
        {score}
      </text>
    </svg>
  );
}

export function VerdictCard({ report }: { report: Report }) {
  const v = VERDICT[report.verdict];
  const from = report.email.from;
  return (
    <div className={`rounded-lg p-3 ${v.bg}`}>
      <div className="flex items-center gap-3">
        <ScoreRing score={report.score} ringClass={v.ring} />
        <div className="min-w-0">
          <div className={`text-base font-semibold ${v.text}`}>{v.label}</div>
          <p className="text-xs text-slate-600 dark:text-slate-300">{v.note}</p>
        </div>
      </div>
      <div className="mt-3 space-y-0.5 border-t border-black/5 pt-2 text-xs dark:border-white/10">
        <div className="truncate font-medium text-slate-900 dark:text-slate-100" title={report.email.subject}>
          {report.email.subject || '(no subject)'}
        </div>
        <div className="truncate text-slate-600 dark:text-slate-400" title={from?.address}>
          {from ? (
            <>
              {from.name && <span>{from.name} · </span>}
              <span className="font-mono">{from.address}</span>
            </>
          ) : (
            'Unknown sender'
          )}
        </div>
      </div>
    </div>
  );
}

function FindingRow({ f }: { f: Finding }) {
  const s = SEVERITY_STYLE[f.severity];
  return (
    <li className="flex gap-2.5 py-2">
      <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${s.dot}`} title={s.label} />
      <div className="min-w-0">
        <div className="text-[13px] font-medium leading-snug text-slate-900 dark:text-slate-100">{f.title}</div>
        {f.detail && <div className="mt-0.5 break-words text-xs text-slate-600 dark:text-slate-400">{f.detail}</div>}
      </div>
    </li>
  );
}

function Group({ title, findings }: { title: string; findings: Finding[] }) {
  if (!findings.length) return null;
  return (
    <>
      <SectionTitle>{title}</SectionTitle>
      <Card className="!py-0">
        <ul className="divide-y divide-slate-100 dark:divide-slate-800">
          {findings.map((f) => (
            <FindingRow key={f.id} f={f} />
          ))}
        </ul>
      </Card>
    </>
  );
}

export function Overview({ report }: { report: Report }) {
  const red = report.findings.filter((f) => f.points > 0 && f.severity !== 'info' && f.severity !== 'good');
  const good = report.findings.filter((f) => f.severity === 'good');
  const notes = report.findings.filter((f) => !red.includes(f) && !good.includes(f));
  return (
    <div>
      <Group title={`Red flags (${red.length})`} findings={red} />
      {!red.length && <p className="mt-3 text-sm text-slate-600 dark:text-slate-400">No red flags were found by the local checks.</p>}
      <Group title="Good signs" findings={good} />
      <Group title="Notes" findings={notes} />
    </div>
  );
}
