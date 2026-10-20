import type { Report } from '../../core/types';
import { Card, Mono, Pill, SectionTitle } from './ui';
import { Icon } from './Icon';

function Stat({ value, label, tone }: { value: number; label: string; tone: 'bad' | 'warn' | 'good' }) {
  const color = { bad: 'text-[var(--bad)]', warn: 'text-[var(--warn)]', good: 'text-[var(--good)]' }[tone];
  return (
    <div className="flex-1 rounded-lg bg-[var(--surface-2)] px-2.5 py-2">
      <div className={`text-lg font-semibold leading-tight ${color}`}>{value}</div>
      <div className="text-[11px] text-[var(--text-3)]">{label}</div>
    </div>
  );
}

export function PrivacyTab({ report }: { report: Report }) {
  const { pixels, trackedLinkCount, services, remoteImages } = report.trackers;
  const tracked = pixels.length > 0 || trackedLinkCount > 0;

  return (
    <div>
      <Card>
        <div className="flex items-start gap-2.5">
          <span className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg ${tracked ? 'bg-[var(--warn-soft)] text-[var(--warn)]' : 'bg-[var(--good-soft)] text-[var(--good)]'}`}>
            <Icon name="eye" className="h-4 w-4" />
          </span>
          <div>
            <div className="text-[13px] font-semibold">{tracked ? 'This email tracks you' : 'No tracking found'}</div>
            <p className="mt-0.5 text-xs text-[var(--text-2)]">
              {tracked
                ? 'When its images load, the sender learns that you opened it and when. In Gmail, images are fetched through Google’s proxy, so your IP address stays hidden; in other mail apps the sender can also see your IP address and device. Tracked links report only when clicked. Unmask’s safe view and Peek load no images.'
                : 'No known tracking pixels or click-tracked links were found. Any remote image can still reveal that you opened it.'}
            </p>
          </div>
        </div>
        <div className="mt-3 flex gap-2">
          <Stat value={pixels.length} label={`tracking pixel${pixels.length === 1 ? '' : 's'}`} tone={pixels.length ? 'warn' : 'good'} />
          <Stat value={trackedLinkCount} label={`tracked link${trackedLinkCount === 1 ? '' : 's'}`} tone={trackedLinkCount ? 'warn' : 'good'} />
          <Stat value={remoteImages} label={`remote image${remoteImages === 1 ? '' : 's'}`} tone={remoteImages ? 'warn' : 'good'} />
        </div>
        {services.length > 0 && (
          <div className="mt-3">
            <div className="mb-1 text-[11px] text-[var(--text-3)]">Tracking services</div>
            <div className="flex flex-wrap gap-1">
              {services.map((s) => (
                <Pill key={s} severity="medium">
                  {s}
                </Pill>
              ))}
            </div>
          </div>
        )}
      </Card>

      {pixels.length > 0 && (
        <>
          <SectionTitle>Tracking pixels</SectionTitle>
          <Card className="!p-0">
            <ul className="divide-y divide-[var(--border)]">
              {pixels.map((p, i) => (
                <li key={i} className="px-3 py-2">
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-medium">{p.service ?? p.host}</span>
                    <span className="text-[11px] text-[var(--text-3)]">{p.reason}</span>
                  </div>
                  <Mono className="mt-0.5 block text-[10px]">{p.src.length > 160 ? `${p.src.slice(0, 160)}…` : p.src}</Mono>
                </li>
              ))}
            </ul>
          </Card>
        </>
      )}

      <SectionTitle>How to avoid tracking</SectionTitle>
      <Card>
        <ul className="list-disc space-y-1 pl-4 text-xs text-[var(--text-2)]">
          <li>In Gmail: Settings → General → Images → <em>Ask before displaying external images</em>.</li>
          <li>Read suspicious emails in Unmask’s Body tab, where remote images stay blocked.</li>
          <li>Avoid clicking tracked links in emails you didn’t expect; visit the site directly instead.</li>
        </ul>
      </Card>
    </div>
  );
}
