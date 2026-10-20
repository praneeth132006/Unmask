import type { Report, TrackerPixel } from '../../core/types';
import { describePixelPlace } from '../pixelPlace';
import { Button, Card, CopyButton, Mono, Pill, SectionTitle } from './ui';
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

export function PrivacyTab({
  report,
  onShowPixel,
  onHoverPixel,
}: {
  report: Report;
  /** Open the Body tab with this pixel's tag highlighted. */
  onShowPixel?: (n: number) => void;
  /** Mark this pixel's spot in the email open in Gmail (null clears). */
  onHoverPixel?: (p: TrackerPixel | null) => void;
}) {
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
          <SectionTitle>Where the tracking pixels are ({pixels.length})</SectionTitle>
          <Card className="!p-0">
            <ul className="divide-y divide-[var(--border)]">
              {pixels.map((p) => (
                <li key={p.n} id={`unmask-pixel-${p.n}`} className="px-3 py-2.5" onMouseEnter={() => onHoverPixel?.(p)} onMouseLeave={() => onHoverPixel?.(null)}>
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <span className="font-semibold">
                      <span className="mr-1.5 inline-block rounded-full bg-[var(--bad)] px-1.5 text-[10px] font-bold text-white">{p.n}</span>
                      {p.service ?? 'Unknown service'} <span className="font-normal text-[var(--text-3)]">· {p.host}</span>
                    </span>
                  </div>
                  <dl className="mt-1.5 space-y-1 text-[11.5px] leading-snug">
                    <div>
                      <dt className="inline font-medium text-[var(--text)]">Where: </dt>
                      <dd className="inline text-[var(--text-2)]">{describePixelPlace(p)}</dd>
                    </div>
                    <div>
                      <dt className="inline font-medium text-[var(--text)]">Why it’s a pixel: </dt>
                      <dd className="inline text-[var(--text-2)]">{p.reason}{p.size && !p.reason.includes(p.size) ? ` (size ${p.size})` : ''}.</dd>
                    </div>
                    <div>
                      <dt className="font-medium text-[var(--text)]">Address it loads from:</dt>
                      <dd className="flex items-start gap-1">
                        <Mono className="block text-[10px]">{p.src.length > 200 ? `${p.src.slice(0, 200)}…` : p.src}</Mono>
                        <CopyButton value={p.src} />
                      </dd>
                    </div>
                  </dl>
                  {onShowPixel && (
                    <Button className="mt-2" onClick={() => onShowPixel(p.n)}>
                      Show it in the safe view
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          </Card>
          {onHoverPixel && <p className="mt-1.5 text-[11px] text-[var(--text-3)]">With the email open in Gmail, hover a pixel to mark its spot there (it only shows if Gmail is displaying the email’s images).</p>}
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
