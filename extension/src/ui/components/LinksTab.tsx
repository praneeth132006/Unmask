import { useState } from 'react';
import type { Finding, LinkInfo, Report } from '../../core/types';
import type { Settings } from '../../lib/settings';
import { traceRedirects, type TraceResult } from '../../integrations/trace';
import { scanUrl, urlscanFindings, type UrlscanResult } from '../../integrations/urlscan';
import { lookupUrl, vtFindings, type VtResult } from '../../integrations/virustotal';
import { Button, Card, CopyButton, ErrorText, Label, Mono, Pill, Spinner, type Async } from './ui';
import { Icon } from './Icon';
import { ServiceSetup, type Service } from './ServiceSetup';

interface LinkState {
  trace?: Async<TraceResult>;
  urlscan?: Async<UrlscanResult>;
  vt?: Async<VtResult>;
}

type Action = 'trace' | 'urlscan' | 'vt';
const NEEDS: Record<Action, { service: Service; field: keyof Settings }> = {
  trace: { service: 'backend', field: 'backendUrl' },
  urlscan: { service: 'urlscan', field: 'urlscanApiKey' },
  vt: { service: 'virustotal', field: 'vtApiKey' },
};

function errMsg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

export interface LinkTabProps {
  report: Report;
  settings: Settings;
  onSettingsChange: (s: Settings) => void;
  onFindings: (f: Finding[]) => void;
  /** Index of the link to scroll to and flash, set when the user clicks a finding. */
  focusIndex?: number | null;
  onHoverLink?: (link: LinkInfo | null) => void;
}

function LinkCard({
  link,
  index,
  settings,
  onSettingsChange,
  onFindings,
  focused,
  onHover,
}: {
  link: LinkInfo;
  index: number;
  settings: Settings;
  onSettingsChange: (s: Settings) => void;
  onFindings: (f: Finding[]) => void;
  focused: boolean;
  onHover?: (link: LinkInfo | null) => void;
}) {
  const [state, setState] = useState<LinkState>({});
  const [setup, setSetup] = useState<Action | null>(null);
  const set = (patch: LinkState) => setState((s) => ({ ...s, ...patch }));
  const target = link.resolved;
  const worst = link.flags[0]?.severity;
  const risky = worst === 'critical' || worst === 'high';
  const canScan = /^https?:/i.test(target);
  // Bold the real host so it stands out from long paths and query strings.
  const hostAt = link.host ? target.toLowerCase().indexOf(link.host) : -1;

  const run = async (action: Action, s: Settings = settings) => {
    if (!s[NEEDS[action].field]) {
      setSetup(action);
      return;
    }
    setSetup(null);
    if (action === 'trace') {
      set({ trace: { status: 'loading' } });
      try {
        set({ trace: { status: 'done', value: await traceRedirects(s.backendUrl, target) } });
      } catch (e) {
        set({ trace: { status: 'error', error: errMsg(e) } });
      }
    } else if (action === 'urlscan') {
      set({ urlscan: { status: 'loading', message: 'Submitting…' } });
      try {
        const value = await scanUrl(s.urlscanApiKey, target, s.urlscanVisibility, (message) => set({ urlscan: { status: 'loading', message } }));
        set({ urlscan: { status: 'done', value } });
        onFindings(urlscanFindings(`urlscan-${index}`, value));
      } catch (e) {
        set({ urlscan: { status: 'error', error: errMsg(e) } });
      }
    } else {
      set({ vt: { status: 'loading' } });
      try {
        const value = await lookupUrl(s.vtApiKey, target);
        set({ vt: { status: 'done', value } });
        onFindings(vtFindings(`vt-url-${index}`, link.host || 'this link', value, 'links').filter((f) => f.points > 0));
      } catch (e) {
        set({ vt: { status: 'error', error: errMsg(e) } });
      }
    }
  };

  return (
    <Card
      id={`unmask-link-${index}`}
      className={`${risky ? 'border-l-[3px] !border-l-[var(--bad)]' : ''} ${focused ? 'unmask-flash' : ''}`}
      onMouseEnter={() => onHover?.(link)}
      onMouseLeave={() => onHover?.(null)}
    >
      <Label>Shows</Label>
      <div className="mt-0.5 break-words text-[13px] font-medium">{link.text || <span className="italic text-[var(--text-3)]">(no text: image or empty link)</span>}</div>

      <div className="mt-2.5 flex items-center justify-between">
        <Label>Really goes to</Label>
        <CopyButton value={target} />
      </div>
      <Mono className="mt-0.5 block leading-relaxed">
        {hostAt >= 0 ? (
          <>
            {target.slice(0, hostAt)}
            <strong className="font-semibold text-[var(--text)]">{target.slice(hostAt, hostAt + link.host.length)}</strong>
            {target.slice(hostAt + link.host.length)}
          </>
        ) : (
          target
        )}
      </Mono>
      {link.unwrappedVia.length > 0 && <div className="mt-1 text-[11px] text-[var(--text-3)]">Unwrapped from: {link.unwrappedVia.join(' → ')}</div>}

      {link.flags.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {link.flags.map((f) => (
            <Pill key={f.id} severity={f.severity}>
              {f.label}
            </Pill>
          ))}
        </div>
      )}

      {canScan && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          <Button onClick={() => void run('urlscan')} disabled={state.urlscan?.status === 'loading'} title="Open the link in urlscan.io's sandbox browser and take a screenshot">
            {state.urlscan?.status === 'loading' ? <Spinner /> : <Icon name="eye" className="h-3.5 w-3.5" />} Sandbox scan
          </Button>
          <Button onClick={() => void run('vt')} disabled={state.vt?.status === 'loading'} title="Look up this URL on VirusTotal">
            {state.vt?.status === 'loading' ? <Spinner /> : <Icon name="shield" className="h-3.5 w-3.5" />} VirusTotal
          </Button>
          <Button variant="ghost" onClick={() => void run('trace')} disabled={state.trace?.status === 'loading'} title="Follow redirects from your Unmask server">
            {state.trace?.status === 'loading' && <Spinner />} Trace redirects
          </Button>
        </div>
      )}

      {setup && (
        <div className="mt-3">
          <ServiceSetup
            compact
            service={NEEDS[setup].service}
            settings={settings}
            onCancel={() => setSetup(null)}
            onSaved={(s) => {
              onSettingsChange(s);
              void run(setup, s);
            }}
          />
          {setup === 'trace' && <p className="mt-1.5 text-[11px] text-[var(--text-3)]">No server? <strong>Sandbox scan</strong> also shows where a link ends up, with no setup beyond a free key.</p>}
        </div>
      )}

      {state.trace?.status === 'error' && <ErrorText>{state.trace.error}</ErrorText>}
      {state.trace?.status === 'done' && (
        <div className="mt-2.5 rounded-lg bg-[var(--surface-2)] p-2.5">
          <div className="mb-1 text-[11px] font-semibold text-[var(--text-2)]">
            Redirect chain ({state.trace.value.hops.length} step{state.trace.value.hops.length === 1 ? '' : 's'})
          </div>
          <ol className="space-y-1">
            {state.trace.value.hops.map((h, i) => (
              <li key={i} className="flex gap-1.5 text-[11px]">
                <span className="w-9 shrink-0 font-mono text-[var(--text-3)]">{h.status || '—'}</span>
                <Mono>{h.url}</Mono>
              </li>
            ))}
          </ol>
          {state.trace.value.error && <ErrorText>{state.trace.value.error}</ErrorText>}
          {state.trace.value.truncated && <p className="mt-1 text-[11px] text-[var(--warn)]">Stopped after too many redirects.</p>}
        </div>
      )}

      {state.urlscan?.status === 'loading' && <p className="mt-1.5 text-[11px] text-[var(--text-3)]">{state.urlscan.message}</p>}
      {state.urlscan?.status === 'error' && <ErrorText>{state.urlscan.error}</ErrorText>}
      {state.urlscan?.status === 'done' && (
        <div className="mt-2.5 rounded-lg bg-[var(--surface-2)] p-2.5">
          <div className="flex items-center justify-between">
            <Pill severity={state.urlscan.value.malicious ? 'critical' : 'info'}>{state.urlscan.value.malicious ? 'Malicious' : 'No verdict from urlscan'}</Pill>
            <a className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--accent)] hover:underline" href={state.urlscan.value.reportUrl} target="_blank" rel="noreferrer">
              Full report <Icon name="external" className="h-3 w-3" />
            </a>
          </div>
          <div className="mt-1.5 text-[11px] text-[var(--text-2)]">
            Lands on: <Mono>{state.urlscan.value.finalUrl ?? 'unknown'}</Mono>
          </div>
          {state.urlscan.value.title && <div className="text-[11px] text-[var(--text-2)]">Page title: {state.urlscan.value.title}</div>}
          {state.urlscan.value.brands.length > 0 && <div className="text-[11px] font-medium text-[var(--bad)]">Pretends to be: {state.urlscan.value.brands.join(', ')}</div>}
          <img src={state.urlscan.value.screenshot} alt="Screenshot of the page taken by urlscan.io" className="mt-2 w-full rounded-md border border-[var(--border)]" />
        </div>
      )}

      {state.vt?.status === 'error' && <ErrorText>{state.vt.error}</ErrorText>}
      {state.vt?.status === 'done' && (
        <div className="mt-2.5 flex items-center justify-between rounded-lg bg-[var(--surface-2)] px-2.5 py-2 text-[11px]">
          <span className={state.vt.value.stats && state.vt.value.stats.malicious + state.vt.value.stats.suspicious > 0 ? 'font-semibold text-[var(--bad)]' : 'text-[var(--text-2)]'}>
            {state.vt.value.found && state.vt.value.stats
              ? `VirusTotal: ${state.vt.value.stats.malicious + state.vt.value.stats.suspicious} security vendors flag this URL`
              : 'VirusTotal has no report for this URL yet'}
          </span>
          <a className="font-medium text-[var(--accent)] hover:underline" href={state.vt.value.permalink} target="_blank" rel="noreferrer">
            Open
          </a>
        </div>
      )}
    </Card>
  );
}

export function LinksTab({ report, settings, onSettingsChange, onFindings, focusIndex, onHoverLink }: LinkTabProps) {
  const [showAll, setShowAll] = useState(false);
  const flagged = report.links.filter((l) => l.flags.length);
  const clean = report.links.filter((l) => !l.flags.length);
  const focusHidden = focusIndex != null && !flagged.includes(report.links[focusIndex]!);
  const shown = showAll || focusHidden ? [...flagged, ...clean] : flagged.length ? flagged : clean.slice(0, 10);

  if (!report.links.length) return <p className="text-sm text-[var(--text-2)]">This email contains no links.</p>;
  return (
    <div className="space-y-2.5">
      <p className="text-xs text-[var(--text-2)]">
        <strong className="text-[var(--text)]">{report.links.length}</strong> link{report.links.length === 1 ? '' : 's'}, <strong className={flagged.length ? 'text-[var(--bad)]' : 'text-[var(--text)]'}>{flagged.length}</strong> with warnings.
        Hover a link to find it in the email. Nothing here opens the link in your browser.
      </p>
      {shown.map((link) => {
        const index = report.links.indexOf(link);
        return (
          <LinkCard
            key={index}
            index={index}
            link={link}
            settings={settings}
            onSettingsChange={onSettingsChange}
            onFindings={onFindings}
            focused={focusIndex === index}
            onHover={onHoverLink}
          />
        );
      })}
      {shown.length < report.links.length && (
        <Button variant="ghost" className="w-full" onClick={() => setShowAll(true)}>
          Show the other {report.links.length - shown.length} links (no warnings)
        </Button>
      )}
    </div>
  );
}
