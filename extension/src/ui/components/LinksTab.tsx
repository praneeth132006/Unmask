import { useState } from 'react';
import type { Finding, LinkInfo, Report } from '../../core/types';
import type { Settings } from '../../lib/settings';
import { traceRedirects, type TraceResult } from '../../integrations/trace';
import { scanUrl, urlscanFindings, type UrlscanResult } from '../../integrations/urlscan';
import { lookupUrl, vtFindings, type VtResult } from '../../integrations/virustotal';
import { Button, Card, CopyButton, ErrorText, Mono, Pill, Spinner, type Async } from './ui';
import { Icon } from './Icon';

interface LinkState {
  trace?: Async<TraceResult>;
  urlscan?: Async<UrlscanResult>;
  vt?: Async<VtResult>;
}

function errMsg(e: unknown) {
  return e instanceof Error ? e.message : String(e);
}

function LinkCard({ link, settings, onFindings, index }: { link: LinkInfo; settings: Settings; onFindings: (f: Finding[]) => void; index: number }) {
  const [state, setState] = useState<LinkState>({});
  const set = (patch: LinkState) => setState((s) => ({ ...s, ...patch }));
  const target = link.resolved;
  const worst = link.flags[0]?.severity;
  const canScan = /^https?:/i.test(target);
  // Bold the real host so it stands out from long paths and query strings.
  const hostAt = link.host ? target.toLowerCase().indexOf(link.host) : -1;

  const runTrace = async () => {
    set({ trace: { status: 'loading' } });
    try {
      set({ trace: { status: 'done', value: await traceRedirects(settings.backendUrl, target) } });
    } catch (e) {
      set({ trace: { status: 'error', error: errMsg(e) } });
    }
  };
  const runUrlscan = async () => {
    set({ urlscan: { status: 'loading', message: 'Submitting…' } });
    try {
      const value = await scanUrl(settings.urlscanApiKey, target, settings.urlscanVisibility, (message) => set({ urlscan: { status: 'loading', message } }));
      set({ urlscan: { status: 'done', value } });
      onFindings(urlscanFindings(`urlscan-${index}`, value));
    } catch (e) {
      set({ urlscan: { status: 'error', error: errMsg(e) } });
    }
  };
  const runVt = async () => {
    set({ vt: { status: 'loading' } });
    try {
      const value = await lookupUrl(settings.vtApiKey, target);
      set({ vt: { status: 'done', value } });
      onFindings(vtFindings(`vt-url-${index}`, link.host || 'this link', value, 'links').filter((f) => f.points > 0));
    } catch (e) {
      set({ vt: { status: 'error', error: errMsg(e) } });
    }
  };

  return (
    <Card className={worst === 'critical' || worst === 'high' ? 'border-red-300 dark:border-red-900' : ''}>
      <div className="text-[11px] uppercase tracking-wide text-slate-500">Shows</div>
      <div className="break-words text-[13px] font-medium text-slate-900 dark:text-slate-100">{link.text || <span className="italic text-slate-400">(no text: image or empty link)</span>}</div>

      <div className="mt-2 flex items-center justify-between text-[11px] uppercase tracking-wide text-slate-500">
        <span>Really goes to</span>
        <CopyButton value={target} />
      </div>
      <Mono className="block">
        {hostAt >= 0 ? (
          <>
            {target.slice(0, hostAt)}
            <strong className="text-slate-950 dark:text-white">{target.slice(hostAt, hostAt + link.host.length)}</strong>
            {target.slice(hostAt + link.host.length)}
          </>
        ) : (
          target
        )}
      </Mono>
      {link.unwrappedVia.length > 0 && <div className="mt-1 text-[11px] text-slate-500">Unwrapped from: {link.unwrappedVia.join(' → ')}</div>}

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
        <div className="mt-2.5 flex flex-wrap gap-1.5">
          <Button onClick={runTrace} disabled={state.trace?.status === 'loading'} title="Follow redirects from the Unmask server, without opening the link in your browser">
            {state.trace?.status === 'loading' && <Spinner />} Trace redirects
          </Button>
          <Button onClick={runUrlscan} disabled={state.urlscan?.status === 'loading'} title="Open the link in urlscan.io's sandbox browser and take a screenshot">
            {state.urlscan?.status === 'loading' && <Spinner />} Sandbox scan
          </Button>
          <Button onClick={runVt} disabled={state.vt?.status === 'loading'} title="Look up an existing VirusTotal report for this URL">
            {state.vt?.status === 'loading' && <Spinner />} VirusTotal
          </Button>
        </div>
      )}

      {state.trace?.status === 'error' && <ErrorText>{state.trace.error}</ErrorText>}
      {state.trace?.status === 'done' && (
        <div className="mt-2 rounded-md bg-slate-50 p-2 dark:bg-slate-800/60">
          <div className="mb-1 text-[11px] font-semibold text-slate-600 dark:text-slate-300">Redirect chain ({state.trace.value.hops.length} hop{state.trace.value.hops.length === 1 ? '' : 's'})</div>
          <ol className="space-y-1">
            {state.trace.value.hops.map((h, i) => (
              <li key={i} className="flex gap-1.5 text-[11px]">
                <span className="w-9 shrink-0 font-mono text-slate-500">{h.status || '—'}</span>
                <Mono>{h.url}</Mono>
              </li>
            ))}
          </ol>
          {state.trace.value.error && <ErrorText>{state.trace.value.error}</ErrorText>}
          {state.trace.value.truncated && <p className="mt-1 text-[11px] text-amber-600">Stopped after too many redirects.</p>}
        </div>
      )}

      {state.urlscan?.status === 'loading' && <p className="mt-1 text-[11px] text-slate-500">{state.urlscan.message}</p>}
      {state.urlscan?.status === 'error' && <ErrorText>{state.urlscan.error}</ErrorText>}
      {state.urlscan?.status === 'done' && (
        <div className="mt-2 rounded-md bg-slate-50 p-2 dark:bg-slate-800/60">
          <div className="flex items-center justify-between">
            <Pill severity={state.urlscan.value.malicious ? 'critical' : 'info'}>{state.urlscan.value.malicious ? 'Malicious' : 'No verdict'}</Pill>
            <a className="inline-flex items-center gap-1 text-[11px] text-indigo-600 hover:underline dark:text-indigo-400" href={state.urlscan.value.reportUrl} target="_blank" rel="noreferrer">
              Full report <Icon name="external" className="h-3 w-3" />
            </a>
          </div>
          <div className="mt-1 text-[11px] text-slate-600 dark:text-slate-300">
            Final page: <Mono>{state.urlscan.value.finalUrl ?? 'unknown'}</Mono>
          </div>
          {state.urlscan.value.title && <div className="text-[11px] text-slate-600 dark:text-slate-300">Title: {state.urlscan.value.title}</div>}
          {state.urlscan.value.brands.length > 0 && <div className="text-[11px] text-red-600">Impersonates: {state.urlscan.value.brands.join(', ')}</div>}
          <img src={state.urlscan.value.screenshot} alt="Screenshot of the page taken by urlscan.io" className="mt-2 w-full rounded border border-slate-200 dark:border-slate-700" />
        </div>
      )}

      {state.vt?.status === 'error' && <ErrorText>{state.vt.error}</ErrorText>}
      {state.vt?.status === 'done' && (
        <div className="mt-2 flex items-center justify-between text-[11px]">
          <span className="text-slate-700 dark:text-slate-300">
            {state.vt.value.found && state.vt.value.stats
              ? `VirusTotal: ${state.vt.value.stats.malicious + state.vt.value.stats.suspicious} vendors flag this URL`
              : 'VirusTotal has no report for this URL'}
          </span>
          <a className="text-indigo-600 hover:underline dark:text-indigo-400" href={state.vt.value.permalink} target="_blank" rel="noreferrer">
            Open
          </a>
        </div>
      )}
    </Card>
  );
}

export function LinksTab({ report, settings, onFindings }: { report: Report; settings: Settings; onFindings: (f: Finding[]) => void }) {
  const [showAll, setShowAll] = useState(false);
  const flagged = report.links.filter((l) => l.flags.length);
  const clean = report.links.filter((l) => !l.flags.length);
  const shown = showAll ? [...flagged, ...clean] : flagged.length ? flagged : clean.slice(0, 10);

  if (!report.links.length) return <p className="text-sm text-slate-600 dark:text-slate-400">This email contains no links.</p>;
  return (
    <div className="space-y-2">
      <p className="text-xs text-slate-600 dark:text-slate-400">
        {report.links.length} link{report.links.length === 1 ? '' : 's'}, {flagged.length} with warnings. Nothing here opens the link in your browser: tracing and scanning run on other servers.
      </p>
      {shown.map((link) => {
        const index = report.links.indexOf(link);
        return <LinkCard key={index} index={index} link={link} settings={settings} onFindings={onFindings} />;
      })}
      {shown.length < report.links.length && (
        <Button variant="ghost" className="w-full" onClick={() => setShowAll(true)}>
          Show all {report.links.length} links
        </Button>
      )}
    </div>
  );
}
