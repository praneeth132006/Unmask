import { useCallback, useEffect, useRef, useState, type DragEvent } from 'react';
import { analyzeRawEmail, withExtraFindings } from '../core/analyze';
import type { Finding, Report } from '../core/types';
import { domainAgeFindings, lookupDomainAge, type DomainAge } from '../integrations/rdap';
import { registrableDomain } from '../lib/domain';
import { DEFAULT_SETTINGS, loadSettings, type Settings } from '../lib/settings';
import { brandOwningDomain, FREE_MAIL_DOMAINS } from '../analyzers/brands';
import { GmailFetchError, messageKey, useGmail } from './useGmail';
import { Overview, VerdictCard } from './components/Overview';
import { SenderTab } from './components/SenderTab';
import { LinksTab } from './components/LinksTab';
import { AttachmentsTab } from './components/AttachmentsTab';
import { BodyTab } from './components/BodyTab';
import { HeadersTab } from './components/HeadersTab';
import { SettingsPanel } from './components/SettingsPanel';
import { Button, CopyButton, Spinner, type Async } from './components/ui';
import { Icon } from './components/Icon';

type TabId = 'overview' | 'sender' | 'links' | 'attachments' | 'body' | 'headers';

type Source = { kind: 'gmail'; key: string } | { kind: 'file'; name: string };

export function App() {
  const gmail = useGmail();
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [showSettings, setShowSettings] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [source, setSource] = useState<Source | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<{ message: string; details: string[] } | null>(null);
  const [tab, setTab] = useState<TabId>('overview');
  const [domainAge, setDomainAge] = useState<Async<DomainAge>>({ status: 'idle' });
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [pasting, setPasting] = useState(false);
  const [dragging, setDragging] = useState(false);
  const runId = useRef(0);
  const cache = useRef(new Map<string, Report>());

  useEffect(() => {
    void loadSettings().then(setSettings);
  }, []);

  /** Merge findings from online checks, ignoring results that arrive after the user moved on. */
  const addFindings = useCallback((run: number, findings: Finding[]) => {
    if (run !== runId.current || !findings.length) return;
    setReport((r) => (r ? withExtraFindings(r, findings) : r));
  }, []);

  const checkDomainAge = useCallback(
    async (r: Report, run: number) => {
      const domain = r.email.from ? registrableDomain(r.email.from.domain) : '';
      if (!domain) return;
      setDomainAge({ status: 'loading' });
      try {
        const age = await lookupDomainAge(domain);
        if (run !== runId.current) return;
        setDomainAge({ status: 'done', value: age });
        // Big providers and known brands are obviously old; don't clutter the report.
        if (!FREE_MAIL_DOMAINS.has(domain) && !brandOwningDomain(domain)) addFindings(run, domainAgeFindings(age, 'sender'));
      } catch (e) {
        if (run === runId.current) setDomainAge({ status: 'error', error: e instanceof Error ? e.message : String(e) });
      }
    },
    [addFindings],
  );

  const analyze = useCallback(
    async (load: () => Promise<string | ArrayBuffer>, src: Source, cacheKey?: string) => {
      const run = ++runId.current;
      setSource(src);
      setError(null);
      setDomainAge({ status: 'idle' });
      setTab('overview');
      const cached = cacheKey ? cache.current.get(cacheKey) : undefined;
      if (cached) {
        setReport(cached);
      } else {
        setLoading(true);
        setReport(null);
      }
      try {
        const r = cached ?? (await analyzeRawEmail(await load()));
        if (run !== runId.current) return;
        if (cacheKey) cache.current.set(cacheKey, r);
        setReport(r);
        if (settings.autoDomainAge) void checkDomainAge(r, run);
      } catch (e) {
        if (run === runId.current) {
          setError({ message: e instanceof Error ? e.message : String(e), details: e instanceof GmailFetchError ? e.details : [] });
        }
      } finally {
        if (run === runId.current) setLoading(false);
      }
    },
    [settings.autoDomainAge, checkDomainAge],
  );

  // Follow the email that is open in Gmail.
  const messages = gmail.state?.messages ?? [];
  useEffect(() => {
    if (source?.kind === 'file') return;
    const keys = messages.map(messageKey);
    const key = selectedKey && keys.includes(selectedKey) ? selectedKey : (keys[keys.length - 1] ?? null);
    if (!key) {
      if (source?.kind === 'gmail') {
        runId.current++; // drop any analysis still in flight for the email that was closed
        setSource(null);
        setReport(null);
        setError(null);
        setLoading(false);
      }
      return;
    }
    if (source?.kind === 'gmail' && source.key === key) return;
    const msg = messages.find((m) => messageKey(m) === key)!;
    void analyze(() => gmail.fetchRaw(msg), { kind: 'gmail', key }, key);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(messages), selectedKey, source]);

  const retry = () => {
    if (source?.kind !== 'gmail') return;
    const msg = messages.find((m) => messageKey(m) === source.key);
    if (msg) void analyze(() => gmail.fetchRaw(msg), { kind: 'gmail', key: source.key }, undefined);
  };

  const openFile = (file: File) => {
    void analyze(() => file.arrayBuffer(), { kind: 'file', name: file.name });
  };

  const backToGmail = () => {
    runId.current++;
    setSource(null);
    setReport(null);
    setError(null);
  };

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) openFile(file);
  };

  const tabs: { id: TabId; label: string; count?: number }[] = report
    ? [
        { id: 'overview', label: 'Overview' },
        { id: 'sender', label: 'Sender' },
        { id: 'links', label: 'Links', count: report.links.length },
        { id: 'attachments', label: 'Files', count: report.attachments.length },
        { id: 'body', label: 'Body' },
        { id: 'headers', label: 'Headers' },
      ]
    : [];

  const onFindings = (findings: Finding[]) => addFindings(runId.current, findings);

  return (
    <div
      className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100"
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(e) => {
        if (e.currentTarget === e.target) setDragging(false);
      }}
      onDrop={onDrop}
    >
      <header className="sticky top-0 z-10 flex items-center justify-between border-b border-slate-200 bg-white/90 px-3 py-2 backdrop-blur dark:border-slate-800 dark:bg-slate-900/90">
        <div className="flex items-center gap-1.5">
          <span className="flex h-6 w-6 items-center justify-center rounded-md bg-indigo-600 text-white">
            <Icon name="mask" className="h-4 w-4" />
          </span>
          <span className="text-sm font-semibold">Unmask</span>
        </div>
        <div className="flex items-center gap-0.5">
          <label className="cursor-pointer rounded-md p-1.5 text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800" title="Open an .eml file">
            <Icon name="upload" />
            <input
              type="file"
              accept=".eml,message/rfc822,.txt"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) openFile(f);
                e.target.value = '';
              }}
            />
          </label>
          <Button variant="ghost" className="!p-1.5" title="Paste raw email source" onClick={() => setPasting(true)}>
            <Icon name="paste" />
          </Button>
          <Button variant="ghost" className="!p-1.5" title="Settings" onClick={() => setShowSettings(true)}>
            <Icon name="gear" />
          </Button>
        </div>
      </header>

      <main className="p-3">
        {showSettings ? (
          <SettingsPanel
            settings={settings}
            onClose={() => setShowSettings(false)}
            onSaved={(s) => {
              setSettings(s);
              setShowSettings(false);
            }}
          />
        ) : pasting ? (
          <PasteBox
            onCancel={() => setPasting(false)}
            onSubmit={(raw) => {
              setPasting(false);
              void analyze(async () => raw, { kind: 'file', name: 'Pasted source' });
            }}
          />
        ) : (
          <>
            {source?.kind === 'file' && (
              <div className="mb-2 flex items-center justify-between rounded-md bg-indigo-50 px-2 py-1 text-xs text-indigo-900 dark:bg-indigo-950/50 dark:text-indigo-200">
                <span className="truncate">Analyzing {source.name}</span>
                {gmail.status === 'ready' && (
                  <button type="button" className="shrink-0 underline" onClick={backToGmail}>
                    Back to Gmail
                  </button>
                )}
              </div>
            )}

            {source?.kind !== 'file' && messages.length > 1 && (
              <select
                className="mb-2 w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 text-xs dark:border-slate-700 dark:bg-slate-900"
                value={source?.kind === 'gmail' ? source.key : ''}
                onChange={(e) => setSelectedKey(e.target.value)}
                aria-label="Which message in this thread"
              >
                {messages.map((m, i) => (
                  <option key={messageKey(m)} value={messageKey(m)}>
                    {i + 1}. {m.fromName || m.fromEmail || 'Unknown sender'}
                  </option>
                ))}
              </select>
            )}

            {loading && (
              <div className="flex items-center gap-2 py-10 text-sm text-slate-600 dark:text-slate-300">
                <Spinner /> Reading and analyzing the email…
              </div>
            )}

            {error && !loading && (
              <div className="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200">
                <p className="font-semibold">Could not analyze this email</p>
                <p className="mt-1 text-xs">{error.message}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {source?.kind === 'gmail' && (
                    <Button variant="secondary" onClick={retry}>
                      <Icon name="refresh" className="h-3.5 w-3.5" /> Try again
                    </Button>
                  )}
                  <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-slate-300 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-800 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100">
                    <Icon name="upload" className="h-3.5 w-3.5" /> Open .eml file
                    <input type="file" accept=".eml,message/rfc822,.txt" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) openFile(f); e.target.value = ''; }} />
                  </label>
                </div>
                {error.details.length > 0 && (
                  <details className="mt-2 text-xs">
                    <summary className="cursor-pointer select-none">Technical details</summary>
                    <ul className="mt-1 space-y-0.5 font-mono text-[10px] break-all">
                      {error.details.map((d, i) => (
                        <li key={i}>{d}</li>
                      ))}
                    </ul>
                    <div className="mt-1">
                      <CopyButton value={error.details.join('\n')} label="Copy details" />
                    </div>
                  </details>
                )}
              </div>
            )}

            {!report && !loading && !error && <EmptyState status={gmail.status} onReload={gmail.reloadTab} />}

            {report && !loading && (
              <>
                <VerdictCard report={report} />
                <nav className="-mx-3 mt-3 flex gap-1 overflow-x-auto border-b border-slate-200 px-3 dark:border-slate-800" role="tablist">
                  {tabs.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      role="tab"
                      aria-selected={tab === t.id}
                      onClick={() => setTab(t.id)}
                      className={`-mb-px whitespace-nowrap border-b-2 px-2 py-1.5 text-xs font-medium ${
                        tab === t.id ? 'border-indigo-600 text-indigo-700 dark:text-indigo-300' : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
                      }`}
                    >
                      {t.label}
                      {t.count !== undefined && t.count > 0 && <span className="ml-1 text-slate-400">{t.count}</span>}
                    </button>
                  ))}
                </nav>
                {/* Remount tab content per analysis so per-link/attachment results don't leak between emails. */}
                <div className="pt-3" key={runId.current}>
                  {tab === 'overview' && <Overview report={report} />}
                  {tab === 'sender' && <SenderTab report={report} domainAge={domainAge} onCheckAge={() => void checkDomainAge(report, runId.current)} />}
                  {tab === 'links' && <LinksTab report={report} settings={settings} onFindings={onFindings} />}
                  {tab === 'attachments' && <AttachmentsTab report={report} settings={settings} onFindings={onFindings} />}
                  {tab === 'body' && <BodyTab report={report} />}
                  {tab === 'headers' && <HeadersTab report={report} />}
                </div>
              </>
            )}
          </>
        )}
      </main>

      {dragging && (
        <div className="pointer-events-none fixed inset-2 z-20 flex items-center justify-center rounded-xl border-2 border-dashed border-indigo-500 bg-indigo-50/90 text-sm font-medium text-indigo-800 dark:bg-indigo-950/90 dark:text-indigo-200">
          Drop the .eml file to analyze it
        </div>
      )}
    </div>
  );
}

function EmptyState({ status, onReload }: { status: ReturnType<typeof useGmail>['status']; onReload: () => void }) {
  return (
    <div className="py-8 text-center">
      <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-indigo-600 text-white">
        <Icon name="mask" className="h-8 w-8" />
      </div>
      {status === 'ready' && <p className="text-sm font-medium">Open an email in Gmail to inspect it.</p>}
      {status === 'no-script' && (
        <>
          <p className="text-sm font-medium">Reload Gmail to connect Unmask.</p>
          <p className="mt-1 text-xs text-slate-500">Gmail was open before Unmask was installed or updated.</p>
          <Button variant="primary" className="mt-3" onClick={onReload}>
            <Icon name="refresh" className="h-3.5 w-3.5" /> Reload Gmail
          </Button>
        </>
      )}
      {status === 'not-gmail' && <p className="text-sm font-medium">Open Gmail to inspect your emails.</p>}
      <p className="mx-auto mt-4 max-w-[280px] text-xs text-slate-500 dark:text-slate-400">
        Using another mail app? Save the email as an <strong>.eml</strong> file and drop it here, or paste its raw source with the clipboard button above.
      </p>
    </div>
  );
}

function PasteBox({ onSubmit, onCancel }: { onSubmit: (raw: string) => void; onCancel: () => void }) {
  const [raw, setRaw] = useState('');
  return (
    <div className="space-y-2">
      <h2 className="text-sm font-semibold">Paste raw email source</h2>
      <p className="text-xs text-slate-600 dark:text-slate-400">
        In Gmail: ⋮ → <em>Show original</em> → <em>Copy to clipboard</em>. In Outlook: File → Properties → Internet headers (headers only).
      </p>
      <textarea
        autoFocus
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
        className="h-64 w-full rounded-md border border-slate-300 bg-white p-2 font-mono text-[11px] dark:border-slate-700 dark:bg-slate-900"
        placeholder={'Delivered-To: you@example.com\nReceived: from …\n…'}
      />
      <div className="flex gap-2">
        <Button variant="primary" disabled={!raw.trim()} onClick={() => onSubmit(raw)}>
          Analyze
        </Button>
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
