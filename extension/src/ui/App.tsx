import { useCallback, useEffect, useLayoutEffect, useRef, useState, type DragEvent } from 'react';
import { analyzeRawEmail, withExtraFindings } from '../core/analyze';
import type { AttachmentInfo, Finding, LinkInfo, Report, TabId } from '../core/types';
import { domainAgeFindings, lookupDomainAge, type DomainAge } from '../integrations/rdap';
import { certFindings, lookupCerts, lookupMailRecords, mailRecordFindings, type DomainIntel } from '../integrations/domainIntel';
import { SEVERITY_RANK } from '../core/score';
import { registrableDomain, sameOrg } from '../lib/domain';
import { loadHistory, rememberSender } from '../lib/historyStore';
import { loadProtection } from '../lib/protectionStore';
import { decodeImageInBrowser } from '../lib/imageDecode';
import { applyTheme, DEFAULT_SETTINGS, loadSettings, saveSettings, type Settings, type Theme } from '../lib/settings';
import type { HighlightTarget } from '../lib/highlight';
import { brandOwningDomain, FREE_MAIL_DOMAINS } from '../analyzers/brands';
import { GmailFetchError, messageKey, useGmail } from './useGmail';
import { attachmentTarget, toFocus, toHighlight, type Focus } from './targets';
import { unwrapUrl } from '../analyzers/links';
import { Overview, VerdictCard } from './components/Overview';
import { SenderTab } from './components/SenderTab';
import { LinksTab } from './components/LinksTab';
import { AttachmentsTab } from './components/AttachmentsTab';
import { BodyTab } from './components/BodyTab';
import { HeadersTab } from './components/HeadersTab';
import { PrivacyTab } from './components/PrivacyTab';
import { SettingsPanel } from './components/SettingsPanel';
import { ReportCard } from './components/ReportCard';
import { Button, CopyButton, Spinner, type Async } from './components/ui';
import { Icon } from './components/Icon';

type Source = { kind: 'gmail'; key: string } | { kind: 'file'; name: string };

const MAX_EMAIL_BYTES = 40 * 1024 * 1024;
const GUIDE_URL = 'https://praneeth132006.github.io/Unmask/guide.html';

const TAB_LABEL: Record<TabId, string> = {
  overview: 'Summary',
  sender: 'Sender',
  links: 'Links',
  attachments: 'Files',
  body: 'Body',
  headers: 'Headers',
  privacy: 'Privacy',
};

export function App() {
  const gmail = useGmail();
  const [settings, setSettings] = useState<Settings>(DEFAULT_SETTINGS);
  const [showSettings, setShowSettings] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [source, setSource] = useState<Source | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<{ message: string; details: string[] } | null>(null);
  const [tab, setTab] = useState<TabId>('overview');
  const [focus, setFocus] = useState<Focus | null>(null);
  const [domainAge, setDomainAge] = useState<Async<DomainAge>>({ status: 'idle' });
  const [intel, setIntel] = useState<Async<DomainIntel>>({ status: 'idle' });
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [pasting, setPasting] = useState(false);
  const [dragging, setDragging] = useState(false);
  const runId = useRef(0);
  const cache = useRef(new Map<string, { report: Report; raw: string | ArrayBuffer }>());
  /** Source of the email on screen, for the .eml download. */
  const [raw, setRaw] = useState<string | ArrayBuffer | null>(null);
  /** Where the user was on the Summary, so "Back" returns to the same finding. */
  const returnTo = useRef<{ scrollY: number; findingId: string | null }>({ scrollY: 0, findingId: null });

  useEffect(() => {
    void loadSettings().then(setSettings);
  }, []);
  useEffect(() => applyTheme(settings.theme), [settings.theme]);

  const cycleTheme = () => {
    const order: Theme[] = ['system', 'light', 'dark'];
    const next = { ...settings, theme: order[(order.indexOf(settings.theme) + 1) % order.length]! };
    setSettings(next);
    void saveSettings(next);
  };

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

  /** Certificate history and mail records for the sender's domain and the riskiest link domains. */
  const checkIntel = useCallback(
    async (r: Report, run: number) => {
      const sender = r.email.from ? registrableDomain(r.email.from.domain) : '';
      const senderKnown = !sender || FREE_MAIL_DOMAINS.has(sender) || Boolean(brandOwningDomain(sender));
      const worst = (l: LinkInfo) => Math.max(0, ...l.flags.map((f) => SEVERITY_RANK[f.severity]));
      const linkDomains = [...new Set(
        [...r.links]
          .filter((l) => l.domain && /^https?:/i.test(l.resolved) && !sameOrg(l.domain, sender) && !brandOwningDomain(l.domain))
          .sort((a, b) => worst(b) - worst(a))
          .map((l) => l.domain),
      )].slice(0, 3);
      if (senderKnown && !linkDomains.length) return;
      setIntel({ status: 'loading' });
      const value: DomainIntel = {};
      const found: Finding[] = [];
      const jobs: Promise<void>[] = [];
      if (!senderKnown) {
        jobs.push(lookupCerts(sender).then((c) => { value.cert = c; found.push(...certFindings(c, 'sender')); }));
        jobs.push(lookupMailRecords(sender).then((m) => { value.mail = m; found.push(...mailRecordFindings(m)); }));
      }
      for (const d of linkDomains) jobs.push(lookupCerts(d).then((c) => void found.push(...certFindings(c, 'link'))));
      const results = await Promise.allSettled(jobs);
      if (run !== runId.current) return;
      const failed = results.filter((x): x is PromiseRejectedResult => x.status === 'rejected');
      if (failed.length === results.length) setIntel({ status: 'error', error: failed[0]!.reason instanceof Error ? failed[0]!.reason.message : String(failed[0]!.reason) });
      else setIntel({ status: 'done', value });
      addFindings(run, found);
    },
    [addFindings],
  );

  const analyze = useCallback(
    async (load: () => Promise<string | ArrayBuffer>, src: Source, cacheKey?: string) => {
      const run = ++runId.current;
      setSource(src);
      setError(null);
      setDomainAge({ status: 'idle' });
      setIntel({ status: 'idle' });
      setTab('overview');
      setFocus(null);
      const cached = cacheKey ? cache.current.get(cacheKey) : undefined;
      if (cached) {
        setReport(cached.report);
        setRaw(cached.raw);
      } else {
        setLoading(true);
        setReport(null);
        setRaw(null);
      }
      try {
        // Emails opened from files may be samples from anywhere: compare them with the history, but never learn from them.
        const history = settings.senderHistory ? await loadHistory() : undefined;
        const source = cached?.raw ?? (await load());
        const r = cached?.report ?? (await analyzeRawEmail(source, { history, protection: await loadProtection(), decodeImage: decodeImageInBrowser }));
        if (run !== runId.current) return;
        if (cacheKey) cache.current.set(cacheKey, { report: r, raw: source });
        setRaw(source);
        if (settings.senderHistory && src.kind === 'gmail' && !cached) void rememberSender(r);
        setReport(r);
        if (settings.autoDomainAge) void checkDomainAge(r, run);
        if (settings.domainIntel) void checkIntel(r, run);
      } catch (e) {
        if (run === runId.current) {
          setError({ message: e instanceof Error ? e.message : String(e), details: e instanceof GmailFetchError ? e.details : [] });
        }
      } finally {
        if (run === runId.current) setLoading(false);
      }
    },
    [settings.autoDomainAge, settings.senderHistory, settings.domainIntel, checkDomainAge, checkIntel],
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

  // ---- Highlighting in Gmail -------------------------------------------------
  const currentMessage = source?.kind === 'gmail' ? messages.find((m) => messageKey(m) === source.key) : undefined;
  const canHighlight = Boolean(currentMessage);
  // Refs keep `highlight` stable, so unrelated re-renders don't wipe an outline the user is hovering.
  const messageRef = useRef(currentMessage);
  messageRef.current = currentMessage;
  const gmailHighlight = gmail.highlight;
  const highlight = useCallback(
    (target: HighlightTarget | null) => {
      if (messageRef.current) gmailHighlight(messageRef.current, target);
    },
    [gmailHighlight],
  );
  // Clear any outline when the panel changes email or tab.
  useEffect(() => () => highlight(null), [highlight, tab, report?.email.messageId]);

  const onHoverFinding = (f: Finding | null) => highlight(f && report ? toHighlight(f.target, report) : null);
  // Links found inside a file or QR code have no element in the body: outline the attachment instead.
  const onHoverLink = (l: LinkInfo | null) =>
    highlight(!l || !report ? null : l.origin ? attachmentTarget(report, l.origin.replace(/^QR code in /, '').replace(/^image in /, '')) : { kind: 'links', hrefs: [l.href] });
  /** A URL from the plain-text part: outline every HTML link with the same address or the same real destination. */
  const onHoverUrl = (url: string | null) => {
    if (!url || !report) return highlight(null);
    const dest = unwrapUrl(url).url;
    const hrefs = [url, ...report.links.filter((l) => l.href === url || l.resolved === dest).map((l) => l.href)];
    highlight({ kind: 'links', hrefs: [...new Set(hrefs)] });
  };
  const onHoverAttachment = (a: AttachmentInfo | null) => highlight(a && report ? attachmentTarget(report, a) : null);

  // ---- Navigation --------------------------------------------------------------
  const openTab = (next: TabId, nextFocus: Focus | null = null, fromFinding: string | null = null) => {
    if (tab === 'overview') returnTo.current = { scrollY: window.scrollY, findingId: fromFinding };
    highlight(null);
    setFocus(nextFocus);
    setTab(next);
    if (!nextFocus) window.scrollTo({ top: 0 });
  };
  const onOpenFinding = (f: Finding) => {
    const fc = toFocus(f.target);
    if (fc) openTab(fc.tab, fc, f.id);
  };
  const backToSummary = () => {
    setFocus(null);
    setTab('overview');
  };

  // After switching tabs: scroll to the focused item, or back to where the user was on the Summary.
  useLayoutEffect(() => {
    if (tab === 'overview') {
      const { scrollY, findingId } = returnTo.current;
      const el = findingId ? document.getElementById(`finding-${findingId}`) : null;
      if (el) {
        el.scrollIntoView({ block: 'center' });
        el.classList.add('unmask-flash');
        setTimeout(() => el.classList.remove('unmask-flash'), 1400);
      } else {
        window.scrollTo({ top: scrollY });
      }
      return;
    }
    const id = focus?.linkIndex != null ? `unmask-link-${focus.linkIndex}` : focus?.sha256 ? `unmask-att-${focus.sha256.slice(0, 12)}` : null;
    if (id) requestAnimationFrame(() => document.getElementById(id)?.scrollIntoView({ block: 'center', behavior: 'smooth' }));
  }, [tab, focus]);

  const retry = () => {
    if (source?.kind !== 'gmail') return;
    const msg = messages.find((m) => messageKey(m) === source.key);
    if (msg) void analyze(() => gmail.fetchRaw(msg), { kind: 'gmail', key: source.key }, undefined);
  };

  const openFile = (file: File) => {
    void analyze(async () => {
      // Very large inputs would freeze the panel; real emails are far smaller (Gmail's limit is 25 MB of attachments).
      if (file.size > MAX_EMAIL_BYTES) throw new Error(`This file is ${(file.size / 1024 / 1024).toFixed(0)} MB. Unmask analyzes emails up to ${MAX_EMAIL_BYTES / 1024 / 1024} MB.`);
      return file.arrayBuffer();
    }, { kind: 'file', name: file.name });
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

  const tabs: { id: TabId; count?: number; alert?: boolean }[] = report
    ? [
        { id: 'overview' },
        { id: 'sender', alert: report.findings.some((f) => (f.category === 'sender' || f.category === 'auth') && (f.severity === 'high' || f.severity === 'critical')) },
        { id: 'links', count: report.links.length, alert: report.links.some((l) => l.flags.some((f) => f.severity === 'high' || f.severity === 'critical')) },
        { id: 'attachments', count: report.attachments.length, alert: report.attachments.some((a) => a.flags.some((f) => f.severity === 'high' || f.severity === 'critical')) },
        { id: 'body', alert: report.hidden.length > 0 },
        { id: 'privacy', count: report.trackers.pixels.length + report.trackers.trackedLinkCount },
        { id: 'headers' },
      ]
    : [];

  const onFindings = (findings: Finding[]) => addFindings(runId.current, findings);

  return (
    <div
      className="min-h-screen bg-[var(--bg)] text-[var(--text)]"
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={(e) => {
        if (e.currentTarget === e.target) setDragging(false);
      }}
      onDrop={onDrop}
    >
      <header className="sticky top-0 z-20 border-b border-[var(--border)] bg-[var(--surface)]/90 backdrop-blur">
        <div className="flex items-center justify-between px-3 py-2">
          <button type="button" className="flex items-center gap-2" onClick={() => { setShowSettings(false); setPasting(false); backToSummary(); }} title="Unmask">
            <img src="/icon/48.png" alt="" className="h-6 w-6" />
            <span className="text-sm font-semibold tracking-tight">Unmask</span>
          </button>
          <div className="flex items-center gap-0.5">
            <label className="cursor-pointer rounded-lg p-1.5 text-[var(--text-2)] hover:bg-[var(--surface-2)] hover:text-[var(--text)]" title="Open an .eml file">
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
            <Button variant="ghost" className="!p-1.5" title={`Theme: ${settings.theme} (click to change)`} onClick={cycleTheme}>
              <Icon name={settings.theme === 'light' ? 'sun' : settings.theme === 'dark' ? 'moon' : 'monitor'} />
            </Button>
            <a
              className="rounded-lg p-1.5 text-[var(--text-2)] hover:bg-[var(--surface-2)] hover:text-[var(--text)]"
              href={GUIDE_URL}
              target="_blank"
              rel="noreferrer"
              title="User guide"
            >
              <Icon name="help" />
            </a>
            <Button variant="ghost" className="!p-1.5" title="Settings" onClick={() => setShowSettings(true)}>
              <Icon name="gear" />
            </Button>
          </div>
        </div>

        {report && !loading && !showSettings && !pasting && (!settings.simpleMode || tab !== 'overview') && (
          <nav className="flex flex-wrap gap-1 px-2 pb-2" role="tablist" aria-label="Report sections">
            {tabs.map((t) => (
              <button
                key={t.id}
                type="button"
                role="tab"
                aria-selected={tab === t.id}
                onClick={() => (t.id === 'overview' ? backToSummary() : openTab(t.id))}
                className={`relative shrink-0 rounded-lg px-2.5 py-1 text-xs font-medium transition-colors ${
                  tab === t.id ? 'bg-[var(--accent-soft)] text-[var(--accent)]' : 'text-[var(--text-2)] hover:bg-[var(--surface-2)] hover:text-[var(--text)]'
                }`}
              >
                {TAB_LABEL[t.id]}
                {t.count !== undefined && t.count > 0 && <span className="ml-1 text-[10px] text-[var(--text-3)]">{t.count}</span>}
                {t.alert && <span className="absolute right-0.5 top-0.5 h-1.5 w-1.5 rounded-full bg-[var(--bad)]" aria-label="has warnings" />}
              </button>
            ))}
          </nav>
        )}
      </header>

      <main className="p-3">
        {showSettings ? (
          <SettingsPanel settings={settings} onClose={() => setShowSettings(false)} onSaved={setSettings} />
        ) : pasting ? (
          <PasteBox
            onCancel={() => setPasting(false)}
            onSubmit={(raw) => {
              setPasting(false);
              void analyze(async () => {
                if (raw.length > MAX_EMAIL_BYTES) throw new Error(`The pasted text is too large. Unmask analyzes emails up to ${MAX_EMAIL_BYTES / 1024 / 1024} MB.`);
                return raw;
              }, { kind: 'file', name: 'Pasted source' });
            }}
          />
        ) : (
          <>
            {source?.kind === 'file' && (
              <div className="mb-2.5 flex items-center justify-between gap-2 rounded-lg bg-[var(--accent-soft)] px-2.5 py-1.5 text-xs text-[var(--accent)]">
                <span className="truncate">Analyzing {source.name}</span>
                {gmail.status === 'ready' && (
                  <button type="button" className="shrink-0 font-medium underline" onClick={backToGmail}>
                    Back to Gmail
                  </button>
                )}
              </div>
            )}

            {source?.kind !== 'file' && messages.length > 1 && tab === 'overview' && (
              <select
                className="mb-2.5 w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] px-2 py-1.5 text-xs text-[var(--text)]"
                value={source?.kind === 'gmail' ? source.key : ''}
                onChange={(e) => setSelectedKey(e.target.value)}
                aria-label="Which message in this thread"
              >
                {messages.map((m, i) => (
                  <option key={messageKey(m)} value={messageKey(m)}>
                    Message {i + 1} of {messages.length}: {m.fromName || m.fromEmail || 'Unknown sender'}
                  </option>
                ))}
              </select>
            )}

            {loading && (
              <div className="flex flex-col items-center gap-2 py-16 text-sm text-[var(--text-2)]">
                <Spinner /> Reading and analyzing the email…
              </div>
            )}

            {error && !loading && (
              <div className="rounded-xl border border-[var(--bad)]/30 bg-[var(--bad-soft)] p-3 text-sm">
                <p className="font-semibold text-[var(--bad)]">Could not analyze this email</p>
                <p className="mt-1 text-xs text-[var(--text-2)]">{error.message}</p>
                <div className="mt-2.5 flex flex-wrap gap-1.5">
                  {source?.kind === 'gmail' && (
                    <Button onClick={retry}>
                      <Icon name="refresh" className="h-3.5 w-3.5" /> Try again
                    </Button>
                  )}
                  <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-2.5 py-1.5 text-xs font-medium text-[var(--text)] hover:bg-[var(--surface-2)]">
                    <Icon name="upload" className="h-3.5 w-3.5" /> Open .eml file
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
                </div>
                {error.details.length > 0 && (
                  <details className="mt-2.5 text-xs">
                    <summary className="cursor-pointer select-none text-[var(--text-2)]">Technical details</summary>
                    <ul className="mt-1 space-y-0.5 break-all font-mono text-[10px] text-[var(--text-2)]">
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

            {!report && !loading && !error && <EmptyState status={gmail.status} app={gmail.app} onReload={gmail.reloadTab} />}

            {report && !loading && (
              <>
                {tab === 'overview' ? (
                  <VerdictCard report={report} />
                ) : (
                  <div className="mb-3 flex items-center justify-between gap-2">
                    <button
                      type="button"
                      onClick={backToSummary}
                      className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-lg py-1 pl-1 pr-2 text-xs font-medium text-[var(--accent)] hover:bg-[var(--accent-soft)]"
                    >
                      <Icon name="back" className="h-3.5 w-3.5" /> Back to summary
                    </button>
                    <span className="truncate text-[11px] text-[var(--text-3)]" title={report.email.subject}>
                      {report.email.subject}
                    </span>
                  </div>
                )}
                {/* Remount tab content per analysis so per-link/attachment results don't leak between emails. */}
                <div className={tab === 'overview' ? 'pt-3' : ''} key={runId.current}>
                  {tab === 'overview' && (
                    <Overview
                      report={report}
                      canHighlight={canHighlight}
                      onHoverFinding={onHoverFinding}
                      onOpenFinding={onOpenFinding}
                      onOpenTab={(t) => openTab(t)}
                      simple={settings.simpleMode}
                    />
                  )}
                  {tab === 'overview' && (
                    <ReportCard
                      report={report}
                      raw={raw}
                      gmailAccount={currentMessage && gmail.app === 'gmail' ? (gmail.state?.accountIndex ?? '0') : null}
                      onReportInGmail={currentMessage && gmail.app === 'gmail' ? () => gmail.reportPhishing(currentMessage) : undefined}
                    />
                  )}
                  {tab === 'sender' && <SenderTab report={report} domainAge={domainAge} intel={intel} onCheckIntel={() => void checkIntel(report, runId.current)} onCheckAge={() => void checkDomainAge(report, runId.current)} onHoverSender={(on) => highlight(on ? { kind: 'sender' } : null)} />}
                  {tab === 'links' && (
                    <LinksTab
                      report={report}
                      settings={settings}
                      onSettingsChange={setSettings}
                      onFindings={onFindings}
                      focusIndex={focus?.linkIndex ?? null}
                      onHoverLink={onHoverLink}
                    />
                  )}
                  {tab === 'attachments' && (
                    <AttachmentsTab
                      report={report}
                      settings={settings}
                      onSettingsChange={setSettings}
                      onFindings={onFindings}
                      focusSha={focus?.sha256 ?? null}
                      onHoverAttachment={onHoverAttachment}
                    />
                  )}
                  {tab === 'body' && <BodyTab report={report} initialReveal={focus?.revealHidden} onHoverUrl={canHighlight ? onHoverUrl : undefined} />}
                  {tab === 'headers' && <HeadersTab report={report} initialFilter={focus?.headerKey} />}
                  {tab === 'privacy' && <PrivacyTab report={report} />}
                </div>
              </>
            )}
          </>
        )}
      </main>

      {dragging && (
        <div className="pointer-events-none fixed inset-2 z-30 flex items-center justify-center rounded-2xl border-2 border-dashed border-[var(--accent)] bg-[var(--accent-soft)]/95 text-sm font-medium text-[var(--accent)]">
          Drop the .eml file to analyze it
        </div>
      )}
    </div>
  );
}

function EmptyState({ status, app, onReload }: { status: ReturnType<typeof useGmail>['status']; app: ReturnType<typeof useGmail>['app']; onReload: () => void }) {
  const name = app === 'outlook' ? 'Outlook' : 'Gmail';
  return (
    <div className="px-2 py-10 text-center">
      <img src="/icon/128.png" alt="" className="mx-auto mb-4 h-16 w-16 drop-shadow-sm" />
      {status === 'ready' && (
        <>
          <p className="text-[15px] font-semibold">Open an email to inspect it</p>
          <p className="mt-1 text-xs text-[var(--text-2)]">Unmask checks the sender, links, attachments and hidden text of the email you open in {name}.</p>
          {app === 'outlook' && (
            <p className="mt-2 text-[11px] text-[var(--text-3)]">In Outlook on the web Unmask reads the email from the page, so header checks (SPF, DKIM, DMARC) need … → View → View message source pasted in with the clipboard button.</p>
          )}
        </>
      )}
      {status === 'no-script' && (
        <>
          <p className="text-[15px] font-semibold">Reload {name} to connect Unmask</p>
          <p className="mt-1 text-xs text-[var(--text-2)]">{name} was already open when Unmask was installed or updated.</p>
          <Button variant="primary" className="mt-3" onClick={onReload}>
            <Icon name="refresh" className="h-3.5 w-3.5" /> Reload {name}
          </Button>
        </>
      )}
      {status === 'not-gmail' && (
        <>
          <p className="text-[15px] font-semibold">Open Gmail or Outlook to get started</p>
          <p className="mt-1 text-xs text-[var(--text-2)]">Then open any email. Unmask will analyze it automatically.</p>
        </>
      )}
      <div className="mx-auto mt-6 max-w-[290px] rounded-xl border border-dashed border-[var(--border-strong)] p-3 text-xs text-[var(--text-2)]">
        Using the Outlook desktop app or another client? Save the email as an <strong className="text-[var(--text)]">.eml</strong> file and drop it here, or paste its raw source with the clipboard button above.
      </div>
    </div>
  );
}

function PasteBox({ onSubmit, onCancel }: { onSubmit: (raw: string) => void; onCancel: () => void }) {
  const [raw, setRaw] = useState('');
  return (
    <div className="space-y-2.5">
      <div className="flex items-center gap-1">
        <Button variant="ghost" className="!px-1.5" onClick={onCancel} aria-label="Back">
          <Icon name="back" />
        </Button>
        <h2 className="text-[15px] font-semibold">Paste raw email source</h2>
      </div>
      <p className="text-xs text-[var(--text-2)]">
        <strong className="text-[var(--text)]">Gmail:</strong> open the email → ⋮ → <em>Show original</em> → <em>Copy to clipboard</em>.<br />
        <strong className="text-[var(--text)]">Outlook:</strong> open the email → … → <em>View</em> → <em>View message source</em>.
      </p>
      <textarea
        autoFocus
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
        className="h-64 w-full rounded-xl border border-[var(--border)] bg-[var(--surface)] p-2.5 font-mono text-[11px] text-[var(--text)] focus:border-[var(--accent)] focus:outline-none"
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
