import { useState } from 'react';
import { browser } from 'wxt/browser';
import type { Report } from '../../core/types';
import { analystReport, buildJsonReport, composeUrl, indicatorText, safeFileName, suspiciousUrls, urlReportPage, type ReportService } from '../../lib/reporting';
import { FORMAT_INFO, buildReportFile, type Audience, type ReportFormat, type ReportMeta, type Tlp } from '../../report';
import { Button, Card, SectionTitle } from './ui';
import { Icon } from './Icon';

function download(name: string, data: BlobPart, type: string): void {
  const url = URL.createObjectURL(new Blob([data], { type }));
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

const META_KEY = 'unmask:report-meta';

function loadMeta(): ReportMeta {
  try {
    return JSON.parse(localStorage.getItem(META_KEY) ?? '{}') as ReportMeta;
  } catch {
    return {};
  }
}

async function sha256Of(raw: string | ArrayBuffer): Promise<{ emlSha256: string; emlSize: number }> {
  const bytes = typeof raw === 'string' ? new TextEncoder().encode(raw) : new Uint8Array(raw);
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource));
  return { emlSha256: Array.from(d, (b) => b.toString(16).padStart(2, '0')).join(''), emlSize: bytes.length };
}

const AUDIENCES: { id: Audience; label: string; hint: string }[] = [
  { id: 'both', label: 'Complete', hint: 'Executive summary for leaders, then the full technical analysis' },
  { id: 'executive', label: 'Executive only', hint: 'Plain language, 2 pages: for managers and non-technical staff' },
  { id: 'technical', label: 'Technical only', hint: 'Full evidence for security analysts and investigators' },
];

function open(url: string): void {
  void browser.tabs.create({ url });
}

/**
 * Report the email and export it. Nothing is sent by Unmask: each button opens
 * Gmail's own report flow, a compose window or a web form for the user to finish.
 */
export function ReportCard({
  report,
  raw,
  gmailAccount,
  onReportInGmail,
}: {
  report: Report;
  /** The original message source, for the .eml download. */
  raw: string | ArrayBuffer | null;
  /** Gmail account index when the email came from Gmail, else null. */
  gmailAccount: string | null;
  onReportInGmail?: () => Promise<{ ok: boolean; error?: string }>;
}) {
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [audience, setAudience] = useState<Audience>('both');
  const [meta, setMeta] = useState<ReportMeta>(loadMeta);
  const [building, setBuilding] = useState<ReportFormat | null>(null);
  const updateMeta = (patch: Partial<ReportMeta>) => {
    const next = { ...meta, ...patch };
    setMeta(next);
    try {
      localStorage.setItem(META_KEY, JSON.stringify({ ...next, caseId: undefined, notes: undefined }));
    } catch {
      // storage unavailable: the details still apply to this report
    }
  };
  const version = browser.runtime.getManifest?.().version ?? 'dev';
  const base = `unmask-${safeFileName(report.email.subject)}`;
  const urls = suspiciousUrls(report);
  const top = urls[0];

  const copy = async (text: string, done: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setNote({ ok: true, text: done });
    } catch {
      setNote({ ok: false, text: 'Could not copy to the clipboard.' });
    }
  };
  const downloadEml = () => raw && download(`${base}.eml`, raw, 'message/rfc822');
  const exportReport = async (format: ReportFormat) => {
    setBuilding(format);
    setNote(null);
    try {
      const evidence = raw ? await sha256Of(raw) : undefined;
      const file = await buildReportFile(report, format, { version, meta, audience, evidence });
      download(`${base}-${audience === 'both' ? 'report' : audience}.${file.ext}`, file.data, file.mime);
      setNote({ ok: true, text: `${FORMAT_INFO[format].label} report saved. It was built on this computer; nothing was uploaded.` });
    } catch (e) {
      setNote({ ok: false, text: `Could not build the report: ${e instanceof Error ? e.message : String(e)}` });
    } finally {
      setBuilding(null);
    }
  };
  const sendTo = (service: ReportService) => {
    downloadEml();
    open(composeUrl(service, report, gmailAccount));
    setNote({ ok: true, text: raw ? `Downloaded ${base}.eml. Attach it to the email that just opened, then send.` : 'Attach the original email (Gmail: ⋮ → Download message) and send.' });
  };
  const reportUrl = async (service: 'google' | 'phishtank' | 'netcraft') => {
    if (!top) return;
    if (service !== 'google') await navigator.clipboard.writeText(top).catch(() => {});
    open(urlReportPage(service, top));
    setNote({ ok: true, text: service === 'google' ? 'Google’s form opened with the link filled in.' : 'The link is copied. Paste it into the form that just opened.' });
  };

  return (
    <>
      <SectionTitle>Report or export</SectionTitle>
      <Card aria-label="Report or export">
        <div className="flex flex-wrap gap-1.5">
          {onReportInGmail && (
            <Button
              variant={report.verdict === 'clear' ? 'secondary' : 'primary'}
              onClick={async () => {
                setNote(null);
                const r = await onReportInGmail();
                setNote(r.ok ? { ok: true, text: 'Gmail is asking you to confirm. Click "Report Phishing Message" there.' } : { ok: false, text: r.error ?? 'Could not open Gmail’s report menu.' });
              }}
            >
              <Icon name="flag" className="h-3.5 w-3.5" /> Report phishing in Gmail
            </Button>
          )}
          <Button onClick={() => sendTo('apwg')} title="Anti-Phishing Working Group: shares reports with browsers, banks and takedown services">
            Send to APWG
          </Button>
          <Button onClick={() => sendTo('netcraft')} title="Netcraft blocks and takes down phishing sites">
            Send to Netcraft
          </Button>
        </div>
        {top && (
          <div className="mt-2.5 border-t border-[var(--border)] pt-2.5">
            <p className="mb-1.5 text-[11px] text-[var(--text-3)]">
              Report the riskiest link: <span className="break-all font-mono">{top.length > 70 ? `${top.slice(0, 70)}…` : top}</span>
            </p>
            <div className="flex flex-wrap gap-1.5">
              <Button onClick={() => void reportUrl('google')}>Google Safe Browsing</Button>
              <Button onClick={() => void reportUrl('phishtank')}>PhishTank</Button>
              <Button onClick={() => void reportUrl('netcraft')}>Netcraft</Button>
            </div>
          </div>
        )}
        <div className="mt-2.5 border-t border-[var(--border)] pt-2.5">
          <p className="mb-1.5 text-[11px] font-medium text-[var(--text-2)]">Investigation report</p>
          <div role="radiogroup" aria-label="Who is the report for?" className="grid gap-1 sm:grid-cols-3">
            {AUDIENCES.map((a) => (
              <button
                key={a.id}
                type="button"
                role="radio"
                aria-checked={audience === a.id}
                title={a.hint}
                onClick={() => setAudience(a.id)}
                className={`rounded-lg border px-2 py-1.5 text-left text-[11px] transition-colors ${audience === a.id ? 'border-[var(--accent)] bg-[var(--accent-soft)] text-[var(--text)]' : 'border-[var(--border)] text-[var(--text-2)] hover:bg-[var(--surface-2)]'}`}
              >
                <span className="block font-medium">{a.label}</span>
                <span className="block text-[10px] text-[var(--text-3)]">{a.hint}</span>
              </button>
            ))}
          </div>
          <details className="mt-1.5 text-[11px] text-[var(--text-2)]">
            <summary className="cursor-pointer select-none">Case details (optional)</summary>
            <div className="mt-1.5 grid gap-1.5 sm:grid-cols-2">
              {(
                [
                  ['caseId', 'Case / ticket ID', 'Auto-generated if empty'],
                  ['preparedBy', 'Prepared by', 'Analyst name'],
                  ['organisation', 'Organisation', ''],
                ] as const
              ).map(([k, label, ph]) => (
                <label key={k} className="block">
                  <span className="text-[10px] text-[var(--text-3)]">{label}</span>
                  <input value={meta[k] ?? ''} onChange={(e) => updateMeta({ [k]: e.target.value })} placeholder={ph} className="mt-0.5 w-full rounded-md border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)]" />
                </label>
              ))}
              <label className="block">
                <span className="text-[10px] text-[var(--text-3)]">Classification (TLP)</span>
                <select value={meta.tlp ?? 'AMBER'} onChange={(e) => updateMeta({ tlp: e.target.value as Tlp })} className="mt-0.5 w-full rounded-md border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)]">
                  {(['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED'] as const).map((t) => (
                    <option key={t} value={t}>
                      TLP:{t}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block sm:col-span-2">
                <span className="text-[10px] text-[var(--text-3)]">Analyst notes (included in the report)</span>
                <textarea value={meta.notes ?? ''} onChange={(e) => updateMeta({ notes: e.target.value })} rows={2} className="mt-0.5 w-full rounded-md border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)]" />
              </label>
            </div>
          </details>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {(['pdf', 'docx', 'html', 'stix'] as const).map((f) => (
              <Button key={f} onClick={() => void exportReport(f)} disabled={building !== null} title={f === 'stix' ? 'STIX 2.1 bundle for threat-intelligence tools (MISP, OpenCTI, Sentinel)' : undefined}>
                <Icon name="download" className="h-3.5 w-3.5" /> {building === f ? 'Building…' : FORMAT_INFO[f].label}
              </Button>
            ))}
          </div>
          <p className="mt-1.5 text-[10px] text-[var(--text-3)]">Built on this computer. Indicators are defanged so the report is safe to open and share.</p>
        </div>
        <div className="mt-2.5 border-t border-[var(--border)] pt-2.5">
          <p className="mb-1.5 text-[11px] text-[var(--text-3)]">Raw data for your IT or security team</p>
          <div className="flex flex-wrap gap-1.5">
            <Button onClick={() => download(`${base}.json`, JSON.stringify(buildJsonReport(report, version), null, 2), 'application/json')}>
              <Icon name="download" className="h-3.5 w-3.5" /> JSON
            </Button>
            {raw && (
              <Button onClick={downloadEml}>
                <Icon name="download" className="h-3.5 w-3.5" /> Original (.eml)
              </Button>
            )}
          </div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            <Button onClick={() => void copy(analystReport(report, version), 'Analyst write-up copied: verdict, authentication, delivery path, findings and indicators.')} title="A case write-up in the order a security analyst works">
              <Icon name="copy" className="h-3.5 w-3.5" /> Copy analyst write-up
            </Button>
            <Button onClick={() => void copy(indicatorText(report), 'Indicators copied, defanged so they can’t be clicked.')} title="Sender, Reply-To, origin IP, URLs, domains, file hashes: defanged">
              <Icon name="copy" className="h-3.5 w-3.5" /> Copy indicators
            </Button>
          </div>
        </div>
        {note && <p className={`mt-2.5 text-xs ${note.ok ? 'text-[var(--text-2)]' : 'text-[var(--bad)]'}`}>{note.text}</p>}
      </Card>
    </>
  );
}
