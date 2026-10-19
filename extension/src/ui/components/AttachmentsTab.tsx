import { useMemo, useState } from 'react';
import type { AttachmentInfo, Finding, LinkInfo, ParsedAttachment, Report } from '../../core/types';
import { buildSafeSrcDoc } from '../safeHtml';
import type { Settings } from '../../lib/settings';
import { lookupFileHash, uploadFile, vtFindings, type VtResult } from '../../integrations/virustotal';
import { Button, Card, CopyButton, ErrorText, Mono, Pill, Spinner, formatBytes, type Async } from './ui';
import { Icon } from './Icon';
import { ServiceSetup } from './ServiceSetup';

function VtSummary({ result }: { result: VtResult }) {
  if (!result.found || !result.stats) {
    return <span className="text-[var(--text-2)]">VirusTotal has never seen this file. Unknown is not the same as safe.</span>;
  }
  const bad = result.stats.malicious + result.stats.suspicious;
  const total = bad + result.stats.harmless + result.stats.undetected;
  return (
    <span className={bad ? 'font-semibold text-[var(--bad)]' : 'text-[var(--good)]'}>
      {bad}/{total} security vendors flag this file{result.label ? ` (${result.label})` : ''}
    </span>
  );
}

const KIND_LABEL = { pdf: 'Links in this PDF', office: 'Links in this document', html: 'Links and form targets in this file', archive: 'Files in this archive' } as const;

/** What Unmask found inside the file, without opening it. */
function Contents({ att, links }: { att: AttachmentInfo; links: LinkInfo[] }) {
  const c = att.contents;
  if (!c) return null;
  if (c.kind === 'archive') {
    if (!c.files.length) return null;
    return (
      <details className="mt-2.5 rounded-lg bg-[var(--surface-2)] px-2.5 py-2 text-xs" open={c.files.length <= 8}>
        <summary className="cursor-pointer select-none font-medium text-[var(--text)]">
          {KIND_LABEL.archive} ({c.files.length})
        </summary>
        <ul className="mt-1.5 space-y-0.5">
          {c.files.map((file, i) => (
            <li key={i} className="flex justify-between gap-2">
              <Mono>{file.name}</Mono>
              <span className="shrink-0 text-[11px] text-[var(--text-3)]">
                {file.encrypted ? 'encrypted · ' : ''}
                {formatBytes(file.size)}
              </span>
            </li>
          ))}
        </ul>
      </details>
    );
  }
  return (
    <div className="mt-2.5 rounded-lg bg-[var(--surface-2)] px-2.5 py-2 text-xs">
      <div className="font-medium text-[var(--text)]">
        {links.length ? `${KIND_LABEL[c.kind]} (${links.length})` : c.kind === 'html' ? 'No outside links or form targets found' : 'No links found inside'}
      </div>
      {c.macros && <div className="mt-1 text-[var(--bad)]">Has macros. Never click “Enable content”.</div>}
      {links.length > 0 && (
        <ul className="mt-1.5 space-y-1">
          {links.slice(0, 12).map((l, i) => (
            <li key={i} className="flex items-start gap-1.5">
              {l.flags[0] && <Pill severity={l.flags[0].severity}>{l.flags[0].severity}</Pill>}
              <Mono>{l.resolved}</Mono>
            </li>
          ))}
          {links.length > 12 && <li className="text-[11px] text-[var(--text-3)]">+{links.length - 12} more on the Links tab</li>}
        </ul>
      )}
    </div>
  );
}

/** The HTML attachment rendered like the Body tab: sandboxed, no scripts, no network, links disabled. */
function HtmlPreview({ file, all }: { file: ParsedAttachment; all: ParsedAttachment[] }) {
  const srcDoc = useMemo(() => buildSafeSrcDoc(new TextDecoder().decode(file.content.subarray(0, 4_000_000)), { reveal: false, remoteImages: false, attachments: all }), [file, all]);
  return (
    <div className="mt-2.5">
      <iframe title={`Safe preview of ${file.filename}`} sandbox="" referrerPolicy="no-referrer" srcDoc={srcDoc} className="h-[360px] w-full resize-y rounded-lg border border-[var(--border)] bg-white" />
      <p className="mt-1 text-[11px] text-[var(--text-3)]">Scripts, forms and links are switched off, and nothing loads from the internet.</p>
    </div>
  );
}

function AttachmentCard({
  att,
  file,
  all,
  links,
  bytes,
  settings,
  onSettingsChange,
  onFindings,
  focused,
  onHover,
}: {
  att: AttachmentInfo;
  file: ParsedAttachment;
  all: ParsedAttachment[];
  links: LinkInfo[];
  bytes: Uint8Array;
  settings: Settings;
  onSettingsChange: (s: Settings) => void;
  onFindings: (f: Finding[]) => void;
  focused: boolean;
  onHover?: (att: AttachmentInfo | null) => void;
}) {
  const [vt, setVt] = useState<Async<VtResult>>({ status: 'idle' });
  const [confirmUpload, setConfirmUpload] = useState(false);
  const [setup, setSetup] = useState(false);
  const [preview, setPreview] = useState(false);
  const risky = att.flags.some((f) => f.severity === 'critical' || f.severity === 'high');

  const report = (value: VtResult) => {
    setVt({ status: 'done', value });
    onFindings(vtFindings(`vt-file-${att.sha256.slice(0, 12)}`, att.filename, value, 'attachments').map((f) => ({ ...f, target: { kind: 'attachment', sha256: att.sha256 } as const })));
  };
  const lookup = async (s: Settings = settings) => {
    if (!s.vtApiKey) {
      setSetup(true);
      return;
    }
    setSetup(false);
    setVt({ status: 'loading', message: 'Looking up the file fingerprint…' });
    try {
      report(await lookupFileHash(s.vtApiKey, att.sha256));
    } catch (e) {
      setVt({ status: 'error', error: e instanceof Error ? e.message : String(e) });
    }
  };
  const upload = async () => {
    setConfirmUpload(false);
    setVt({ status: 'loading', message: 'Uploading…' });
    try {
      report(await uploadFile(settings.vtApiKey, bytes, att.filename, att.sha256, (message) => setVt({ status: 'loading', message })));
    } catch (e) {
      setVt({ status: 'error', error: e instanceof Error ? e.message : String(e) });
    }
  };

  const notFound = vt.status === 'done' && !vt.value.found;

  return (
    <Card
      id={`unmask-att-${att.sha256.slice(0, 12)}`}
      className={`${risky ? 'border-l-[3px] !border-l-[var(--bad)]' : ''} ${focused ? 'unmask-flash' : ''}`}
      onMouseEnter={() => onHover?.(att)}
      onMouseLeave={() => onHover?.(null)}
    >
      <div className="break-all text-[13px] font-medium">{att.filename}</div>
      <div className="text-[11px] text-[var(--text-3)]">
        {att.mimeType} · {formatBytes(att.size)}
        {att.inline && ' · inline image'}
      </div>
      <div className="mt-1.5 flex items-center gap-1">
        <span className="shrink-0 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-3)]">SHA-256</span>
        <Mono className="truncate">{att.sha256}</Mono>
        <CopyButton value={att.sha256} />
      </div>
      {att.flags.length > 0 && (
        <ul className="mt-2 space-y-1">
          {att.flags.map((f) => (
            <li key={f.id} className="flex items-start gap-1.5 text-xs">
              <Pill severity={f.severity}>{f.severity}</Pill>
              <span className="text-[var(--text-2)]">{f.label}</span>
            </li>
          ))}
        </ul>
      )}

      <Contents att={att} links={links} />
      {preview && <HtmlPreview file={file} all={all} />}

      <div className="mt-3 flex flex-wrap gap-1.5">
        {att.contents?.kind === 'html' && (
          <Button onClick={() => setPreview((p) => !p)}>
            <Icon name="eye" className="h-3.5 w-3.5" /> {preview ? 'Hide preview' : 'Safe preview'}
          </Button>
        )}
        <Button onClick={() => void lookup()} disabled={vt.status === 'loading'} title="Sends only the file's fingerprint (hash), never the file">
          {vt.status === 'loading' ? <Spinner /> : <Icon name="shield" className="h-3.5 w-3.5" />} Check on VirusTotal
        </Button>
        {(notFound || vt.status === 'error') && settings.vtApiKey && (
          <Button onClick={() => setConfirmUpload(true)}>
            <Icon name="upload" className="h-3.5 w-3.5" /> Send file to VirusTotal
          </Button>
        )}
      </div>

      {setup && (
        <div className="mt-3">
          <ServiceSetup
            compact
            service="virustotal"
            settings={settings}
            onCancel={() => setSetup(false)}
            onSaved={(s) => {
              onSettingsChange(s);
              void lookup(s);
            }}
          />
        </div>
      )}

      {confirmUpload && (
        <div className="mt-2.5 rounded-lg border border-[var(--warn)] bg-[var(--warn-soft)] p-2.5 text-xs text-[var(--text)]">
          <p className="font-semibold">Send {att.filename} to VirusTotal?</p>
          <p className="mt-1 text-[var(--text-2)]">Unmask sends it straight from this email, so you don’t need to download it. 70+ antivirus engines then scan it.</p>
          <p className="mt-1 text-[var(--text-2)]">
            <strong className="text-[var(--text)]">Only for files you don’t mind sharing:</strong> VirusTotal keeps uploaded files and shares them with security companies. Don’t send invoices, tax forms, contracts or ID documents that contain personal details.
          </p>
          <div className="mt-2 flex gap-1.5">
            <Button variant="danger" onClick={() => void upload()}>
              Send to VirusTotal
            </Button>
            <Button variant="ghost" onClick={() => setConfirmUpload(false)}>
              Cancel
            </Button>
          </div>
        </div>
      )}

      {vt.status === 'loading' && <p className="mt-1.5 text-[11px] text-[var(--text-3)]">{vt.message}</p>}
      {vt.status === 'error' && <ErrorText>{vt.error}</ErrorText>}
      {vt.status === 'done' && (
        <div className="mt-2.5 flex items-center justify-between gap-2 rounded-lg bg-[var(--surface-2)] px-2.5 py-2 text-xs">
          <VtSummary result={vt.value} />
          <a className="shrink-0 font-medium text-[var(--accent)] hover:underline" href={vt.value.permalink} target="_blank" rel="noreferrer">
            Report
          </a>
        </div>
      )}
    </Card>
  );
}

export function AttachmentsTab({
  report,
  settings,
  onSettingsChange,
  onFindings,
  focusSha,
  onHoverAttachment,
}: {
  report: Report;
  settings: Settings;
  onSettingsChange: (s: Settings) => void;
  onFindings: (f: Finding[]) => void;
  focusSha?: string | null;
  onHoverAttachment?: (att: AttachmentInfo | null) => void;
}) {
  if (!report.attachments.length) return <p className="text-sm text-[var(--text-2)]">This email has no attachments.</p>;
  const all = report.email.attachments;
  const files = report.attachments.map((att, i) => ({ att, file: all[i]!, bytes: all[i]!.content })).sort((a, b) => Number(a.att.inline) - Number(b.att.inline));
  return (
    <div className="space-y-2.5">
      <p className="text-xs text-[var(--text-2)]">Don’t open attachments you weren’t expecting. Unmask reads inside PDFs, Office files, archives and HTML files without opening them. Checking on VirusTotal sends only the file’s fingerprint.</p>
      {files.map(({ att, file, bytes }) => (
        <AttachmentCard
          key={att.sha256 + att.filename}
          att={att}
          file={file}
          all={all}
          links={report.links.filter((l) => l.source === 'attachment' && l.origin === att.filename)}
          bytes={bytes}
          settings={settings}
          onSettingsChange={onSettingsChange}
          onFindings={onFindings}
          focused={focusSha === att.sha256}
          onHover={onHoverAttachment}
        />
      ))}
    </div>
  );
}
