import { useState } from 'react';
import type { AttachmentInfo, Finding, Report } from '../../core/types';
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

function AttachmentCard({
  att,
  bytes,
  settings,
  onSettingsChange,
  onFindings,
  focused,
  onHover,
}: {
  att: AttachmentInfo;
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

      <div className="mt-3 flex flex-wrap gap-1.5">
        <Button onClick={() => void lookup()} disabled={vt.status === 'loading'} title="Sends only the file's fingerprint (hash), never the file">
          {vt.status === 'loading' ? <Spinner /> : <Icon name="shield" className="h-3.5 w-3.5" />} Check on VirusTotal
        </Button>
        {(notFound || vt.status === 'error') && settings.vtApiKey && (
          <Button variant="ghost" onClick={() => setConfirmUpload(true)}>
            Upload file…
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
          <p className="font-semibold">Upload {att.filename} to VirusTotal?</p>
          <p className="mt-1 text-[var(--text-2)]">Files uploaded to VirusTotal can be downloaded by its paying customers. Do not upload anything confidential such as invoices, contracts or personal documents.</p>
          <div className="mt-2 flex gap-1.5">
            <Button variant="danger" onClick={() => void upload()}>
              Upload anyway
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
  const files = report.attachments.map((att, i) => ({ att, bytes: report.email.attachments[i]!.content })).sort((a, b) => Number(a.att.inline) - Number(b.att.inline));
  return (
    <div className="space-y-2.5">
      <p className="text-xs text-[var(--text-2)]">Don’t open attachments you weren’t expecting. Checking on VirusTotal sends only the file’s fingerprint, never its contents.</p>
      {files.map(({ att, bytes }) => (
        <AttachmentCard
          key={att.sha256 + att.filename}
          att={att}
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
