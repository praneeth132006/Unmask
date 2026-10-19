import { useState } from 'react';
import type { AttachmentInfo, Finding, Report } from '../../core/types';
import type { Settings } from '../../lib/settings';
import { lookupFileHash, uploadFile, vtFindings, type VtResult } from '../../integrations/virustotal';
import { Button, Card, CopyButton, ErrorText, Mono, Pill, Spinner, formatBytes, type Async } from './ui';

function VtSummary({ result }: { result: VtResult }) {
  if (!result.found || !result.stats) {
    return <span className="text-slate-600 dark:text-slate-300">VirusTotal has never seen this file. Unknown is not the same as safe.</span>;
  }
  const bad = result.stats.malicious + result.stats.suspicious;
  const total = bad + result.stats.harmless + result.stats.undetected;
  return (
    <span className={bad ? 'font-semibold text-red-600 dark:text-red-400' : 'text-emerald-700 dark:text-emerald-400'}>
      {bad}/{total} security vendors flag this file{result.label ? ` (${result.label})` : ''}
    </span>
  );
}

function AttachmentCard({ att, bytes, settings, onFindings }: { att: AttachmentInfo; bytes: Uint8Array; settings: Settings; onFindings: (f: Finding[]) => void }) {
  const [vt, setVt] = useState<Async<VtResult>>({ status: 'idle' });
  const [confirmUpload, setConfirmUpload] = useState(false);

  const report = (value: VtResult) => {
    setVt({ status: 'done', value });
    onFindings(vtFindings(`vt-file-${att.sha256.slice(0, 12)}`, att.filename, value, 'attachments'));
  };
  const lookup = async () => {
    setVt({ status: 'loading', message: 'Looking up hash…' });
    try {
      report(await lookupFileHash(settings.vtApiKey, att.sha256));
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
    <Card className={att.flags.some((f) => f.severity === 'critical' || f.severity === 'high') ? 'border-red-300 dark:border-red-900' : ''}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="break-all text-[13px] font-medium text-slate-900 dark:text-slate-100">{att.filename}</div>
          <div className="text-[11px] text-slate-500">
            {att.mimeType} · {formatBytes(att.size)}
            {att.inline && ' · inline image'}
          </div>
        </div>
      </div>
      <div className="mt-1.5 flex items-center gap-1">
        <span className="text-[11px] text-slate-500">SHA-256</span>
        <Mono className="truncate">{att.sha256}</Mono>
        <CopyButton value={att.sha256} />
      </div>
      {att.flags.length > 0 && (
        <ul className="mt-2 space-y-1">
          {att.flags.map((f) => (
            <li key={f.id} className="flex items-start gap-1.5 text-xs">
              <Pill severity={f.severity}>{f.severity}</Pill>
              <span className="text-slate-700 dark:text-slate-300">{f.label}</span>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-2.5 flex flex-wrap gap-1.5">
        <Button onClick={lookup} disabled={vt.status === 'loading'} title="Sends only the file's fingerprint (hash), never the file">
          {vt.status === 'loading' && <Spinner />} Check hash on VirusTotal
        </Button>
        {(notFound || vt.status === 'error') && (
          <Button variant="ghost" onClick={() => setConfirmUpload(true)}>
            Upload file…
          </Button>
        )}
      </div>

      {confirmUpload && (
        <div className="mt-2 rounded-md border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-100">
          <p className="font-semibold">Upload {att.filename} to VirusTotal?</p>
          <p className="mt-1">Files uploaded to VirusTotal can be downloaded by its paying customers. Do not upload anything confidential such as invoices, contracts or personal documents.</p>
          <div className="mt-2 flex gap-1.5">
            <Button variant="danger" onClick={upload}>
              Upload anyway
            </Button>
            <Button variant="ghost" onClick={() => setConfirmUpload(false)}>
              Cancel
            </Button>
          </div>
        </div>
      )}

      {vt.status === 'loading' && <p className="mt-1 text-[11px] text-slate-500">{vt.message}</p>}
      {vt.status === 'error' && <ErrorText>{vt.error}</ErrorText>}
      {vt.status === 'done' && (
        <div className="mt-2 flex items-center justify-between gap-2 text-xs">
          <VtSummary result={vt.value} />
          <a className="shrink-0 text-indigo-600 hover:underline dark:text-indigo-400" href={vt.value.permalink} target="_blank" rel="noreferrer">
            Report
          </a>
        </div>
      )}
    </Card>
  );
}

export function AttachmentsTab({ report, settings, onFindings }: { report: Report; settings: Settings; onFindings: (f: Finding[]) => void }) {
  if (!report.attachments.length) return <p className="text-sm text-slate-600 dark:text-slate-400">This email has no attachments.</p>;
  const files = report.attachments.map((att, i) => ({ att, bytes: report.email.attachments[i]!.content })).sort((a, b) => Number(a.att.inline) - Number(b.att.inline));
  return (
    <div className="space-y-2">
      <p className="text-xs text-slate-600 dark:text-slate-400">Don't open attachments you weren't expecting. Checking the hash only sends the file's fingerprint to VirusTotal, never its contents.</p>
      {files.map(({ att, bytes }) => (
        <AttachmentCard key={att.sha256 + att.filename} att={att} bytes={bytes} settings={settings} onFindings={onFindings} />
      ))}
    </div>
  );
}
