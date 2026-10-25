import { useState } from 'react';
import { browser } from 'wxt/browser';
import type { Report } from '../../core/types';
import { analystReport, buildJsonReport, buildPdfReport, composeUrl, indicatorText, safeFileName, suspiciousUrls, urlReportPage, type ReportService } from '../../lib/reporting';
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
      <Card>
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
          <p className="mb-1.5 text-[11px] text-[var(--text-3)]">For your IT or security team</p>
          <div className="flex flex-wrap gap-1.5">
            <Button onClick={() => download(`${base}.pdf`, buildPdfReport(report, version) as BlobPart, 'application/pdf')}>
              <Icon name="download" className="h-3.5 w-3.5" /> PDF report
            </Button>
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
