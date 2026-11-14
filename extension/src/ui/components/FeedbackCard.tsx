import { useState } from 'react';
import { browser } from 'wxt/browser';
import type { Report } from '../../core/types';
import { feedbackText, feedbackUrl, likelyMistake, type Mistake } from '../../lib/feedback';
import { Button, Card, CopyButton } from './ui';

/** "Was this right?" at the end of the summary. Nothing leaves the computer unless the user opens the issue. */
function extensionVersion(): string {
  try {
    return browser.runtime.getManifest().version;
  } catch {
    return 'unknown';
  }
}

export function FeedbackCard({ report }: { report: Report }) {
  const version = extensionVersion();
  const [step, setStep] = useState<'ask' | 'thanks' | 'wrong'>('ask');
  const [mistake, setMistake] = useState<Mistake>(likelyMistake(report));
  const [includeDomain, setIncludeDomain] = useState(false);
  const domain = report.email.from?.domain ?? '';
  const opts = { mistake, includeDomain, version };
  const text = feedbackText(report, opts);

  return (
    <Card className="mt-4" aria-label="Was this right?">
      {step === 'ask' && (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <p className="text-xs font-medium">Was this right?</p>
          <div className="flex gap-1.5">
            <Button onClick={() => setStep('thanks')}>Yes</Button>
            <Button onClick={() => setStep('wrong')}>No, it got this wrong</Button>
          </div>
        </div>
      )}
      {step === 'thanks' && <p className="text-xs text-[var(--text-2)]">Thanks. Nothing was sent.</p>}
      {step === 'wrong' && (
        <div className="space-y-2 text-xs">
          <p className="font-medium">What went wrong?</p>
          <fieldset className="space-y-1">
            <label className="flex items-center gap-2">
              <input type="radio" name="unmask-mistake" checked={mistake === 'false-alarm'} onChange={() => setMistake('false-alarm')} /> It’s a real email, but Unmask warned about it
            </label>
            <label className="flex items-center gap-2">
              <input type="radio" name="unmask-mistake" checked={mistake === 'missed'} onChange={() => setMistake('missed')} /> It’s phishing, but Unmask didn’t warn enough
            </label>
          </fieldset>
          {domain && (
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={includeDomain} onChange={(e) => setIncludeDomain(e.target.checked)} /> Also share the sender’s domain ({domain})
            </label>
          )}
          <p className="text-[var(--text-2)]">This is everything that will be shared. The email itself, your address and the links are never included.</p>
          <pre className="max-h-40 overflow-auto whitespace-pre-wrap rounded-lg bg-[var(--surface-2)] p-2 font-mono text-[11px]" aria-label="What will be shared">{`${text.title}\n${text.why}`}</pre>
          <div className="flex flex-wrap gap-1.5">
            <a className="inline-flex items-center rounded-lg bg-[var(--accent)] px-2.5 py-1.5 text-xs font-medium text-white" href={feedbackUrl(report, opts)} target="_blank" rel="noopener noreferrer">
              Open a GitHub issue
            </a>
            <CopyButton value={`${text.title}\n${text.why}`} label="Copy instead" />
            <Button onClick={() => setStep('ask')}>Cancel</Button>
          </div>
          <p className="text-[11px] text-[var(--text-3)]">Opens GitHub in a new tab with the form filled in. You can edit it before posting, or not post it at all.</p>
        </div>
      )}
    </Card>
  );
}
