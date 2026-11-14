import { useEffect, useState } from 'react';
import { analyzeRawEmail } from '../core/analyze';
import type { Report } from '../core/types';
import { EXAMPLE_EMAIL } from '../demo/example';
import { PlainCard } from './components/Overview';
import { Card } from './components/ui';

/**
 * Shown once, right after install: the real analysis running on a made-up
 * phishing email, so people see what a warning looks like before the first
 * real one, and know where to find Unmask.
 */
export function Welcome() {
  const [report, setReport] = useState<Report | null>(null);
  useEffect(() => {
    void analyzeRawEmail(EXAMPLE_EMAIL).then(setReport);
  }, []);
  const reasons = report?.findings.filter((f) => f.points > 0 && f.severity !== 'info').slice(0, 4) ?? [];

  return (
    <main className="mx-auto max-w-[760px] px-4 py-8 text-[var(--text)]">
      <div className="flex items-center gap-3">
        <img src="/icon/128.png" alt="" className="h-12 w-12" />
        <div>
          <h1 className="text-xl font-semibold">Unmask is on</h1>
          <p className="text-sm text-[var(--text-2)]">It checks every email you open in Gmail or Outlook, on your computer. Nothing is sent anywhere.</p>
        </div>
      </div>

      <h2 className="mt-8 text-sm font-semibold uppercase tracking-wide text-[var(--text-3)]">This is what a warning looks like</h2>
      <p className="mt-1 text-sm text-[var(--text-2)]">Unmask just checked a made-up scam email, the way it will check yours:</p>
      <Card className="mt-3">
        <p className="text-xs text-[var(--text-3)]">From: <span className="font-mono">PayPal Service &lt;billing@paypa1-support.example&gt;</span></p>
        <p className="mt-0.5 text-sm font-semibold">Your account has been limited - action required within 24 hours</p>
        {report && (
          <div className="mt-3 rounded-lg border-t-4 border-[var(--bad)] bg-[var(--bad-soft)] p-3" role="alert" aria-label="Example warning">
            <p className="text-sm font-semibold text-[var(--bad)]">⚠ Unmask: High risk ({report.score}/100)</p>
            <ul className="mt-1 list-disc pl-5 text-sm">
              {reasons.map((f) => (
                <li key={f.id}>{f.plain ?? f.title}</li>
              ))}
            </ul>
          </div>
        )}
      </Card>
      {report && (
        <div className="mt-3">
          <PlainCard report={report} />
        </div>
      )}

      <h2 className="mt-8 text-sm font-semibold uppercase tracking-wide text-[var(--text-3)]">Three things to know</h2>
      <ol className="mt-2 list-decimal space-y-2 pl-5 text-sm">
        <li><strong>Warnings appear inside your inbox</strong>: a red or amber banner on risky emails, and a stop before a risky link opens.</li>
        <li><strong>Click the Unmask icon</strong> in the toolbar (pin it with the puzzle-piece menu) for the full report on the email you have open. It also has <em>See an example phishing email</em>.</li>
        <li><strong>Helping someone else?</strong> In Settings → Family mode, add yourself as their helper: risky emails then show “Ask you” instead of “Open anyway”.</li>
      </ol>
      <p className="mt-6 text-xs text-[var(--text-3)]">
        <a className="text-[var(--accent)]" href="/practice.html">Practise spotting scams</a> ·{' '}
        <a className="text-[var(--accent)]" href="https://praneeth132006.github.io/Unmask/guide.html" target="_blank" rel="noopener noreferrer">Read the user guide</a> ·{' '}
        <a className="text-[var(--accent)]" href="https://praneeth132006.github.io/Unmask/privacy.html" target="_blank" rel="noopener noreferrer">Privacy</a>
      </p>
    </main>
  );
}
