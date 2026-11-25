import { useState } from 'react';
import { analyzePasted, type PastedKind } from '../core/pasted';
import type { Report } from '../core/types';
import { PlainCard, VerdictCard } from './components/Overview';
import { ScoreBreakdownCard } from './components/ScoreBreakdownCard';
import { ShareCard } from './components/ShareCard';
import { Button } from './components/ui';

const SAMPLES = [
  { label: 'Parcel fee text', text: 'USPS: Your package is on hold due to an unpaid $1.99 fee. Pay within 24 hours or it will be returned: https://usps-redelivery-fee.top/pay' },
  { label: 'Bank alert', text: 'HDFC Bank: Your account will be blocked today. Update your KYC now at http://hdfc-kyc-update.in-verify.xyz to avoid suspension.' },
  { label: 'A look-alike link', text: 'paypa1-secure.top/signin' },
];

const KIND: Record<PastedKind, string> = { email: 'Full email', message: 'Message', link: 'Link' };

/** Paste a text message, a WhatsApp chat, a link or a whole email, and check it on this device. */
export function CheckMessage() {
  const [text, setText] = useState('');
  const [result, setResult] = useState<(Report & { kind: PastedKind }) | null>(null);
  const [busy, setBusy] = useState(false);

  const check = async (value = text) => {
    if (!value.trim()) return;
    setBusy(true);
    try {
      setResult(await analyzePasted(value));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="mx-auto max-w-[680px] px-4 py-10 text-[var(--text)]">
      <h1 className="text-2xl font-semibold tracking-tight">Check a message</h1>
      <p className="mt-1 text-sm text-[var(--text-2)]">
        Paste a text message, a WhatsApp or Telegram message, a link, or a whole email with its headers. It is checked here, on your device. Nothing is sent anywhere.
      </p>
      <label htmlFor="pasted" className="sr-only">Message to check</label>
      <textarea
        id="pasted"
        className="mt-4 h-40 w-full resize-y rounded-xl border border-[var(--border)] bg-[var(--surface)] p-3 font-mono text-[13px] outline-none focus:border-[var(--accent)]"
        placeholder="Paste the message or link here"
        value={text}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) void check(); }}
      />
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <Button variant="primary" onClick={() => void check()} disabled={busy || !text.trim()}>{busy ? 'Checking…' : 'Check it'}</Button>
        <span className="text-xs text-[var(--text-3)]">or try:</span>
        {SAMPLES.map((s) => (
          <button key={s.label} type="button" className="rounded-full border border-[var(--border)] px-2.5 py-1 text-xs text-[var(--text-2)] hover:text-[var(--text)]" onClick={() => { setText(s.text); void check(s.text); }}>
            {s.label}
          </button>
        ))}
      </div>
      {result && (
        <section className="mt-6" aria-live="polite">
          <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--text-3)]">{KIND[result.kind]}</p>
          {result.kind === 'email' && <VerdictCard report={result} />}
          <PlainCard report={result} />
          <ScoreBreakdownCard report={result} />
          <ShareCard report={result} />
          {result.kind !== 'email' && (
            <p className="mt-3 text-xs text-[var(--text-3)]">A message has no sender we can check, so only its links and wording are judged. A clean result is not a promise it is safe.</p>
          )}
        </section>
      )}
    </main>
  );
}
