import { useEffect, useRef, useState } from 'react';
import type { Finding, Report } from '../../core/types';
import { aiAvailability, aiFindings, languageModel, outputLanguage, readWithAi, type AiAvailability, type AiReading } from '../../lib/onDeviceAi';
import { Button, Card, Spinner } from './ui';

const ASK_LABEL: Record<string, string> = {
  'pay-money': 'Pay money',
  'change-bank-details': 'Change bank details',
  'buy-gift-cards': 'Buy gift cards',
  'sign-in': 'Sign in',
  'share-code-or-password': 'Share a code or password',
  'share-personal-details': 'Share personal details',
  'call-a-number': 'Call a number',
  'install-or-run-something': 'Install or run something',
  'open-attachment': 'Open an attachment',
  'reply-with-information': 'Reply with information',
};

/** Readings already made, by email, so switching tabs doesn't run the model again. */
const done = new Map<string, AiReading | null>();

/** Chrome's on-device model reads the email: what it asks for, and why the verdict fits. Nothing leaves the computer. */
export function AiCard({ report, onFindings }: { report: Report; onFindings: (f: Finding[]) => void }) {
  const lang = outputLanguage(typeof navigator !== 'undefined' ? navigator.language : 'en');
  const [status, setStatus] = useState<AiAvailability | 'checking'>('checking');
  const [state, setState] = useState<{ kind: 'idle' | 'reading' | 'done' | 'error'; reading?: AiReading | null; error?: string; progress?: number }>({ kind: 'idle' });
  const latest = useRef(report);
  latest.current = report;
  // One reading per email; the findings it adds must not start another.
  const key = report.email.messageId ?? `${report.email.from?.address ?? ''}|${report.email.date ?? ''}|${report.email.subject}`;

  const read = async (download = false) => {
    const lm = languageModel();
    if (!lm) return;
    setState({ kind: 'reading', progress: download ? 0 : undefined });
    try {
      const reading = await readWithAi(lm, latest.current, lang);
      done.set(key, reading);
      if (done.size > 50) done.delete(done.keys().next().value!);
      setState({ kind: 'done', reading });
      onFindings(aiFindings(reading, latest.current));
      setStatus('available');
    } catch (e) {
      setState({ kind: 'error', error: e instanceof Error ? e.message : String(e) });
    }
  };

  useEffect(() => {
    let live = true;
    if (done.has(key)) {
      setStatus('available');
      setState({ kind: 'done', reading: done.get(key) });
      return;
    }
    setState({ kind: 'idle' });
    void aiAvailability(languageModel(), lang).then((a) => {
      if (!live) return;
      setStatus(a);
      if (a === 'available') void read();
    });
    return () => {
      live = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  if (status === 'checking' || status === 'unavailable') return null;
  const reading = state.reading;
  const asks = reading?.asks.filter((a) => a !== 'nothing') ?? [];

  return (
    <Card className="mt-3" aria-label="On-device AI">
      <div className="mb-1 flex items-center justify-between gap-2">
        <p className="text-[11px] font-semibold uppercase tracking-wide text-[var(--text-3)]">Read by Chrome’s on-device AI</p>
        <span className="text-[10px] text-[var(--text-3)]">Nothing leaves this computer</span>
      </div>
      {(status === 'downloadable' || status === 'downloading') && state.kind === 'idle' && (
        <div className="space-y-1.5 text-xs">
          <p className="text-[var(--text-2)]">Chrome can read emails with its own built-in model, on this computer. It needs a one-time download of the model by Chrome (several GB, over an unmetered connection).</p>
          <Button onClick={() => void read(true)}>{status === 'downloading' ? 'Finish the download and read this email' : 'Download the model and read this email'}</Button>
        </div>
      )}
      {state.kind === 'reading' && (
        <p className="flex items-center gap-1.5 text-xs text-[var(--text-2)]">
          <Spinner /> Reading the email on this computer…
        </p>
      )}
      {state.kind === 'error' && <p className="text-xs text-[var(--text-2)]">The on-device model could not read this email ({state.error}). The other checks are unaffected.</p>}
      {state.kind === 'done' && !reading && <p className="text-xs text-[var(--text-2)]">The on-device model gave an answer Unmask couldn’t read. The other checks are unaffected.</p>}
      {state.kind === 'done' && reading && (
        <div className="space-y-1.5 text-xs">
          {reading.explanation && <p>{reading.explanation}</p>}
          <p className="text-[var(--text-2)]">
            It asks you to: <strong className="text-[var(--text-1)]">{asks.length ? asks.map((a) => ASK_LABEL[a] ?? a).join(', ') : 'nothing in particular'}</strong>
            {reading.urgent ? ' · with pressure to act fast' : ''}
            {reading.pretendsToBe ? ` · claims to be ${reading.pretendsToBe}` : ''}
          </p>
          <p className="text-[10px] text-[var(--text-3)]">AI can be wrong. It never decides the verdict on its own.</p>
        </div>
      )}
    </Card>
  );
}
