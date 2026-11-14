import { useEffect, useMemo, useState } from 'react';
import { analyzeRawEmail } from '../core/analyze';
import type { Report } from '../core/types';
import { PRACTICE, type PracticeItem } from '../demo/practice';
import { PlainCard } from './components/Overview';
import { Button, Card } from './components/ui';

const ROUND = 10;

/** A shuffled round with both kinds of email, so guessing "scam" every time doesn't win. */
export function pickRound(items: PracticeItem[], n = ROUND, rand = Math.random): PracticeItem[] {
  const shuffle = <T,>(a: T[]) => a.map((x) => [rand(), x] as const).sort((p, q) => p[0] - q[0]).map(([, x]) => x);
  const scams = shuffle(items.filter((i) => i.scam));
  const real = shuffle(items.filter((i) => !i.scam));
  const nScam = Math.min(scams.length, Math.ceil(n * 0.6));
  return shuffle([...scams.slice(0, nScam), ...real.slice(0, n - nScam)]);
}

/** Practice: is this email a scam? Then Unmask shows why. For people, schools and team training. */
export function Practice() {
  const [round, setRound] = useState(() => pickRound(PRACTICE));
  const [at, setAt] = useState(0);
  const [answer, setAnswer] = useState<boolean | null>(null);
  const [right, setRight] = useState(0);
  const [report, setReport] = useState<Report | null>(null);
  const item = round[at];

  useEffect(() => {
    setReport(null);
    if (item) void analyzeRawEmail(item.raw).then(setReport);
  }, [item]);

  const shown = useMemo(() => {
    if (!report) return null;
    return { from: report.email.from, subject: report.email.subject, text: report.previewText };
  }, [report]);

  if (!item) {
    return (
      <main className="mx-auto max-w-[680px] px-4 py-10 text-center text-[var(--text)]">
        <h1 className="text-xl font-semibold">You spotted {right} of {round.length}</h1>
        <p className="mt-2 text-sm text-[var(--text-2)]">{right === round.length ? 'Perfect. Scammers will have a hard time with you.' : right >= round.length * 0.7 ? 'Well done. Look again at the ones you missed: those are the tricks that work.' : 'These are hard on purpose. The lessons are what count: who really sent it, and what it asks you to do.'}</p>
        <Button variant="primary" className="mt-4" onClick={() => { setRound(pickRound(PRACTICE)); setAt(0); setRight(0); setAnswer(null); }}>
          Practise again
        </Button>
      </main>
    );
  }

  const choose = (scam: boolean) => {
    if (answer !== null) return;
    setAnswer(scam);
    if (scam === item.scam) setRight((r) => r + 1);
  };
  const correct = answer !== null && answer === item.scam;

  return (
    <main className="mx-auto max-w-[680px] px-4 py-8 text-[var(--text)]">
      <div className="flex items-baseline justify-between">
        <h1 className="text-lg font-semibold">Spot the scam</h1>
        <p className="text-xs text-[var(--text-3)]" aria-label="Progress">Email {at + 1} of {round.length} · {right} right</p>
      </div>
      <p className="mt-1 text-sm text-[var(--text-2)]">Made-up emails built like real ones. Nothing here can be clicked.</p>

      <Card className="mt-4" aria-label="Practice email">
        {shown ? (
          <>
            <p className="text-xs text-[var(--text-3)]">From: <span className="font-mono">{shown.from ? `${shown.from.name ? `${shown.from.name} ` : ''}<${shown.from.address}>` : 'unknown'}</span></p>
            <p className="mt-0.5 text-sm font-semibold">{shown.subject}</p>
            <p className="mt-2 whitespace-pre-wrap text-sm text-[var(--text-2)]">{shown.text || '(no text)'}</p>
          </>
        ) : (
          <p className="text-sm text-[var(--text-3)]">Loading…</p>
        )}
      </Card>

      {answer === null ? (
        <div className="mt-4 flex justify-center gap-2">
          <Button variant="primary" onClick={() => choose(true)}>It’s a scam</Button>
          <Button onClick={() => choose(false)}>It’s real</Button>
        </div>
      ) : (
        <div className="mt-4">
          <p className={`text-sm font-semibold ${correct ? 'text-[var(--good)]' : 'text-[var(--bad)]'}`} role="status">
            {correct ? 'Right.' : 'Not this time.'} This email is {item.scam ? 'a scam' : 'real'}.
          </p>
          <p className="mt-1 text-sm">{item.lesson}</p>
          {report && (
            <div className="mt-3">
              <PlainCard report={report} />
            </div>
          )}
          <div className="mt-4 text-center">
            <Button variant="primary" onClick={() => { setAt((a) => a + 1); setAnswer(null); }}>
              {at + 1 < round.length ? 'Next email' : 'See my score'}
            </Button>
          </div>
        </div>
      )}
    </main>
  );
}
