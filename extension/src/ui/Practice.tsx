import { useEffect, useMemo, useState } from 'react';
import { analyzeRawEmail } from '../core/analyze';
import type { Report } from '../core/types';
import { PRACTICE, type PracticeItem } from '../demo/practice';
import { PlainCard } from './components/Overview';
import { Button, Card } from './components/ui';
import { recordStat } from '../lib/statsStore';

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
    return <Finished right={right} of={round.length} onAgain={() => { setRound(pickRound(PRACTICE)); setAt(0); setRight(0); setAnswer(null); }} />;
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

/** The end of a round: the score, counted on this device, and a certificate to print for a perfect one. */
function Finished({ right, of, onAgain }: { right: number; of: number; onAgain: () => void }) {
  const [name, setName] = useState('');
  useEffect(() => {
    void recordStat({ type: 'practice', right, of });
  }, [right, of]);
  const perfect = right === of;
  return (
    <main className="mx-auto max-w-[680px] px-4 py-10 text-center text-[var(--text)]">
      <div className="print:hidden">
        <h1 className="text-xl font-semibold">You spotted {right} of {of}</h1>
        <p className="mt-2 text-sm text-[var(--text-2)]">{perfect ? 'Perfect. Scammers will have a hard time with you.' : right >= of * 0.7 ? 'Well done. Look again at the ones you missed: those are the tricks that work.' : 'These are hard on purpose. The lessons are what count: who really sent it, and what it asks you to do.'}</p>
        <Button variant="primary" className="mt-4" onClick={onAgain}>Practise again</Button>
        {perfect && (
          <div className="mx-auto mt-6 max-w-[360px] rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4 text-left text-sm">
            <p className="font-semibold">Print a Scam Spotter certificate</p>
            <label className="mt-2 block text-xs text-[var(--text-2)]" htmlFor="cert-name">Name on the certificate</label>
            <input id="cert-name" className="mt-1 w-full rounded-lg border border-[var(--border)] bg-[var(--bg)] px-2 py-1.5" value={name} onChange={(e) => setName(e.target.value)} placeholder="Your name" />
            <Button className="mt-2" onClick={() => window.print()} disabled={!name.trim()}>Print certificate</Button>
          </div>
        )}
      </div>
      {perfect && (
        <section className="hidden print:block print:pt-24" aria-label="Certificate">
          <p className="text-sm uppercase tracking-[0.3em]">Unmask</p>
          <h2 className="mt-6 text-4xl font-bold">Scam Spotter</h2>
          <p className="mt-8 text-lg">This certifies that</p>
          <p className="mt-2 text-3xl font-semibold">{name}</p>
          <p className="mt-8 text-lg">spotted every scam and every real email in a round of {of},</p>
          <p className="text-lg">on {new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' })}.</p>
        </section>
      )}
    </main>
  );
}
