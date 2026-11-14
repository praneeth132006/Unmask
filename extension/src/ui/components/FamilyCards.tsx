import { useEffect, useState } from 'react';
import type { Report } from '../../core/types';
import { askHelperLink, validHelper } from '../../lib/family';
import { thisAndLastWeek, weekSentence, type Stats } from '../../lib/stats';
import { loadStats } from '../../lib/statsStore';
import { Card } from './ui';

/** "Not sure? Ask Sam": a ready-written email to the person the user trusts, sent from their own mail app. */
export function AskHelperCard({ report, name, email }: { report: Report; name: string; email: string }) {
  const helper = { name, email };
  if (!validHelper(helper) || report.verdict === 'clear') return null;
  const who = name.trim() || 'your helper';
  return (
    <Card className="mt-3 border-[var(--accent-border)] bg-[var(--accent-soft)]" aria-label="Ask for help">
      <p className="text-sm font-semibold">Not sure? Ask {who} before you do anything.</p>
      <p className="mt-0.5 text-xs text-[var(--text-2)]">Opens an email to {email} in your own mail app, with what Unmask found. You choose whether to send it.</p>
      <a className="mt-2 inline-flex items-center rounded-lg bg-[var(--accent)] px-3 py-1.5 text-xs font-semibold text-white" href={askHelperLink(helper, report)} target="_blank" rel="noopener noreferrer">
        Ask {who}
      </a>
    </Card>
  );
}

/** What Unmask did this week, counted only on this device. */
export function WeeklyCard() {
  const [stats, setStats] = useState<Stats | null>(null);
  useEffect(() => {
    void loadStats().then(setStats);
  }, []);
  if (!stats) return null;
  const { thisWeek, lastWeek } = thisAndLastWeek(stats);
  if (!thisWeek.checked && !lastWeek?.checked) return null;
  return (
    <div className="mx-auto mt-5 max-w-[300px] rounded-xl border border-[var(--border)] bg-[var(--surface)] p-3 text-left text-xs" aria-label="This week">
      <p className="font-semibold text-[var(--text)]">This week, Unmask {weekSentence(thisWeek)}.</p>
      {lastWeek && lastWeek.checked > 0 && <p className="mt-1 text-[var(--text-3)]">Last week it {weekSentence(lastWeek)}.</p>}
      <p className="mt-1.5 text-[10px] text-[var(--text-3)]">Counted on this device only.</p>
    </div>
  );
}
