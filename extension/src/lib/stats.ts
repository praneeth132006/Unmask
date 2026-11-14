/**
 * "This week, Unmask checked 42 emails and stopped 1 risky click." Counts
 * kept only in this browser, so people can see the protection working.
 * Nothing about the emails is stored: just numbers, and short fingerprints
 * of message ids so an email opened twice is counted once.
 */
export interface WeekStats {
  checked: number;
  warned: number;
  high: number;
  clicksStopped: number;
  repliesStopped: number;
  /** Short hashes of the message keys counted this week. */
  seen: string[];
}

export interface Stats {
  weeks: Record<string, WeekStats>;
}

export type StatEvent = { type: 'checked'; key: string; verdict: 'clear' | 'suspicious' | 'high' } | { type: 'stopped'; what: 'link' | 'reply' };

export const EMPTY_STATS: Stats = { weeks: {} };
const KEEP_WEEKS = 8;
const MAX_SEEN = 2000;

/** Monday of the week, as YYYY-MM-DD in local time. */
export function weekOf(d: Date): string {
  const day = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  day.setDate(day.getDate() - ((day.getDay() + 6) % 7));
  return `${day.getFullYear()}-${String(day.getMonth() + 1).padStart(2, '0')}-${String(day.getDate()).padStart(2, '0')}`;
}

/** A short, non-reversible tag for a message key (FNV-1a). */
function tag(key: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) h = Math.imul(h ^ key.charCodeAt(i), 0x01000193);
  return (h >>> 0).toString(36);
}

const empty = (): WeekStats => ({ checked: 0, warned: 0, high: 0, clicksStopped: 0, repliesStopped: 0, seen: [] });

export function addEvent(stats: Stats, event: StatEvent, now = new Date()): Stats {
  const week = weekOf(now);
  const cur = { ...empty(), ...(stats.weeks[week] ?? {}) };
  cur.seen = [...cur.seen];
  if (event.type === 'checked') {
    const t = tag(event.key);
    if (cur.seen.includes(t)) return stats;
    cur.seen.push(t);
    if (cur.seen.length > MAX_SEEN) cur.seen.shift();
    cur.checked++;
    if (event.verdict !== 'clear') cur.warned++;
    if (event.verdict === 'high') cur.high++;
  } else if (event.what === 'link') cur.clicksStopped++;
  else cur.repliesStopped++;
  const weeks = { ...stats.weeks, [week]: cur };
  for (const old of Object.keys(weeks).sort().slice(0, -KEEP_WEEKS)) delete weeks[old];
  return { weeks };
}

export function thisAndLastWeek(stats: Stats, now = new Date()): { thisWeek: WeekStats; lastWeek: WeekStats | null } {
  const last = new Date(now);
  last.setDate(last.getDate() - 7);
  return { thisWeek: stats.weeks[weekOf(now)] ?? empty(), lastWeek: stats.weeks[weekOf(last)] ?? null };
}

export function weekSentence(w: WeekStats): string {
  const parts = [`checked ${w.checked} email${w.checked === 1 ? '' : 's'}`];
  if (w.warned) parts.push(`warned you about ${w.warned}${w.high ? ` (${w.high} high risk)` : ''}`);
  const stopped = w.clicksStopped + w.repliesStopped;
  if (stopped) parts.push(`stopped ${w.clicksStopped ? `${w.clicksStopped} risky click${w.clicksStopped === 1 ? '' : 's'}` : ''}${w.clicksStopped && w.repliesStopped ? ' and ' : ''}${w.repliesStopped ? `${w.repliesStopped} reply${w.repliesStopped === 1 ? '' : 'ies'} to an impostor` : ''}`);
  return parts.length === 1 ? parts[0]! : `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}
