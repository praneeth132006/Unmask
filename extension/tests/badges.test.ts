import { describe, expect, it } from 'vitest';
import { addEvent, badges, EMPTY_STATS, scamsCaught, streakWeeks } from '../src/lib/stats';

const at = (iso: string) => new Date(`${iso}T12:00:00`);

describe('streaks and badges', () => {
  it('counts weeks in a row, and an empty current week does not break the streak', () => {
    let s = EMPTY_STATS;
    for (const d of ['2026-11-02', '2026-11-09', '2026-11-16']) s = addEvent(s, { type: 'checked', key: d, verdict: 'clear' }, at(d));
    expect(streakWeeks(s, at('2026-11-18'))).toBe(3);
    expect(streakWeeks(s, at('2026-11-24'))).toBe(3);
    expect(streakWeeks(s, at('2026-12-01'))).toBe(0);
  });

  it('counts scams caught and keeps practice results next to the weeks', () => {
    let s = addEvent(EMPTY_STATS, { type: 'checked', key: 'a', verdict: 'high' }, at('2026-11-16'));
    s = addEvent(s, { type: 'stopped', what: 'link' }, at('2026-11-16'));
    s = addEvent(s, { type: 'practice', right: 10, of: 10 });
    s = addEvent(s, { type: 'checked', key: 'b', verdict: 'clear' }, at('2026-11-17'));
    expect(scamsCaught(s)).toBe(2);
    expect(s.practice).toEqual({ rounds: 1, best: 100, perfect: 1 });
    expect(badges(s, at('2026-11-17'))).toEqual(['2 scams caught', 'Perfect quiz']);
  });
});
