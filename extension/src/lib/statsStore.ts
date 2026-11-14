import { browser } from 'wxt/browser';
import { addEvent, EMPTY_STATS, type StatEvent, type Stats } from './stats';

const KEY = 'unmask:stats';
let queue: Promise<unknown> = Promise.resolve();

export async function loadStats(): Promise<Stats> {
  try {
    return ((await browser.storage.local.get(KEY))[KEY] as Stats | undefined) ?? EMPTY_STATS;
  } catch {
    return EMPTY_STATS;
  }
}

/** Counts one event. Writes are queued so two quick events don't overwrite each other. */
export function recordStat(event: StatEvent): Promise<void> {
  const run = queue.then(async () => {
    const next = addEvent(await loadStats(), event);
    await browser.storage.local.set({ [KEY]: next });
  });
  queue = run.catch(() => {});
  return run.catch(() => {});
}

export async function clearStats(): Promise<void> {
  await browser.storage.local.remove(KEY);
}
