/**
 * Runs `fn` once things go quiet for `wait` ms, but never later than `maxWait`
 * ms after the first request. A plain debounce never fires on a page that
 * changes all the time, and Gmail's inbox does (status dot, timestamps,
 * animations).
 */
export function debounceMax(fn: () => void, wait: number, maxWait: number): { schedule: () => void; cancel: () => void } {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let first: number | null = null;
  const run = () => {
    timer = undefined;
    first = null;
    fn();
  };
  return {
    schedule() {
      const now = Date.now();
      first ??= now;
      clearTimeout(timer);
      timer = setTimeout(run, Math.max(0, Math.min(wait, first + maxWait - now)));
    },
    cancel() {
      clearTimeout(timer);
      timer = undefined;
      first = null;
    },
  };
}
