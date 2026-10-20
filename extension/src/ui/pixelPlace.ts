import type { TrackerPixel } from '../core/types';

/** "near the end", "at the very top"… from how far down the email the pixel sits. */
export function positionWords(pct: number): string {
  if (pct <= 5) return 'at the very top';
  if (pct < 35) return 'near the top';
  if (pct < 65) return 'in the middle';
  if (pct < 95) return 'near the end';
  return 'at the very end';
}

/** One plain sentence saying exactly where a pixel is, built only from what was measured. */
export function describePixelPlace(p: TrackerPixel): string {
  const what = p.kind === 'img' ? `Image ${p.imageIndex} of ${p.imageCount}` : 'A background image';
  const around = p.before && p.after ? `, between “${p.before}” and “${p.after}”` : p.before ? `, after “${p.before}”` : p.after ? `, before “${p.after}”` : '';
  return `${what}, ${positionWords(p.positionPct)} of the email’s visible text (${p.positionPct}% of the way down)${around}.${p.inHiddenBlock ? ' It sits inside a hidden block: you would never see it, but it still loads when the email’s images load.' : ''}`;
}
