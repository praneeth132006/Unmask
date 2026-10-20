/**
 * Exact, testable sentences about what an email contains and what did or
 * didn't happen. Every place that talks about trackers or the verdict uses
 * these, so the side panel, the Peek card and the banner can never disagree.
 */
import type { Report } from './types';

const n = (count: number, one: string, many = `${one}s`) => `${count} ${count === 1 ? one : many}`;

export interface TrackerFacts {
  pixels: number;
  trackedLinks: number;
  remoteImages: number;
}

export function trackerFacts(r: Report): TrackerFacts {
  return { pixels: r.trackers.pixels.length, trackedLinks: r.trackers.trackedLinkCount, remoteImages: r.trackers.remoteImages };
}

/** Short label for the Summary chip, e.g. "1 pixel · 24 tracked links". */
export function trackerChipLabel(r: Report): string {
  const f = trackerFacts(r);
  const parts = [f.pixels ? n(f.pixels, 'pixel') : '', f.trackedLinks ? n(f.trackedLinks, 'tracked link') : ''].filter(Boolean);
  if (parts.length) return parts.join(' · ');
  return f.remoteImages ? 'No known trackers' : 'No trackers';
}

/**
 * What the email contains, for a Peek (nothing loaded): which trackers exist,
 * and the fact that none of them fired.
 */
export function peekPrivacyLines(r: Report): string[] {
  const f = trackerFacts(r);
  const lines: string[] = [];
  if (f.pixels) {
    lines.push(`Contains ${n(f.pixels, 'tracking pixel')}${f.remoteImages > f.pixels ? ` among ${n(f.remoteImages, 'remote image')}` : ''}. Peek loaded none of them, so the sender has not been told you looked.`);
  } else if (f.remoteImages) {
    lines.push(`Contains ${n(f.remoteImages, 'remote image')} (no known tracking pixels). Peek loaded none of them.`);
  } else {
    lines.push('Contains no remote images or tracking pixels.');
  }
  if (f.trackedLinks) lines.push(`${n(f.trackedLinks, 'link is', 'links are')} click-tracked: each reports a click only if you click it.`);
  if (f.remoteImages) lines.push('Opening it in Gmail loads these images, which tells the sender that you opened it and when.');
  return lines;
}

/** The verdict's name. "No red flags" only when there is truly nothing to point out. */
export function verdictLabel(r: Report): string {
  if (r.verdict === 'high') return 'High risk';
  if (r.verdict === 'suspicious') return 'Suspicious';
  return r.findings.some((f) => f.points > 0) ? 'Low risk' : 'No red flags';
}

/** Heading for the list of findings that add risk, matching the verdict. */
export function concernsHeading(r: Report, count: number): string {
  return r.verdict === 'clear' ? `Worth knowing (${count})` : `Red flags (${count})`;
}
