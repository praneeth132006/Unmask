/**
 * A picture of the verdict to send to family or a team chat ("Don't click
 * this one"). Drawn on a canvas from the plain-language summary only: no
 * links are written out in full and nothing in it can be clicked.
 */
import { plainSummary } from '../core/plain';
import { verdictLabel } from '../core/facts';
import type { Report } from '../core/types';

const COLORS = {
  high: { accent: '#e5484d', soft: '#3a1d1f' },
  suspicious: { accent: '#f0a020', soft: '#3a2f17' },
  clear: { accent: '#86c232', soft: '#26301b' },
} as const;

/** Breaks text into lines that fit `width`. */
export function wrapLines(measure: (s: string) => number, text: string, width: number, maxLines = 3): string[] {
  const words = text.split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let line = '';
  for (const w of words) {
    const next = line ? `${line} ${w}` : w;
    if (measure(next) <= width || !line) line = next;
    else {
      lines.push(line);
      line = w;
      if (lines.length === maxLines) break;
    }
  }
  if (lines.length < maxLines && line) lines.push(line);
  if (lines.length === maxLines && words.join(' ').length > lines.join(' ').length) lines[maxLines - 1] = (lines[maxLines - 1] ?? '').replace(/\s*\S*$/, '') + '…';
  return lines;
}

/** Defangs a domain so the image can't be turned back into a working link: paypa1[.]top. */
export const defang = (domain: string) => domain.replace(/\./g, '[.]');

export function shareText(report: Report): string {
  const s = plainSummary(report);
  const from = report.email.from;
  return [
    `⚠️ ${verdictLabel(report)}: ${s.headline}`,
    from ? `From: ${from.name ? `${from.name} ` : ''}<${defang(from.address)}>` : '',
    report.email.subject ? `Subject: ${report.email.subject}` : '',
    ...s.reasons.map((r) => `• ${r}`),
    s.action,
    'Checked with Unmask, on my own device.',
  ].filter(Boolean).join('\n');
}

export function drawShareCard(report: Report, canvas: HTMLCanvasElement): void {
  const W = 1080, H = 1080, P = 80;
  canvas.width = W;
  canvas.height = H;
  const ctx = canvas.getContext('2d')!;
  const c = COLORS[report.verdict];
  const s = plainSummary(report);
  const font = (size: number, weight = 400) => `${weight} ${size}px ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif`;

  ctx.fillStyle = '#16191c';
  ctx.fillRect(0, 0, W, H);
  const glow = ctx.createRadialGradient(W * 0.85, 0, 0, W * 0.85, 0, 700);
  glow.addColorStop(0, c.soft);
  glow.addColorStop(1, '#16191c');
  ctx.fillStyle = glow;
  ctx.fillRect(0, 0, W, H);

  ctx.fillStyle = c.accent;
  ctx.fillRect(P, P, 12, 120);
  ctx.font = font(30, 600);
  ctx.fillStyle = c.accent;
  ctx.fillText(verdictLabel(report).toUpperCase(), P + 40, P + 40);
  ctx.font = font(58, 700);
  ctx.fillStyle = '#f2f4ef';
  wrapLines((t) => ctx.measureText(t).width, s.headline, W - 2 * P - 40, 2).forEach((l, i) => ctx.fillText(l, P + 40, P + 112 + i * 68));

  let y = P + 300;
  const from = report.email.from;
  ctx.font = font(28);
  ctx.fillStyle = '#9ea3a0';
  if (from) { ctx.fillText(`From  ${defang(from.address)}`, P, y); y += 44; }
  if (report.email.subject) {
    const subj = wrapLines((t) => ctx.measureText(t).width, `Subject  ${report.email.subject}`, W - 2 * P, 1)[0] ?? '';
    ctx.fillText(subj, P, y);
    y += 44;
  }

  y += 40;
  ctx.font = font(34, 500);
  for (const reason of s.reasons.slice(0, 3)) {
    ctx.fillStyle = c.accent;
    ctx.beginPath();
    ctx.arc(P + 10, y - 11, 8, 0, Math.PI * 2);
    ctx.fill();
    ctx.fillStyle = '#e4e7e1';
    const lines = wrapLines((t) => ctx.measureText(t).width, reason, W - 2 * P - 40, 2);
    lines.forEach((l, i) => ctx.fillText(l, P + 40, y + i * 44));
    y += lines.length * 44 + 28;
  }

  ctx.fillStyle = '#23272b';
  ctx.fillRect(P, H - P - 150, W - 2 * P, 110);
  ctx.font = font(30, 600);
  ctx.fillStyle = '#f2f4ef';
  wrapLines((t) => ctx.measureText(t).width, s.action, W - 2 * P - 60, 2).forEach((l, i) => ctx.fillText(l, P + 30, H - P - 102 + i * 38));

  ctx.font = font(24);
  ctx.fillStyle = '#7d8280';
  ctx.fillText('Checked with Unmask · on my own device · praneeth132006.github.io/Unmask', P, H - P + 6);
}
