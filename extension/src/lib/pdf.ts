/**
 * A tiny PDF writer for text reports: Helvetica, A4 pages, word wrap,
 * headings and coloured lines. No dependencies, so the report is produced
 * entirely in the browser. Text outside Latin-1 is replaced, since the
 * standard PDF fonts only cover WinAnsi.
 */

export type PdfLine =
  | { kind: 'title' | 'heading'; text: string }
  | { kind: 'text' | 'mono' | 'small'; text: string; color?: [number, number, number] }
  | { kind: 'gap' };

const PAGE_W = 595;
const PAGE_H = 842;
const MARGIN = 50;
const STYLE = {
  title: { font: 'F2', size: 18, lead: 26 },
  heading: { font: 'F2', size: 12.5, lead: 20 },
  text: { font: 'F1', size: 10, lead: 14 },
  mono: { font: 'F3', size: 8.5, lead: 11.5 },
  small: { font: 'F1', size: 8.5, lead: 12 },
} as const;

function winAnsi(s: string): string {
  return s
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[–—]/g, '-')
    .replace(/…/g, '...')
    .replace(/→/g, '->')
    .replace(/[^\x20-\x7e\xa0-\xff]/g, '?');
}

function escape(s: string): string {
  return s.replace(/[\\()]/g, '\\$&');
}

/** Wraps by an average glyph width; good enough for a report, never overflowing the page. */
function wrap(text: string, size: number, mono: boolean): string[] {
  const max = Math.floor((PAGE_W - 2 * MARGIN) / (size * (mono ? 0.6 : 0.52)));
  const out: string[] = [];
  for (const para of text.split('\n')) {
    let line = '';
    for (const word of para.split(/(\s+)/)) {
      if ((line + word).length <= max) {
        line += word;
        continue;
      }
      if (line.trim()) out.push(line.trimEnd());
      // Words longer than a line (URLs, hashes) are hard-split.
      let w = word.trimStart();
      while (w.length > max) {
        out.push(w.slice(0, max));
        w = w.slice(max);
      }
      line = w;
    }
    out.push(line.trimEnd());
  }
  return out;
}

export function buildPdf(lines: PdfLine[], footer: string): Uint8Array {
  const pages: string[] = [];
  let ops: string[] = [];
  let y = PAGE_H - MARGIN;
  const newPage = () => {
    if (ops.length) pages.push(ops.join('\n'));
    ops = [];
    y = PAGE_H - MARGIN;
  };

  for (const line of lines) {
    if (line.kind === 'gap') {
      y -= 8;
      continue;
    }
    const st = STYLE[line.kind];
    const color = 'color' in line && line.color ? line.color : line.kind === 'small' ? [0.42, 0.45, 0.5] : [0.08, 0.09, 0.1];
    if (line.kind === 'heading') y -= 6;
    for (const part of wrap(winAnsi(line.text), st.size, line.kind === 'mono')) {
      if (y - st.lead < MARGIN + 20) newPage();
      y -= st.lead;
      ops.push(`BT /${st.font} ${st.size} Tf ${color.map((c) => c.toFixed(2)).join(' ')} rg ${MARGIN} ${y.toFixed(1)} Td (${escape(part)}) Tj ET`);
    }
  }
  newPage();

  const objects: string[] = [];
  const add = (body: string) => objects.push(body);
  add('<< /Type /Catalog /Pages 2 0 R >>');
  add(''); // pages, filled in below
  add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
  add('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>');
  const kids: number[] = [];
  pages.forEach((content, i) => {
    const foot = `BT /F1 8 Tf 0.55 0.57 0.6 rg ${MARGIN} 30 Td (${escape(winAnsi(`${footer}  -  page ${i + 1} of ${pages.length}`))}) Tj ET`;
    const stream = `${content}\n${foot}`;
    add(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
    const contentId = objects.length;
    add(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents ${contentId} 0 R >>`);
    kids.push(objects.length);
  });
  objects[1] = `<< /Type /Pages /Kids [${kids.map((k) => `${k} 0 R`).join(' ')}] /Count ${kids.length} >>`;

  let out = '%PDF-1.4\n%\xe2\xe3\xcf\xd3\n';
  const offsets: number[] = [];
  objects.forEach((body, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;

  const bytes = new Uint8Array(out.length);
  for (let i = 0; i < out.length; i++) bytes[i] = out.charCodeAt(i) & 0xff;
  return bytes;
}
