/**
 * A small PDF layout engine for the investigation report: A4 pages, real
 * Helvetica widths for accurate wrapping, headings, bullets, bordered tables
 * with repeating headers, shaded code and callout boxes, a cover page and a
 * contents page with page numbers. No dependencies, so it runs in the
 * browser with nothing sent anywhere. Text outside Latin-1 becomes "?".
 */
import type { Block, CaseDoc, Section, Tone } from './model';

const W = 595.28;
const H = 841.89;
const M = 48;
const CW = W - 2 * M;

/** Helvetica advance widths (per 1000 em) for ASCII 32..126. */
const HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584];

type Font = 'F1' | 'F2' | 'F3';

function winAnsi(s: string): string {
  return s
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[–—−]/g, '-')
    .replace(/…/g, '...')
    .replace(/→/g, '->')
    .replace(/[☐□]/g, '[ ]')
    .replace(/[•·]/g, '-')
    .replace(/[^\x20-\x7e\xa0-\xff\n]/g, '?');
}

const esc = (s: string) => s.replace(/[\\()]/g, '\\$&');

function width(text: string, font: Font, size: number): number {
  if (font === 'F3') return text.length * 0.6 * size;
  let w = 0;
  for (const ch of text) {
    const c = ch.charCodeAt(0);
    w += c >= 32 && c <= 126 ? HELV[c - 32]! : 556;
  }
  return (w / 1000) * size * (font === 'F2' ? 1.07 : 1);
}

function wrap(text: string, font: Font, size: number, maxW: number): string[] {
  const out: string[] = [];
  for (const para of winAnsi(text).split('\n')) {
    let line = '';
    for (const word of para.split(/(\s+)/)) {
      if (!word) continue;
      if (width(line + word, font, size) <= maxW) { line += word; continue; }
      if (line.trim()) { out.push(line.trimEnd()); line = ''; }
      let w = word.trimStart();
      // Words wider than the line (URLs, hashes) are hard-split.
      while (width(w, font, size) > maxW && w.length > 1) {
        let n = w.length;
        while (n > 1 && width(w.slice(0, n), font, size) > maxW) n--;
        out.push(w.slice(0, n));
        w = w.slice(n);
      }
      line = w;
    }
    out.push(line.trimEnd());
  }
  return out;
}

type Rgb = [number, number, number];
const TONE: Record<Tone, { fg: Rgb; bg: Rgb }> = {
  bad: { fg: [0.7, 0.15, 0.12], bg: [0.99, 0.93, 0.92] },
  warn: { fg: [0.54, 0.33, 0], bg: [1, 0.96, 0.88] },
  good: { fg: [0.1, 0.43, 0.24], bg: [0.91, 0.97, 0.94] },
  info: { fg: [0.16, 0.29, 0.54], bg: [0.92, 0.94, 0.98] },
};
const INK: Rgb = [0.11, 0.125, 0.14];
const MUTE: Rgb = [0.36, 0.39, 0.44];
const ACCENT: Rgb = [0.24, 0.42, 0.12];
const DARK: Rgb = [0.13, 0.15, 0.17];
const LINE: Rgb = [0.85, 0.87, 0.89];
const rg = (c: Rgb) => c.map((v) => v.toFixed(3)).join(' ');

class Page {
  ops: string[] = [];
}

class Writer {
  pages: Page[] = [new Page()];
  y = H - M;
  headings: { id: string; title: string; page: number; level: number }[] = [];

  get page() { return this.pages[this.pages.length - 1]!; }
  get no() { return this.pages.length; }
  newPage() { this.pages.push(new Page()); this.y = H - M; }
  ensure(h: number) { if (this.y - h < M + 22) this.newPage(); }

  text(x: number, y: number, s: string, font: Font, size: number, color: Rgb) {
    this.page.ops.push(`BT /${font} ${size} Tf ${rg(color)} rg ${x.toFixed(1)} ${y.toFixed(1)} Td (${esc(winAnsi(s))}) Tj ET`);
  }
  rect(x: number, y: number, w: number, h: number, fill?: Rgb, stroke?: Rgb) {
    const parts: string[] = [];
    if (fill) parts.push(`${rg(fill)} rg`);
    if (stroke) parts.push(`${rg(stroke)} RG 0.6 w`);
    parts.push(`${x.toFixed(1)} ${y.toFixed(1)} ${w.toFixed(1)} ${h.toFixed(1)} re ${fill && stroke ? 'B' : fill ? 'f' : 'S'}`);
    this.page.ops.push(parts.join(' '));
  }

  /** Wrapped paragraph at the cursor. Returns nothing; advances y. */
  para(s: string, font: Font, size: number, color: Rgb, opts: { indent?: number; lead?: number; maxW?: number; gapAfter?: number } = {}) {
    const lead = opts.lead ?? size * 1.4;
    const x = M + (opts.indent ?? 0);
    for (const line of wrap(s, font, size, (opts.maxW ?? CW) - (opts.indent ?? 0))) {
      this.ensure(lead);
      this.y -= lead;
      this.text(x, this.y + lead * 0.22, line, font, size, color);
    }
    this.y -= opts.gapAfter ?? 4;
  }
}

function drawBlock(w: Writer, b: Block): void {
  switch (b.t) {
    case 'h3':
      w.y -= 6;
      w.ensure(40);
      w.para(b.text, 'F2', 11.5, INK, { gapAfter: 3 });
      return;
    case 'p':
      w.para(b.text, 'F1', b.small ? 8.5 : 10, b.small ? MUTE : INK, { gapAfter: 6 });
      return;
    case 'ul':
    case 'checklist':
      for (const item of b.items) {
        const lines = wrap(item, 'F1', 10, CW - 20);
        w.ensure(14 * Math.min(lines.length, 2));
        lines.forEach((line, i) => {
          w.ensure(14);
          w.y -= 14;
          if (i === 0) w.text(M + 4, w.y + 3, b.t === 'checklist' ? '[ ]' : '-', 'F1', 10, ACCENT);
          w.text(M + (b.t === 'checklist' ? 24 : 16), w.y + 3, line, 'F1', 10, INK);
        });
        w.y -= 2;
      }
      w.y -= 4;
      return;
    case 'code': {
      const lines = wrap(b.text, 'F3', 7.8, CW - 16);
      let i = 0;
      while (i < lines.length) {
        const room = Math.max(1, Math.floor((w.y - M - 26) / 10));
        const take = Math.min(lines.length - i, room);
        if (take < Math.min(3, lines.length - i)) { w.newPage(); continue; }
        const h = take * 10 + 8;
        w.rect(M, w.y - h, CW, h, [0.94, 0.95, 0.96], LINE);
        for (let k = 0; k < take; k++) w.text(M + 8, w.y - 11 - k * 10, lines[i + k]!, 'F3', 7.8, INK);
        w.y -= h + 4;
        i += take;
        if (i < lines.length) w.newPage();
      }
      w.y -= 4;
      return;
    }
    case 'callout': {
      const t = TONE[b.tone];
      const tl = wrap(b.title, 'F2', 11.5, CW - 28);
      const bl = wrap(b.text, 'F1', 10, CW - 28);
      const h = 14 + tl.length * 15 + bl.length * 13.5 + 6;
      w.ensure(Math.min(h, 200));
      w.rect(M, w.y - h, CW, h, t.bg);
      w.rect(M, w.y - h, 5, h, t.fg);
      let y = w.y - 8;
      for (const l of tl) { y -= 15; w.text(M + 16, y + 3, l, 'F2', 11.5, t.fg); }
      for (const l of bl) { y -= 13.5; w.text(M + 16, y + 3, l, 'F1', 10, INK); }
      w.y -= h + 8;
      return;
    }
    case 'kv': {
      const kw = 150;
      for (const [k, v] of b.rows) {
        const kl = wrap(k, 'F2', 9, kw - 12);
        const vl = wrap(v, 'F1', 9.5, CW - kw - 12);
        const rows = Math.max(kl.length, vl.length);
        const h = rows * 12.5 + 7;
        w.ensure(h);
        w.rect(M, w.y - h, kw, h, [0.96, 0.965, 0.97], LINE);
        w.rect(M + kw, w.y - h, CW - kw, h, undefined, LINE);
        kl.forEach((l, i) => w.text(M + 6, w.y - 12 - i * 12.5, l, 'F2', 9, INK));
        vl.forEach((l, i) => w.text(M + kw + 6, w.y - 12 - i * 12.5, l, 'F1', 9.5, INK));
        w.y -= h;
      }
      w.y -= 8;
      return;
    }
    case 'table': {
      const n = b.head.length;
      const pct = b.widths && b.widths.length === n ? b.widths : Array(n).fill(100 / n);
      const total = pct.reduce((a, c) => a + c, 0);
      const cols = pct.map((p) => (p / total) * CW);
      const draw = (cells: string[], header: boolean, tone?: Tone) => {
        const font = (ci: number): Font => (header ? 'F2' : b.mono?.[ci] ? 'F3' : 'F1');
        const size = (ci: number) => (header ? 8.5 : b.mono?.[ci] ? 7.2 : 8.6);
        const wrapped = cells.map((c, ci) => wrap(c || '', font(ci), size(ci), cols[ci]! - 10));
        const lines = Math.max(...wrapped.map((x) => x.length));
        const lead = 10.6;
        const h = lines * lead + 8;
        if (w.y - h < M + 22) {
          w.newPage();
          if (!header) draw(b.head, true);
        }
        let x = M;
        wrapped.forEach((ls, ci) => {
          w.rect(x, w.y - h, cols[ci]!, h, header ? DARK : undefined, header ? undefined : LINE);
          const color = header ? ([1, 1, 1] as Rgb) : ci === 0 && tone ? TONE[tone].fg : INK;
          const f = !header && ci === 0 && tone ? 'F2' : font(ci);
          ls.forEach((l, i) => w.text(x + 5, w.y - 9 - i * lead, l, f, size(ci), color));
          x += cols[ci]!;
        });
        w.y -= h;
      };
      w.ensure(40);
      draw(b.head, true);
      b.rows.forEach((r, i) => draw(r, false, b.tones?.[i]));
      w.y -= 10;
      return;
    }
  }
}

const PART_TITLE: Record<Section['part'], string> = { executive: 'Part A: Executive summary', technical: 'Part B: Technical analysis', appendix: 'Appendices' };
const PART_LEAD: Record<Section['part'], string> = { executive: 'For leaders, managers and non-technical staff. Plain language.', technical: 'For security analysts, incident responders and investigators.', appendix: 'Reference material.' };

function layout(doc: CaseDoc, toc: Map<string, number> | null): Writer {
  const w = new Writer();
  // Cover
  w.rect(0, H - 250, W, 250, DARK);
  w.text(M, H - 70, `TLP:${doc.tlp}   ${doc.meta[0]?.[1] ?? ''}`, 'F1', 9, [0.75, 0.78, 0.82]);
  w.text(M, H - 112, doc.title, 'F2', 30, [1, 1, 1]);
  let y = H - 140;
  for (const l of wrap(doc.subtitle, 'F1', 13, CW).slice(0, 3)) { w.text(M, y, l, 'F1', 13, [0.9, 0.92, 0.94]); y -= 17; }
  const t = TONE[doc.verdict.tone];
  const label = `${doc.verdict.label}   -   risk score ${doc.verdict.score}/100`;
  const bw = width(label, 'F2', 13) + 28;
  w.rect(M, H - 232, bw, 26, t.fg);
  w.text(M + 14, H - 224, label, 'F2', 13, [1, 1, 1]);
  w.y = H - 280;
  drawBlock(w, { t: 'kv', rows: [...doc.meta.map(([k, v]): [string, string] => [k, v]), ['Tool', `${doc.tool} ${doc.version}`]] });
  w.para('This report was produced on the analyst’s own computer. The email and its files were not uploaded anywhere. Indicators are defanged (hxxp, [.]) so they cannot be clicked by accident.', 'F1', 9, MUTE, { gapAfter: 8 });

  // Contents
  w.newPage();
  w.para('Contents', 'F2', 20, INK, { gapAfter: 10 });
  let lastPart: Section['part'] | null = null;
  for (const s of doc.sections) {
    if (s.part !== lastPart) { w.para(PART_TITLE[s.part], 'F2', 11, ACCENT, { gapAfter: 3 }); lastPart = s.part; }
    w.ensure(14);
    w.y -= 14;
    const pg = toc?.get(s.id);
    w.text(M + 10, w.y + 3, s.title, 'F1', 10, INK);
    if (pg) w.text(W - M - width(String(pg), 'F1', 10), w.y + 3, String(pg), 'F1', 10, MUTE);
  }

  // Body
  lastPart = null;
  for (const s of doc.sections) {
    if (s.part !== lastPart) {
      w.newPage();
      w.rect(M, w.y - 56, CW, 56, ACCENT);
      w.text(M + 16, w.y - 26, PART_TITLE[s.part], 'F2', 18, [1, 1, 1]);
      w.text(M + 16, w.y - 44, PART_LEAD[s.part], 'F1', 9.5, [0.92, 0.96, 0.9]);
      w.y -= 76;
      lastPart = s.part;
    } else if (w.y < H - 260) w.ensure(120);
    w.headings.push({ id: s.id, title: s.title, page: w.no, level: 1 });
    w.y -= 8;
    w.ensure(60);
    w.para(s.title, 'F2', 16, INK, { gapAfter: 2 });
    w.rect(M, w.y - 1, CW, 1.4, LINE);
    w.y -= 8;
    if (s.lead) w.para(s.lead, 'F1', 9.5, MUTE, { gapAfter: 6 });
    for (const b of s.blocks) drawBlock(w, b);
  }
  return w;
}

export function renderPdf(doc: CaseDoc): Uint8Array {
  // Two passes: the first finds which page each section lands on for the contents list.
  const first = layout(doc, null);
  const toc = new Map(first.headings.map((h) => [h.id, h.page]));
  const w = layout(doc, toc);

  const objects: string[] = [];
  objects.push('<< /Type /Catalog /Pages 2 0 R >>', '', '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>', '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>', '<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>');
  const info = objects.length + 1;
  objects.push(`<< /Title (${esc(winAnsi(`${doc.title}: ${doc.subtitle}`.slice(0, 120)))}) /Producer (${esc(winAnsi(`${doc.tool} ${doc.version}`))}) /Subject (Email investigation report) >>`);
  const kids: number[] = [];
  const total = w.pages.length;
  w.pages.forEach((p, i) => {
    const foot = `BT /F1 7.5 Tf ${rg(MUTE)} rg ${M} 28 Td (${esc(winAnsi(`Unmask report  -  TLP:${doc.tlp}  -  ${doc.meta[0]?.[1] ?? ''}`))}) Tj ET BT /F1 7.5 Tf ${rg(MUTE)} rg ${(W - M - 52).toFixed(1)} 28 Td (${esc(`Page ${i + 1} of ${total}`)}) Tj ET`;
    const stream = `${p.ops.join('\n')}\n${foot}`;
    objects.push(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
    const contentId = objects.length;
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${W.toFixed(2)} ${H.toFixed(2)}] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents ${contentId} 0 R >>`);
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
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Info ${info} 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  const bytes = new Uint8Array(out.length);
  for (let i = 0; i < out.length; i++) bytes[i] = out.charCodeAt(i) & 0xff;
  return bytes;
}
