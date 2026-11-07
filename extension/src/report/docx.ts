/**
 * Word (.docx) report built straight from the report model: real headings
 * (so Word's navigation pane works), tables with repeating header rows,
 * shaded call-outs and code blocks, and a footer with page numbers. Written
 * as plain OOXML, so it opens in Word, LibreOffice and Google Docs with no
 * library and nothing leaving the browser.
 */
import type { Block, CaseDoc, Section, Tone } from './model';
import { buildZip } from './zip';

const x = (s: string): string => s.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const PAGE_W = 9900; // text width in twips (A4 with 1000-twip margins)

const TONE: Record<Tone, { fg: string; bg: string }> = {
  bad: { fg: 'B3261E', bg: 'FDECEA' },
  warn: { fg: '8A5300', bg: 'FFF4E0' },
  good: { fg: '1B6E3C', bg: 'E8F6EE' },
  info: { fg: '2A4A8A', bg: 'EAF0FB' },
};
const ACCENT = '3D6B1F';
const DARK = '2E353B';

interface RunOpts { bold?: boolean; italic?: boolean; color?: string; size?: number; mono?: boolean }

function run(text: string, o: RunOpts = {}): string {
  const rpr = `${o.mono ? '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>' : ''}${o.bold ? '<w:b/>' : ''}${o.italic ? '<w:i/>' : ''}${o.color ? `<w:color w:val="${o.color}"/>` : ''}${o.size ? `<w:sz w:val="${o.size}"/><w:szCs w:val="${o.size}"/>` : ''}`;
  const parts = text.split('\n').map((t) => `<w:t xml:space="preserve">${x(t)}</w:t>`).join('<w:br/>');
  return `<w:r>${rpr ? `<w:rPr>${rpr}</w:rPr>` : ''}${parts}</w:r>`;
}

interface ParaOpts extends RunOpts { style?: string; shade?: string; keepNext?: boolean; before?: number; after?: number; left?: number; hanging?: number; pageBreakBefore?: boolean }

function para(text: string | string[], o: ParaOpts = {}): string {
  const ppr = `${o.style ? `<w:pStyle w:val="${o.style}"/>` : ''}${o.keepNext ? '<w:keepNext/>' : ''}${o.pageBreakBefore ? '<w:pageBreakBefore/>' : ''}${o.shade ? `<w:shd w:val="clear" w:color="auto" w:fill="${o.shade}"/>` : ''}${o.before !== undefined || o.after !== undefined ? `<w:spacing${o.before !== undefined ? ` w:before="${o.before}"` : ''}${o.after !== undefined ? ` w:after="${o.after}"` : ''}/>` : ''}${o.left !== undefined ? `<w:ind w:left="${o.left}"${o.hanging ? ` w:hanging="${o.hanging}"` : ''}/>` : ''}`;
  const runs = (Array.isArray(text) ? text : [text]).map((t) => run(t, o)).join('');
  return `<w:p>${ppr ? `<w:pPr>${ppr}</w:pPr>` : ''}${runs}</w:p>`;
}

const border = (color: string, sz = 4) => `w:val="single" w:sz="${sz}" w:space="0" w:color="${color}"`;
const TBL_BORDERS = `<w:tblBorders><w:top ${border('D9DDE3')}/><w:left ${border('D9DDE3')}/><w:bottom ${border('D9DDE3')}/><w:right ${border('D9DDE3')}/><w:insideH ${border('D9DDE3')}/><w:insideV ${border('D9DDE3')}/></w:tblBorders>`;

function cell(text: string, width: number, o: { fill?: string; color?: string; bold?: boolean; mono?: boolean; size?: number; leftBar?: string } = {}): string {
  const tcPr = `<w:tcW w:w="${width}" w:type="dxa"/>${o.leftBar ? `<w:tcBorders><w:left w:val="single" w:sz="36" w:space="0" w:color="${o.leftBar}"/></w:tcBorders>` : ''}${o.fill ? `<w:shd w:val="clear" w:color="auto" w:fill="${o.fill}"/>` : ''}`;
  const paras = text.split('\n').map((t) => para(t, { bold: o.bold, color: o.color, mono: o.mono, size: o.size ?? 18, before: 20, after: 20 })).join('');
  return `<w:tc><w:tcPr>${tcPr}</w:tcPr>${paras || para('', { size: 18 })}</w:tc>`;
}

function table(grid: number[], rows: string[]): string {
  return `<w:tbl><w:tblPr><w:tblW w:w="${PAGE_W}" w:type="dxa"/>${TBL_BORDERS}<w:tblLayout w:type="fixed"/><w:tblCellMar><w:top w:w="30" w:type="dxa"/><w:left w:w="90" w:type="dxa"/><w:bottom w:w="30" w:type="dxa"/><w:right w:w="90" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid>${grid.map((g) => `<w:gridCol w:w="${g}"/>`).join('')}</w:tblGrid>${rows.join('')}</w:tbl>`;
}

const spacer = () => para('', { after: 60, size: 8 });

function block(b: Block): string {
  switch (b.t) {
    case 'h3':
      return para(b.text, { style: 'Heading3', keepNext: true });
    case 'p':
      return para(b.text, b.small ? { size: 17, color: '5D6470', after: 100 } : { after: 100 });
    case 'ul':
      return b.items.map((i) => para(`•  ${i}`, { left: 360, hanging: 260, after: 40 })).join('') + spacer();
    case 'checklist':
      return b.items.map((i) => para(`☐  ${i}`, { left: 420, hanging: 320, after: 40 })).join('') + spacer();
    case 'code':
      return b.text.split('\n').map((l) => para(l || ' ', { style: 'Code' })).join('') + spacer();
    case 'callout': {
      const t = TONE[b.tone];
      const inner = `<w:tc><w:tcPr><w:tcW w:w="${PAGE_W}" w:type="dxa"/><w:tcBorders><w:left w:val="single" w:sz="48" w:space="0" w:color="${t.fg}"/></w:tcBorders><w:shd w:val="clear" w:color="auto" w:fill="${t.bg}"/></w:tcPr>${para(b.title, { bold: true, color: t.fg, size: 26, after: 40 })}${para(b.text, { size: 21, after: 40 })}</w:tc>`;
      return table([PAGE_W], [`<w:tr><w:trPr><w:cantSplit/></w:trPr>${inner}</w:tr>`]) + spacer();
    }
    case 'kv': {
      const k = 2800;
      const rows = b.rows.map(([a, v]) => `<w:tr><w:trPr><w:cantSplit/></w:trPr>${cell(a, k, { fill: 'F5F6F8', bold: true })}${cell(v, PAGE_W - k)}</w:tr>`);
      return table([k, PAGE_W - k], rows) + spacer();
    }
    case 'table': {
      const n = b.head.length;
      const pct = b.widths && b.widths.length === n ? b.widths : Array(n).fill(100 / n);
      const tot = pct.reduce((a, c) => a + c, 0);
      const grid = pct.map((p) => Math.floor((p / tot) * PAGE_W));
      grid[n - 1] = PAGE_W - grid.slice(0, -1).reduce((a, c) => a + c, 0);
      const head = `<w:tr><w:trPr><w:cantSplit/><w:tblHeader/></w:trPr>${b.head.map((h, i) => cell(h, grid[i]!, { fill: DARK, color: 'FFFFFF', bold: true, size: 17 })).join('')}</w:tr>`;
      const body = b.rows.map((r, ri) => `<w:tr><w:trPr><w:cantSplit/></w:trPr>${r.map((c, ci) => cell(c, grid[ci]!, { mono: b.mono?.[ci], size: b.mono?.[ci] ? 15 : 17, bold: ci === 0 && !!b.tones?.[ri], color: ci === 0 && b.tones?.[ri] ? TONE[b.tones[ri]!].fg : undefined })).join('')}</w:tr>`);
      return table(grid, [head, ...body]) + spacer();
    }
  }
}

const PART_TITLE: Record<Section['part'], string> = { executive: 'Part A: Executive summary', technical: 'Part B: Technical analysis', appendix: 'Appendices' };
const PART_LEAD: Record<Section['part'], string> = { executive: 'For leaders, managers and non-technical staff. Plain language.', technical: 'For security analysts, incident responders and investigators.', appendix: 'Reference material.' };

const STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/><w:sz w:val="21"/><w:szCs w:val="21"/><w:lang w:val="en-US"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:before="0" w:after="60"/></w:pPr><w:rPr><w:b/><w:color w:val="FFFFFF"/><w:sz w:val="60"/><w:szCs w:val="60"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:pBdr><w:bottom w:val="single" w:sz="8" w:space="2" w:color="D9DDE3"/></w:pBdr><w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:color w:val="1D2024"/><w:sz w:val="36"/><w:szCs w:val="36"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:color w:val="3D6B1F"/><w:sz w:val="30"/><w:szCs w:val="30"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="200" w:after="60"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Code"><w:name w:val="Code"/><w:basedOn w:val="Normal"/><w:pPr><w:shd w:val="clear" w:color="auto" w:fill="F0F2F4"/><w:spacing w:before="0" w:after="0" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/><w:sz w:val="16"/><w:szCs w:val="16"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Footer"><w:name w:val="footer"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="5D6470"/><w:sz w:val="16"/><w:szCs w:val="16"/></w:rPr></w:style>
</w:styles>`;

export function renderDocx(doc: CaseDoc): Uint8Array {
  const enc = new TextEncoder();
  const body: string[] = [];

  // Cover
  const t = TONE[doc.verdict.tone];
  const coverCell = `<w:tc><w:tcPr><w:tcW w:w="${PAGE_W}" w:type="dxa"/><w:shd w:val="clear" w:color="auto" w:fill="22272B"/></w:tcPr>${para(`TLP:${doc.tlp}   ${doc.meta[0]?.[1] ?? ''}`, { color: 'B9BEC6', size: 18, before: 200, after: 40 })}${para(doc.title, { style: 'Title' })}${para(doc.subtitle, { color: 'E6E9EE', size: 26, after: 160 })}${para(`${doc.verdict.label}   ·   risk score ${doc.verdict.score}/100`, { bold: true, color: 'FFFFFF', shade: t.fg, size: 26, after: 200 })}</w:tc>`;
  body.push(table([PAGE_W], [`<w:tr>${coverCell}</w:tr>`]), spacer());
  body.push(block({ t: 'kv', rows: [...doc.meta.map(([k, v]): [string, string] => [k, v]), ['Tool', `${doc.tool} ${doc.version}`]] }));
  body.push(para('This report was produced on the analyst’s own computer. The email and its files were not uploaded anywhere. Indicators are defanged (hxxp, [.]) so they cannot be clicked by accident.', { size: 17, color: '5D6470' }));
  body.push(para('Contents', { style: 'Heading1', pageBreakBefore: true }));
  let last: Section['part'] | null = null;
  for (const s of doc.sections) {
    if (s.part !== last) { body.push(para(PART_TITLE[s.part], { bold: true, color: ACCENT, size: 22, before: 160, after: 40 })); last = s.part; }
    body.push(para(s.title, { left: 300, after: 20 }));
  }

  last = null;
  for (const s of doc.sections) {
    if (s.part !== last) {
      body.push(para(PART_TITLE[s.part], { bold: true, color: 'FFFFFF', shade: ACCENT, size: 36, pageBreakBefore: true, before: 0, after: 0, keepNext: true }));
      body.push(para(PART_LEAD[s.part], { color: 'FFFFFF', shade: ACCENT, size: 20, after: 200, keepNext: true }));
      last = s.part;
    }
    body.push(para(s.title, { style: 'Heading1' }));
    if (s.lead) body.push(para(s.lead, { italic: true, color: '5D6470', size: 19 }));
    for (const b of s.blocks) body.push(block(b));
  }

  const NS = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"';
  const documentXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document ${NS}><w:body>${body.join('')}<w:sectPr><w:footerReference w:type="default" r:id="rId2"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1000" w:right="1000" w:bottom="1000" w:left="1000" w:header="500" w:footer="500" w:gutter="0"/></w:sectPr></w:body></w:document>`;
  const fld = (instr: string) => `<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> ${instr} </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>`;
  const footerXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr ${NS}><w:p><w:pPr><w:pStyle w:val="Footer"/></w:pPr>${run(`Unmask report  ·  TLP:${doc.tlp}  ·  ${doc.meta[0]?.[1] ?? ''}  ·  Page `)}${fld('PAGE')}${run(' of ')}${fld('NUMPAGES')}</w:p></w:ftr>`;
  const files: { name: string; text: string }[] = [
    { name: '[Content_Types].xml', text: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>` },
    { name: '_rels/.rels', text: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>` },
    { name: 'word/_rels/document.xml.rels', text: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>` },
    { name: 'word/document.xml', text: documentXml },
    { name: 'word/styles.xml', text: STYLES },
    { name: 'word/footer1.xml', text: footerXml },
    { name: 'docProps/core.xml', text: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>${x(`${doc.title}: ${doc.subtitle}`.slice(0, 200))}</dc:title><dc:creator>${x(doc.tool)}</dc:creator><dcterms:created xsi:type="dcterms:W3CDTF">${x(doc.generatedAt.slice(0, 19))}Z</dcterms:created></cp:coreProperties>` },
    { name: 'docProps/app.xml', text: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Unmask</Application><AppVersion>${x(doc.version.replace(/[^\d.]/g, '') || '1.0')}</AppVersion></Properties>` },
  ];
  return buildZip(files.map((f) => ({ name: f.name, data: enc.encode(f.text) })), new Date(doc.generatedAt));
}
