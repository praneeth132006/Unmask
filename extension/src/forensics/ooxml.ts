/**
 * Word, Excel and PowerPoint files that are really ZIPs of XML parts
 * (.docx, .xlsx, .pptx and their macro-enabled twins). Walks the relationship
 * files, fields, formulas, slides and the VBA project, like Didier Stevens'
 * oledump/zipdump with the OOXML plugins, but built for the browser. Nothing
 * is opened or run; parts are only read as text and bytes.
 */
import { zipEntries, zipRead, type ZipEntry } from '../lib/binary';
import { extractIocs } from './ioc';
import { emptyMacros, parseCfb, readVbaMacros } from './ole';
import type { Anomaly, ExtractedLink, Iocs, OfficeField, OoxmlReport } from './types';
import { EMPTY_IOCS } from './types';
import { sniff } from './util';

const dec = new TextDecoder();
const unxml = (s: string) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_, n: string) => String.fromCharCode(Number(n))).replace(/&amp;/g, '&');
const attr = (tag: string, name: string) => tag.match(new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`, 'i'))?.[1];
const isUnc = (t: string) => /^\\\\[^\\]/.test(t) || /^file:/i.test(t) || /^\/\/[^/]/.test(t);

const LURE = /enable (editing|content|macros)|protected view|this document is (protected|encrypted)|unable to display|scan (the|this) qr|click (here )?to (view|open|download|unlock)|to (view|read|unlock) (this|the) (document|content|message)|sign in to (view|continue)|previewing is not available/gi;
const GENERATORS = /aspose|python-docx|openpyxl|xlsxwriter|docx4j|apache poi|libreoffice|pandoc|epplus|closedxml|spire|docxtemplater|xlsx-populate|exceljs/i;

export interface OoxmlAnalysis {
  report: OoxmlReport;
  anomalies: Anomaly[];
  links: ExtractedLink[];
  iocs: Iocs;
  embeddedFiles: { name: string; bytes: Uint8Array }[];
}

export async function analyzeOoxml(bytes: Uint8Array): Promise<OoxmlAnalysis> {
  const entries = zipEntries(bytes, 6000);
  const byName = new Map(entries.map((e) => [e.name, e]));
  const names = entries.map((e) => e.name);
  const anomalies: Anomaly[] = [];
  const add = (a: Anomaly) => { if (!anomalies.some((x) => x.id === a.id)) anomalies.push(a); };
  const links: ExtractedLink[] = [];
  const fields: OfficeField[] = [];
  const read = async (e: ZipEntry | undefined, limit = 4 * 1024 * 1024): Promise<string> => {
    if (!e) return '';
    const b = await zipRead(bytes, e, limit);
    return b ? dec.decode(b) : '';
  };
  const readNamed = (n: string, limit?: number) => read(byName.get(n), limit);

  const app: OoxmlReport['app'] = names.some((n) => n.startsWith('word/')) ? 'word' : names.some((n) => n.startsWith('xl/')) ? 'excel' : names.some((n) => n.startsWith('ppt/')) ? 'powerpoint' : 'unknown';

  /* metadata */
  const metadata: Record<string, string> = {};
  const core = await readNamed('docProps/core.xml', 200_000);
  const pick = (xml: string, tag: string) => unxml(xml.match(new RegExp(`<${tag}[^>]*>([^<]{1,300})</${tag}>`))?.[1] ?? '');
  for (const [k, tag] of [['Creator', 'dc:creator'], ['LastModifiedBy', 'cp:lastModifiedBy'], ['Created', 'dcterms:created'], ['Modified', 'dcterms:modified'], ['Revision', 'cp:revision'], ['Title', 'dc:title']] as const) { const v = pick(core, tag); if (v) metadata[k] = v; }
  const appXml = await readNamed('docProps/app.xml', 200_000);
  for (const [k, tag] of [['Application', 'Application'], ['AppVersion', 'AppVersion'], ['Company', 'Company'], ['Template', 'Template'], ['TotalTime', 'TotalTime']] as const) { const v = pick(appXml, tag); if (v) metadata[k] = v; }

  /* relationships: everything that points outside the file */
  const externalRefs: OoxmlReport['externalRefs'] = [];
  const relMaps = new Map<string, Map<string, { type: string; target: string; external: boolean }>>();
  for (const e of entries.filter((x) => /\.rels$/i.test(x.name)).slice(0, 200)) {
    const xml = await read(e, 1024 * 1024);
    const map = new Map<string, { type: string; target: string; external: boolean }>();
    for (const m of xml.matchAll(/<Relationship\b[^>]*>/g)) {
      const tag = m[0];
      const target = unxml(attr(tag, 'Target') ?? '');
      const type = (attr(tag, 'Type') ?? '').split('/').pop() ?? '';
      const external = /TargetMode\s*=\s*"External"/i.test(tag);
      const id = attr(tag, 'Id');
      if (id) map.set(id, { type, target, external });
      if (external && target) externalRefs.push({ part: e.name, type, target, mode: 'External' });
    }
    relMaps.set(e.name, map);
  }
  const relsFor = (part: string) => relMaps.get(part.replace(/([^/]+)$/, '_rels/$1.rels')) ?? new Map();

  for (const r of externalRefs) {
    const how: ExtractedLink['how'] = /attachedTemplate/i.test(r.type) ? 'template' : /hyperlink/i.test(r.type) ? 'link' : /image|oleObject|frame|subDocument|externalLink|audio|video|footnotes|connections|aftChunk|altChunk|slideMaster|slide/i.test(r.type) ? 'resource' : 'link';
    if (/^(https?|ftp|file|smb|\\\\)/i.test(r.target) || isUnc(r.target)) links.push({ url: r.target, where: `${r.part} (${r.type})`, how });
  }

  /* hyperlinks with their visible text, and fields */
  if (app === 'word') {
    for (const e of entries.filter((x) => /^word\/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$/i.test(x.name)).slice(0, 12)) {
      const xml = await read(e, 6 * 1024 * 1024);
      const rels = relsFor(e.name);
      for (const m of xml.matchAll(/<w:hyperlink\b([^>]*)>([\s\S]*?)<\/w:hyperlink>/g)) {
        const id = attr(m[1]!, 'r:id');
        const target = id ? rels.get(id)?.target : undefined;
        const label = [...m[2]!.matchAll(/<w:t[^>]*>([^<]*)<\/w:t>/g)].map((t) => unxml(t[1]!)).join('').trim();
        if (target) { const l = links.find((x) => x.url === target); if (l) l.label = label.slice(0, 120); else links.push({ url: target, where: e.name, how: 'link', label: label.slice(0, 120) }); }
      }
      for (const m of xml.matchAll(/<w:instrText[^>]*>([^<]{1,2000})<\/w:instrText>|<w:fldSimple\b[^>]*w:instr="([^"]{1,2000})"/g)) {
        const instr = unxml(m[1] ?? m[2] ?? '').trim();
        const type = instr.match(/^\s*([A-Za-z]+)/)?.[1]?.toUpperCase() ?? '';
        if (type && fields.length < 80 && /^(HYPERLINK|INCLUDETEXT|INCLUDEPICTURE|LINK|DDE|DDEAUTO|MACROBUTTON|IMPORT|DATABASE|AUTOTEXT|QUOTE|SYMBOL|SET|IF|MERGEFIELD|REF|EMBED)$/.test(type)) fields.push({ type, instr: instr.slice(0, 300), where: e.name });
        const url = instr.match(/"((?:https?|ftp|file|\\\\)[^"]+)"/i)?.[1] ?? instr.match(/(?:HYPERLINK|INCLUDETEXT|INCLUDEPICTURE|LINK)\s+"?((?:https?|ftp|file):\/\/[^\s"]+)/i)?.[1];
        if (url && !links.some((l) => l.url === url)) links.push({ url, where: `${type} field in ${e.name}`, how: type === 'HYPERLINK' ? 'link' : 'resource' });
      }
    }
  }
  let hiddenSlides = 0;
  if (app === 'powerpoint') {
    for (const e of entries.filter((x) => /^ppt\/slides\/slide\d+\.xml$/i.test(x.name)).slice(0, 200)) {
      const xml = await read(e, 2 * 1024 * 1024);
      if (/<p:sld\b[^>]*\bshow="0"/.test(xml)) hiddenSlides++;
      const rels = relsFor(e.name);
      for (const m of xml.matchAll(/<a:hlink(?:Click|Hover)\b([^>]*)\/?>/g)) {
        const id = attr(m[1]!, 'r:id');
        const action = attr(m[1]!, 'action') ?? '';
        const target = id ? rels.get(id)?.target : undefined;
        if (target && !links.some((l) => l.url === target)) links.push({ url: target, where: e.name, how: 'link' });
        if (/ppaction:\/\/(program|macro)/i.test(action)) fields.push({ type: 'ACTION', instr: `${action}${target ? ` ${target}` : ''}`, where: e.name });
      }
    }
  }
  let hiddenSheets: string[] = [];
  let autoOpenName = false;
  if (app === 'excel') {
    const wb = await readNamed('xl/workbook.xml', 1024 * 1024);
    hiddenSheets = [...wb.matchAll(/<sheet\b[^>]*>/g)].filter((m) => /state="(hidden|veryHidden)"/i.test(m[0])).map((m) => `${unxml(attr(m[0], 'name') ?? '?')} (${/veryHidden/i.test(m[0]) ? 'very hidden' : 'hidden'})`);
    autoOpenName = /<definedName\b[^>]*name="_?xlnm\.(Auto_Open|Auto_Close)|<definedName\b[^>]*name="Auto_(Open|Close)"/i.test(wb);
    const conn = await readNamed('xl/connections.xml', 1024 * 1024);
    for (const m of conn.matchAll(/<(?:webPr|dbPr|textPr)\b[^>]*\b(?:url|connection|sourceFile)="([^"]+)"/g)) { const t = unxml(m[1]!); if (/^(https?|ftp|file)/i.test(t) || isUnc(t)) links.push({ url: t, where: 'xl/connections.xml (data connection)', how: 'resource' }); else fields.push({ type: 'CONNECTION', instr: t.slice(0, 200), where: 'xl/connections.xml' }); }
    for (const e of entries.filter((x) => /^xl\/worksheets\/sheet\d+\.xml$/i.test(x.name)).slice(0, 40)) {
      const xml = await read(e, 4 * 1024 * 1024);
      for (const m of xml.matchAll(/<f[^>]*>([^<]{1,1500})<\/f>/g)) {
        const f = unxml(m[1]!);
        const url = f.match(/HYPERLINK\s*\(\s*"([^"]+)"(?:\s*,\s*"([^"]*)")?/i);
        if (url) links.push({ url: url[1]!, where: `${e.name} (formula)`, how: 'link', label: url[2] });
        if (/\b(EXEC|CALL|REGISTER|RUN|FOPEN|URLDownloadToFile|SHELL)\s*\(/i.test(f)) fields.push({ type: 'FORMULA', instr: f.slice(0, 200), where: e.name });
      }
      const rels = relsFor(e.name);
      for (const m of xml.matchAll(/<hyperlink\b([^>]*)\/?>/g)) { const id = attr(m[1]!, 'r:id'); const t = id ? rels.get(id)?.target : undefined; if (t && !links.some((l) => l.url === t)) links.push({ url: t, where: e.name, how: 'link', label: attr(m[1]!, 'display') }); }
    }
  }

  /* macros: the VBA project is itself an OLE container */
  let macros = emptyMacros();
  const vba = entries.find((e) => /(^|\/)vbaProject\.bin$/i.test(e.name));
  let macroSources: string[] = [];
  if (vba) {
    const raw = await zipRead(bytes, vba, 16 * 1024 * 1024);
    const cfb = raw ? parseCfb(raw) : null;
    if (cfb) { const r = readVbaMacros(cfb); macros = r.macros; macroSources = r.sources; }
    macros.present = true;
  }
  const macroSheets = entries.filter((e) => /\/macrosheets\/[^/]+\.xml$/i.test(e.name));
  if (macroSheets.length) { macros.present = true; macros.xlmSheets = macroSheets.map((e) => ({ name: e.name.split('/').pop()!.replace(/\.xml$/i, ''), hidden: 'visible' as const })); }

  /* embedded objects */
  const embedded: OoxmlReport['embedded'] = [];
  const embeddedFiles: { name: string; bytes: Uint8Array }[] = [];
  for (const e of entries.filter((x) => /\/embeddings\/[^/]+$|oleObject\d*\.bin$|\/activeX\/[^/]+\.bin$/i.test(x.name)).slice(0, 12)) {
    const b = await zipRead(bytes, e, 8 * 1024 * 1024);
    if (!b) { embedded.push({ part: e.name, size: e.size, type: e.encrypted ? 'encrypted' : 'unreadable' }); continue; }
    embedded.push({ part: e.name, size: b.length, type: sniff(b).label });
    if (embeddedFiles.length < 8) embeddedFiles.push({ name: e.name, bytes: b });
  }
  const activeX = names.filter((n) => /\/activeX\/activeX\d+\.xml$/i.test(n)).length;

  /* visible text and lure phrases */
  const textParts: string[] = [];
  const textSources = app === 'word' ? ['word/document.xml'] : app === 'powerpoint' ? names.filter((n) => /^ppt\/slides\/slide\d+\.xml$/i.test(n)).slice(0, 6) : ['xl/sharedStrings.xml'];
  for (const n of textSources) {
    const xml = await readNamed(n, 3 * 1024 * 1024);
    for (const m of xml.matchAll(/<(?:w:t|a:t|t)(?:\s[^>]*)?>([^<]*)<\/(?:w:t|a:t|t)>/g)) { textParts.push(unxml(m[1]!)); if (textParts.join(' ').length > 3000) break; }
  }
  const fullText = textParts.join(' ');
  const textPreview = fullText.replace(/\s+/g, ' ').trim().slice(0, 600);
  const lurePhrases = [...new Set([...fullText.matchAll(LURE)].map((m) => m[0].toLowerCase()))].slice(0, 6);

  /* indicators */
  const iocText = [fullText, macroSources.join('\n'), externalRefs.map((r) => r.target).join('\n'), fields.map((f) => f.instr).join('\n')].join('\n');
  const found = extractIocs(iocText, { decode: true });
  for (const u of found.iocs.urls) if (!links.some((l) => l.url === u)) links.push({ url: u, where: macroSources.join('').includes(u) ? 'macro code' : 'text inside the file', how: macroSources.join('').includes(u) ? 'macro' : 'text' });
  for (const d of found.decoded) if (macroSources.length && /program|text/.test(d.label)) add({ id: 'ole-base64', severity: d.label.includes('program') ? 'critical' : 'medium', title: `Macro hides ${d.label} in base64`, detail: d.preview, plain: 'The macro contains an encoded block that decodes to something hidden.', attack: 'T1027' });

  const template = externalRefs.find((r) => /attachedTemplate/i.test(r.type));
  if (template) add({ id: 'office-remote-template', severity: 'critical', title: 'Loads a template from the internet when opened', detail: template.target, plain: 'This document fetches a file from another server the moment it is opened (template injection), a way to run macros without carrying them.', where: template.part, attack: 'T1221' });
  const remoteObj = externalRefs.filter((r) => /oleObject|frame|subDocument|altChunk|aFChunk|externalLink|connections/i.test(r.type) && /^(https?|ftp)/i.test(r.target));
  if (remoteObj.length) add({ id: 'office-remote-object', severity: 'high', title: 'Pulls content from the internet when opened', detail: remoteObj.slice(0, 3).map((r) => `${r.type}: ${r.target}`).join('; '), plain: 'Parts of this document are loaded from another server, so what you see can change after it reaches you.', attack: 'T1221' });
  const unc = [...externalRefs.map((r) => r.target), ...fields.map((f) => f.instr)].filter(isUnc);
  if (unc.length) add({ id: 'office-unc-leak', severity: 'high', title: 'Reaches out to a file share or local path', detail: unc.slice(0, 3).join('; '), plain: 'Opening this document can contact another computer and leak your Windows sign-in hash.', attack: 'T1187' });
  const remoteImg = externalRefs.filter((r) => /image/i.test(r.type) && /^https?/i.test(r.target));
  if (remoteImg.length) add({ id: 'office-remote-image', severity: 'medium', title: 'Loads a picture from the internet', detail: remoteImg[0]!.target, plain: 'A picture is loaded from a web address, which tells the sender you opened the file.' });
  if (macros.present) {
    const auto = macros.autoExec.length > 0, risky = macros.suspicious.length > 0;
    add({ id: 'office-macros', severity: auto && risky ? 'critical' : 'high', title: `Contains macros${auto ? ' that run automatically' : ''}`, detail: [auto ? `auto-run: ${macros.autoExec.join(', ')}` : '', risky ? `uses: ${macros.suspicious.slice(0, 5).join('; ')}` : ''].filter(Boolean).join(' · ') || undefined, plain: auto ? 'This document has a macro set to start as soon as you enable content, and it uses features malware relies on.' : 'This document contains macros (code that can run when you click "Enable content").', attack: 'T1204.002' });
    if (macros.obfuscation.chrCalls > 30 || macros.obfuscation.longStrings > 0 || macros.obfuscation.base64Blobs > 0) add({ id: 'ole-macro-obfuscated', severity: 'high', title: 'Macro code is obfuscated', detail: `Chr() calls: ${macros.obfuscation.chrCalls}, very long strings: ${macros.obfuscation.longStrings}, base64-like blobs: ${macros.obfuscation.base64Blobs}`, plain: 'The macro code is deliberately scrambled so people and scanners cannot read it.', attack: 'T1027' });
  }
  if (macros.xlmSheets.length) add({ id: 'ole-xlm', severity: 'high', title: 'Excel 4.0 macro sheet', plain: 'This spreadsheet contains old-style Excel 4.0 macros. Many scanners do not read them, so malware authors favour them.', attack: 'T1059' });
  if (fields.some((f) => /^DDE(AUTO)?$/.test(f.type)) || /DDEAUTO|\bDDE\b\s*"/i.test(await readNamed('word/document.xml', 4 * 1024 * 1024))) add({ id: 'office-dde', severity: 'high', title: 'Uses DDE fields that can run commands', plain: 'This document uses an old feature that can start programs when you accept a prompt.', attack: 'T1559.002' });
  if (fields.some((f) => f.type === 'MACROBUTTON')) add({ id: 'office-macrobutton', severity: 'medium', title: 'Has a MACROBUTTON field', plain: 'A button in the text that runs a macro when clicked.' });
  if (fields.some((f) => f.type === 'FORMULA')) add({ id: 'office-xlm-formula', severity: 'high', title: 'Spreadsheet formulas that run commands', detail: fields.find((f) => f.type === 'FORMULA')?.instr, plain: 'Formulas in this spreadsheet start programs or download files.', attack: 'T1059' });
  if (fields.some((f) => f.type === 'ACTION')) add({ id: 'office-ppt-action', severity: 'high', title: 'Slide runs a program or macro when clicked', detail: fields.find((f) => f.type === 'ACTION')?.instr, plain: 'A shape or text in this presentation starts a program or macro when clicked.', attack: 'T1204.002' });
  if (embedded.length) add({ id: 'office-ole', severity: embedded.some((e) => /program|script|shortcut/i.test(e.type)) ? 'critical' : 'medium', title: `Contains embedded objects (${embedded.length})`, detail: embedded.map((e) => `${e.part.split('/').pop()} (${e.type})`).join('; '), plain: 'Other files are hidden inside this document.', attack: 'T1027.009' });
  if (activeX) add({ id: 'office-activex', severity: 'medium', title: `Contains ActiveX controls (${activeX})`, plain: 'Interactive components that can run code. Ordinary letters and reports do not need them.' });
  if (hiddenSheets.length) add({ id: 'office-hidden-sheet', severity: hiddenSheets.some((s) => /very hidden/.test(s)) || autoOpenName ? 'medium' : 'low', title: `Hidden sheets: ${hiddenSheets.join(', ')}`, plain: 'Parts of this workbook are hidden from view, which is where macro payloads and lure data are often kept.' });
  if (autoOpenName) add({ id: 'office-auto-open-name', severity: 'high', title: 'Workbook defines an Auto_Open name', plain: 'This workbook is set to run something automatically when it is opened.', attack: 'T1204.002' });
  if (hiddenSlides > 0 && links.length) add({ id: 'office-hidden-slides', severity: 'low', title: `${hiddenSlides} hidden slide${hiddenSlides > 1 ? 's' : ''}`, plain: 'Some slides are hidden from the slide show.' });
  if (lurePhrases.length) add({ id: 'office-lure', severity: 'medium', title: 'Text pushes you to switch protection off or click through', detail: lurePhrases.join(', '), plain: 'The document tells you to enable editing, enable content or click to view. That is how malicious documents get past Office’s safety features.', attack: 'T1204.002' });
  if (GENERATORS.test(`${metadata.Application ?? ''} ${metadata.Creator ?? ''}`)) add({ id: 'office-generated', severity: 'info', title: `Created by a document library: ${metadata.Application ?? metadata.Creator}`, plain: 'Made by software that builds documents automatically, as mass-mailed lures are. Many legitimate reports are built this way too.' });

  return {
    report: { app, parts: names.length, metadata, externalRefs: externalRefs.slice(0, 60), fields: fields.slice(0, 60), macros, embedded, activeX, hiddenSheets, hiddenSlides, textPreview, lurePhrases },
    anomalies,
    links,
    iocs: { ...EMPTY_IOCS(), ...found.iocs },
    embeddedFiles,
  };
}
