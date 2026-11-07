/**
 * Legacy Office files (.doc, .xls, .ppt) and the VBA projects inside every
 * Office format. Same ideas as Didier Stevens' oledump.py and its VBA
 * plugins, rewritten for the browser: read the OLE2 container, list its
 * streams, decompress the VBA source and look for what malware needs
 * (auto-run macros, shell commands, downloads), plus Excel 4.0 macro sheets.
 */
import { latin1 } from '../lib/binary';
import { extractIocs } from './ioc';
import type { Anomaly, ExtractedLink, Iocs, MacroReport, OleReport, VbaModule } from './types';
import { EMPTY_IOCS } from './types';
import { hashes, sniff } from './util';

const u16 = (b: Uint8Array, o: number) => (o + 2 <= b.length ? b[o]! | (b[o + 1]! << 8) : 0);
const u32 = (b: Uint8Array, o: number) => (o + 4 <= b.length ? (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0 : 0);

const END = 0xfffffffe;
const FREE = 0xffffffff;
const NOSTREAM = 0xffffffff;

interface DirEntry {
  name: string;
  type: number;
  left: number;
  right: number;
  child: number;
  start: number;
  size: number;
  path: string;
}

export interface Cfb {
  entries: DirEntry[];
  read(e: DirEntry): Uint8Array;
  find(path: string): DirEntry | undefined;
}

export const isOle = (b: Uint8Array) => b.length > 512 && b[0] === 0xd0 && b[1] === 0xcf && b[2] === 0x11 && b[3] === 0xe0 && b[4] === 0xa1 && b[5] === 0xb1 && b[6] === 0x1a && b[7] === 0xe1;

/** Reads an OLE2 / Compound File Binary container. Null if it is not one or is damaged beyond reading. */
export function parseCfb(b: Uint8Array): Cfb | null {
  if (!isOle(b) || b.length > 96 * 1024 * 1024) return null;
  const sectorShift = u16(b, 30);
  const miniShift = u16(b, 32);
  if (sectorShift < 7 || sectorShift > 16 || miniShift > 12) return null;
  const secSize = 1 << sectorShift;
  const miniSize = 1 << miniShift;
  const miniCutoff = u32(b, 56) || 4096;
  const sectorAt = (n: number) => b.subarray((n + 1) * secSize, (n + 2) * secSize);

  // FAT: sector ids come from the header's DIFAT, then from the DIFAT chain.
  const fatSectors: number[] = [];
  for (let i = 0; i < 109; i++) { const s = u32(b, 76 + i * 4); if (s !== FREE && s !== END) fatSectors.push(s); }
  let difat = u32(b, 68);
  for (let n = u32(b, 72), guard = 0; n > 0 && difat !== END && difat !== FREE && guard < 200; n--, guard++) {
    const sec = sectorAt(difat);
    for (let i = 0; i < secSize / 4 - 1; i++) { const s = u32(sec, i * 4); if (s !== FREE && s !== END) fatSectors.push(s); }
    difat = u32(sec, secSize - 4);
  }
  const fat: number[] = [];
  for (const s of fatSectors) {
    const sec = sectorAt(s);
    for (let i = 0; i < secSize / 4; i++) fat.push(u32(sec, i * 4));
    if (fat.length > 8_000_000) break;
  }
  const chain = (start: number, table: number[]): number[] => {
    const out: number[] = [];
    for (let s = start; s !== END && s !== FREE && s < table.length && out.length <= table.length; s = table[s]!) out.push(s);
    return out;
  };
  const readChain = (start: number) => {
    const secs = chain(start, fat);
    const out = new Uint8Array(secs.length * secSize);
    secs.forEach((s, i) => out.set(sectorAt(s), i * secSize));
    return out;
  };

  const dirBytes = readChain(u32(b, 48));
  const flat: DirEntry[] = [];
  for (let o = 0; o + 128 <= dirBytes.length && flat.length < 6000; o += 128) {
    const len = Math.min(u16(dirBytes, o + 64), 64);
    const nameBytes = dirBytes.subarray(o, o + Math.max(0, len - 2));
    const name = new TextDecoder('utf-16le').decode(nameBytes);
    flat.push({ name, type: dirBytes[o + 66]!, left: u32(dirBytes, o + 68), right: u32(dirBytes, o + 72), child: u32(dirBytes, o + 76), start: u32(dirBytes, o + 116), size: u32(dirBytes, o + 120), path: '' });
  }
  const root = flat[0];
  if (!root || root.type !== 5) return null;

  const visited = new Set<number>();
  const entries: DirEntry[] = [];
  const walk = (id: number, prefix: string) => {
    if (id === NOSTREAM || id >= flat.length || visited.has(id)) return;
    visited.add(id);
    const e = flat[id]!;
    walk(e.left, prefix);
    e.path = prefix + e.name;
    entries.push(e);
    if (e.type === 1) walk(e.child, `${e.path}/`);
    walk(e.right, prefix);
  };
  walk(root.child, '');

  let ministream: Uint8Array | null = null;
  let miniFat: number[] | null = null;
  const loadMini = () => {
    if (ministream) return;
    ministream = readChain(root.start);
    const mf = readChain(u32(b, 60));
    miniFat = [];
    for (let i = 0; i + 4 <= mf.length; i += 4) miniFat.push(u32(mf, i));
  };

  const read = (e: DirEntry): Uint8Array => {
    if (e.type !== 2) return new Uint8Array(0);
    if (e.size < miniCutoff) {
      loadMini();
      const secs = chain(e.start, miniFat!);
      const out = new Uint8Array(secs.length * miniSize);
      secs.forEach((s, i) => out.set(ministream!.subarray(s * miniSize, (s + 1) * miniSize), i * miniSize));
      return out.subarray(0, e.size);
    }
    return readChain(e.start).subarray(0, e.size);
  };
  return { entries, read, find: (p) => entries.find((e) => e.path.toLowerCase() === p.toLowerCase()) };
}

/* ------------------------------------------------------------- VBA source */

/** MS-OVBA "CompressedContainer" decompression. */
export function decompressVba(buf: Uint8Array): Uint8Array | null {
  if (buf[0] !== 1) return null;
  const out: number[] = [];
  let pos = 1;
  while (pos + 2 <= buf.length && out.length < 8 * 1024 * 1024) {
    const header = u16(buf, pos);
    const chunkEnd = Math.min(pos + (header & 0x0fff) + 3, buf.length);
    const compressed = (header >> 15) & 1;
    pos += 2;
    const chunkStart = out.length;
    if (!compressed) {
      for (let i = 0; i < 4096 && pos < buf.length; i++) out.push(buf[pos++]!);
      continue;
    }
    while (pos < chunkEnd) {
      const flags = buf[pos++]!;
      for (let bit = 0; bit < 8 && pos < chunkEnd; bit++) {
        if (((flags >> bit) & 1) === 0) { out.push(buf[pos++]!); continue; }
        const token = u16(buf, pos);
        pos += 2;
        const cur = out.length - chunkStart;
        const bitCount = Math.min(12, Math.max(Math.ceil(Math.log2(Math.max(cur, 1))), 4));
        const lengthMask = 0xffff >> bitCount;
        const length = (token & lengthMask) + 3;
        const offset = ((token & ~lengthMask & 0xffff) >> (16 - bitCount)) + 1;
        if (offset > out.length) return Uint8Array.from(out);
        for (let i = 0; i < length; i++) out.push(out[out.length - offset]!);
      }
    }
  }
  return Uint8Array.from(out);
}

const AUTOEXEC = ['AutoExec', 'AutoOpen', 'Auto_Open', 'AutoNew', 'AutoClose', 'Auto_Close', 'Document_Open', 'DocumentOpen', 'Document_New', 'Document_Close', 'Document_BeforeClose', 'Workbook_Open', 'Workbook_Activate', 'Workbook_BeforeClose', 'Worksheet_Calculate', 'Worksheet_Change', 'Auto_Activate', 'Auto_Deactivate'];
const SUSPICIOUS: [RegExp, string][] = [
  [/\bShell\s*[(\s"]/i, 'Shell (runs a program)'],
  [/WScript\.Shell|Wscript\.Shell/i, 'WScript.Shell (runs programs and scripts)'],
  [/\bCreateObject\s*\(/i, 'CreateObject (starts a Windows component)'],
  [/powershell/i, 'PowerShell'],
  [/\bcmd(\.exe)?\s*\/[ck]/i, 'cmd /c (command line)'],
  [/mshta|certutil|bitsadmin|regsvr32|rundll32/i, 'living-off-the-land program (mshta, certutil, bitsadmin, regsvr32 or rundll32)'],
  [/URLDownloadToFile/i, 'URLDownloadToFile (downloads a file)'],
  [/XMLHTTP|WinHttp\.WinHttpRequest|ServerXMLHTTP|MSXML2\./i, 'HTTP request (downloads data)'],
  [/ADODB\.Stream/i, 'ADODB.Stream (saves downloaded data to disk)'],
  [/Environ\s*\(/i, 'Environ (reads the temp folder or user name)'],
  [/\bOpen\b[^\n]{0,100}\bFor\s+(Output|Binary|Append)\b/i, 'writes a file'],
  [/Declare\s+(PtrSafe\s+)?(Function|Sub)/i, 'calls Windows functions directly'],
  [/VirtualAlloc|RtlMoveMemory|CreateThread|WriteProcessMemory|NtProtectVirtualMemory/i, 'allocates memory and starts threads (shellcode)'],
  [/GetObject\s*\(\s*"winmgmts/i, 'WMI (can start processes)'],
  [/Application\.Run\b|ExecuteExcel4Macro|\bEXEC\s*\(/i, 'runs code indirectly'],
  [/\bSendKeys\b/i, 'SendKeys'],
  [/MacScript|AppleScript/i, 'MacScript (Mac scripting)'],
  [/Application\.Visible\s*=\s*False|ScreenUpdating\s*=\s*False/i, 'hides what it is doing'],
  [/\bSleep\b|Application\.Wait/i, 'waits before acting (sandbox evasion)'],
];

export function analyzeVbaSource(name: string, kind: VbaModule['kind'], src: string): VbaModule {
  const autoExec = AUTOEXEC.filter((k) => new RegExp(`\\b${k}\\b`, 'i').test(src));
  const suspicious = SUSPICIOUS.filter(([re]) => re.test(src)).map(([, l]) => l);
  return { name, kind, length: src.length, preview: src.slice(0, 1200), autoExec, suspicious, truncated: src.length > 1200 };
}

const decodeCp = (b: Uint8Array) => new TextDecoder('windows-1252').decode(b);

interface DirModule { name: string; stream: string; offset: number; kind: VbaModule['kind'] }

function parseVbaDir(dir: Uint8Array): DirModule[] {
  const mods: DirModule[] = [];
  let cur: Partial<DirModule> | null = null;
  let pos = 0;
  for (let guard = 0; guard < 4000 && pos + 6 <= dir.length; guard++) {
    const id = u16(dir, pos);
    const size = u32(dir, pos + 2);
    pos += 6;
    if (size > dir.length - pos + 4) break;
    const data = dir.subarray(pos, pos + size);
    if (id === 0x0019) { cur = { name: decodeCp(data), kind: 'unknown' }; }
    else if (id === 0x001a && cur) cur.stream = decodeCp(data);
    else if (id === 0x0031 && cur) cur.offset = u32(data, 0);
    else if (id === 0x0021 && cur) cur.kind = 'standard';
    else if (id === 0x0022 && cur) cur.kind = 'class';
    else if (id === 0x002b && cur) {
      if (cur.name && cur.stream !== undefined) mods.push({ name: cur.name, stream: cur.stream, offset: cur.offset ?? 0, kind: cur.kind ?? 'unknown' });
      cur = null;
    }
    pos += size + (id === 0x0009 ? 2 : 0);
    if (id === 0x0010) break;
  }
  return mods;
}

export function emptyMacros(): MacroReport {
  return { present: false, modules: [], xlmSheets: [], autoExec: [], suspicious: [], obfuscation: { chrCalls: 0, longStrings: 0, base64Blobs: 0 } };
}

/** Reads every VBA module in an OLE container (a .doc, .xls or an OOXML vbaProject.bin). */
export function readVbaMacros(cfb: Cfb): { macros: MacroReport; sources: string[] } {
  const macros = emptyMacros();
  const sources: string[] = [];
  const dirs = cfb.entries.filter((e) => e.type === 2 && /(^|\/)VBA\/dir$/i.test(e.path));
  for (const d of dirs) {
    const base = d.path.slice(0, -3);
    const dirData = decompressVba(cfb.read(d));
    if (!dirData) continue;
    macros.present = true;
    for (const m of parseVbaDir(dirData).slice(0, 60)) {
      const stream = cfb.find(`${base}${m.stream}`);
      if (!stream) continue;
      const raw = cfb.read(stream);
      const text = decompressVba(raw.subarray(Math.min(m.offset, raw.length)));
      if (!text) continue;
      const src = decodeCp(text);
      sources.push(src);
      macros.modules.push(analyzeVbaSource(m.name, m.kind, src));
    }
  }
  if (!macros.present && cfb.entries.some((e) => /(^|\/)(_VBA_PROJECT|PROJECT)$/i.test(e.path) || /^Macros\//i.test(e.path) || /^_VBA_PROJECT_CUR\//i.test(e.path))) macros.present = true;
  const all = sources.join('\n');
  macros.autoExec = [...new Set(macros.modules.flatMap((m) => m.autoExec))];
  macros.suspicious = [...new Set(macros.modules.flatMap((m) => m.suspicious))];
  macros.obfuscation = {
    chrCalls: (all.match(/\bChr[BW$]?\s*\(/gi) ?? []).length,
    longStrings: (all.match(/"[^"\n]{200,}"/g) ?? []).length,
    base64Blobs: (all.match(/[A-Za-z0-9+/]{80,}={0,2}/g) ?? []).length,
  };
  return { macros, sources };
}

/* ----------------------------------------------------- Excel 4.0 sheets */

function xlmSheets(cfb: Cfb): MacroReport['xlmSheets'] {
  const wb = cfb.find('Workbook') ?? cfb.find('Book');
  if (!wb) return [];
  const b = cfb.read(wb);
  const out: MacroReport['xlmSheets'] = [];
  for (let pos = 0, guard = 0; pos + 4 <= b.length && guard < 20_000; guard++) {
    const id = u16(b, pos);
    const len = u16(b, pos + 2);
    const d = b.subarray(pos + 4, pos + 4 + len);
    if (id === 0x0085 && d.length > 8) {
      const state = d[4]!, type = d[5]!, cch = d[6]!, wide = d[7]! & 1;
      if (type === 1) {
        const name = wide ? new TextDecoder('utf-16le').decode(d.subarray(8, 8 + cch * 2)) : latin1(d.subarray(8, 8 + cch));
        out.push({ name, hidden: state === 2 ? 'very-hidden' : state === 1 ? 'hidden' : 'visible' });
      }
    }
    if (id === 0x000a && pos > 0) break;
    pos += 4 + len;
  }
  return out;
}

/* ------------------------------------------------------- metadata & more */

const FILETIME_EPOCH = 11644473600000;

function propertySet(b: Uint8Array, names: Record<number, string>): Record<string, string> {
  const out: Record<string, string> = {};
  if (b.length < 48) return out;
  const sec = u32(b, 44);
  const count = Math.min(u32(b, sec + 4), 60);
  for (let i = 0; i < count; i++) {
    const id = u32(b, sec + 8 + i * 8);
    const off = sec + u32(b, sec + 12 + i * 8);
    const type = u16(b, off);
    const name = names[id];
    if (!name) continue;
    if (type === 0x1e) { const n = u32(b, off + 4); const v = decodeCp(b.subarray(off + 8, off + 8 + Math.max(0, n - 1))); if (v.trim()) out[name] = v.replace(/[^\x20-\x7e]/g, '').slice(0, 200); }
    else if (type === 0x1f) { const n = u32(b, off + 4); const v = new TextDecoder('utf-16le').decode(b.subarray(off + 8, off + 8 + Math.max(0, n * 2 - 2))); if (v.trim()) out[name] = v.replace(/[^\x20-\x7e]/g, '').slice(0, 200); }
    else if (type === 0x40) {
      const t = (u32(b, off + 8) * 2 ** 32 + u32(b, off + 4)) / 10000 - FILETIME_EPOCH;
      if (t > 0 && t < 4e12) out[name] = new Date(t).toISOString().slice(0, 19).replace('T', ' ');
    }
  }
  return out;
}

const SUMMARY_NAMES = { 2: 'Title', 3: 'Subject', 4: 'Author', 5: 'Keywords', 6: 'Comments', 7: 'Template', 8: 'LastAuthor', 9: 'Revision', 12: 'Created', 13: 'LastSaved', 18: 'Application' };
const DOCSUM_NAMES = { 14: 'Manager', 15: 'Company' };

/** The Ole10Native stream: a file embedded in an OLE object (a program dropped by a document). */
function readOle10Native(b: Uint8Array): { name: string; data: Uint8Array } | null {
  if (b.length < 20) return null;
  let p = 6;
  const z = () => { const s = p; while (p < b.length && b[p] !== 0) p++; const v = latin1(b.subarray(s, p)); p++; return v; };
  const label = z();
  z();
  p += 4;
  const tmp = u32(b, p);
  p += 4 + tmp;
  const n = u32(b, p);
  p += 4;
  if (n <= 0 || p + n > b.length) return b.length > 100 ? { name: label || 'embedded', data: b.subarray(Math.min(b.length, 20)) } : null;
  return { name: label || 'embedded', data: b.subarray(p, p + n) };
}

export interface OleAnalysis {
  report: OleReport;
  anomalies: Anomaly[];
  links: ExtractedLink[];
  iocs: Iocs;
  embeddedFiles: { name: string; bytes: Uint8Array }[];
}

export async function analyzeOle(bytes: Uint8Array): Promise<OleAnalysis> {
  const anomalies: Anomaly[] = [];
  const add = (a: Anomaly) => { if (!anomalies.some((x) => x.id === a.id)) anomalies.push(a); };
  const cfb = parseCfb(bytes);
  const links: ExtractedLink[] = [];
  const embedded: OleReport['embedded'] = [];
  const embeddedFiles: { name: string; bytes: Uint8Array }[] = [];
  const text = latin1(bytes, 8_000_000).replace(/\0/g, '');
  let iocs = extractIocs(text.slice(0, 4_000_000), { decode: false }).iocs;

  if (!cfb) {
    // Damaged or oddly built container: fall back to a byte search like the old checks did.
    const macros = emptyMacros();
    macros.present = /_VBA_PROJECT|VBA\b.{0,40}(ThisDocument|ThisWorkbook|Module1)|Attribute VB_Name/.test(text);
    if (macros.present) add({ id: 'office-macros', severity: 'high', title: 'Contains macros (code that can run when you click "Enable content")', plain: 'This document contains program code that runs if you click "Enable content".', attack: 'T1204.002' });
    add({ id: 'ole-unreadable', severity: 'low', title: 'The Office container could not be read', plain: 'The file claims to be an Office document but its structure is damaged. Malware makers sometimes do this to escape scanners.' });
    for (const u of iocs.urls.slice(0, 100)) links.push({ url: u, where: 'text inside the file', how: 'text' });
    return { report: { streams: [], metadata: {}, macros, embedded, riskyClasses: [] }, anomalies, links, iocs, embeddedFiles };
  }

  const streams = cfb.entries.filter((e) => e.type === 2).map((e) => ({ path: e.path, size: e.size }));
  const metadata: Record<string, string> = {};
  const sumInfo = cfb.find('\x05SummaryInformation');
  if (sumInfo) Object.assign(metadata, propertySet(cfb.read(sumInfo), SUMMARY_NAMES));
  const docSum = cfb.find('\x05DocumentSummaryInformation');
  if (docSum) Object.assign(metadata, propertySet(cfb.read(docSum), DOCSUM_NAMES));

  const { macros, sources } = readVbaMacros(cfb);
  macros.xlmSheets = xlmSheets(cfb);
  macros.present = macros.present || macros.xlmSheets.length > 0;

  const riskyClasses: string[] = [];
  for (const e of cfb.entries) {
    if (e.type !== 2) continue;
    if (/Equation Native/i.test(e.path)) riskyClasses.push('Microsoft Equation Editor object (exploited by CVE-2017-11882 and similar)');
    if (/\x01Ole10Native$/i.test(e.path)) {
      const o = readOle10Native(cfb.read(e));
      if (o) {
        const t = sniff(o.data).label;
        embedded.push({ name: o.name, source: 'Ole10Native', size: o.data.length, type: t, sha256: (await hashes(o.data)).sha256 });
        if (embeddedFiles.length < 8) embeddedFiles.push({ name: o.name, bytes: o.data });
      }
    }
    if (/\x01CompObj$/i.test(e.path)) {
      const t = latin1(cfb.read(e)).replace(/\0/g, '');
      if (/Equation\.3|Equation\.DSMT/i.test(t)) riskyClasses.push('Microsoft Equation Editor object (exploited by CVE-2017-11882 and similar)');
      if (/Package\b/.test(t)) riskyClasses.push('Packager object (an attached file that can run)');
      if (/ShockwaveFlash|htmlfile|Forms\.|MSComctl|Scripting\./i.test(t)) riskyClasses.push(`Active component: ${t.match(/ShockwaveFlash[\w.]*|htmlfile|Forms\.[\w.]+|MSComctl[\w.]+|Scripting\.[\w.]+/i)?.[0] ?? 'ActiveX'}`);
    }
  }

  const srcText = sources.join('\n');
  const srcIocs = extractIocs(srcText, { decode: true });
  iocs = { ...EMPTY_IOCS(), ...iocs };
  for (const u of srcIocs.iocs.urls) links.push({ url: u, where: 'macro code', how: 'macro' });
  for (const d of srcIocs.decoded) if (/program|text/.test(d.label)) add({ id: 'ole-base64', severity: d.label.includes('program') ? 'critical' : 'medium', title: `Macro hides ${d.label} in base64`, detail: d.preview, plain: 'The macro contains an encoded block that decodes to something hidden.', attack: 'T1027' });
  iocs.urls = [...new Set([...iocs.urls, ...srcIocs.iocs.urls])];
  iocs.commands = [...new Set([...iocs.commands, ...srcIocs.iocs.commands])];
  iocs.executables = [...new Set([...iocs.executables, ...srcIocs.iocs.executables])];
  for (const u of iocs.urls.slice(0, 100)) if (!links.some((l) => l.url === u)) links.push({ url: u, where: 'text inside the file', how: 'text' });

  if (macros.present) {
    const auto = macros.autoExec.length > 0;
    const risky = macros.suspicious.length > 0;
    add({
      id: 'office-macros',
      severity: auto && risky ? 'critical' : 'high',
      title: `Contains macros${auto ? ' that run automatically' : ''}`,
      detail: [auto ? `auto-run: ${macros.autoExec.join(', ')}` : '', risky ? `uses: ${macros.suspicious.slice(0, 5).join('; ')}` : ''].filter(Boolean).join(' · ') || undefined,
      plain: auto ? 'This document has a macro set to start the moment you enable content, and it uses features malware relies on.' : 'This document contains macros (code that can run when you click "Enable content").',
      attack: 'T1204.002',
    });
  }
  if (macros.xlmSheets.length) add({ id: 'ole-xlm', severity: 'high', title: `Excel 4.0 macro sheet${macros.xlmSheets.length > 1 ? 's' : ''}: ${macros.xlmSheets.map((s) => `${s.name}${s.hidden !== 'visible' ? ` (${s.hidden})` : ''}`).join(', ')}`, plain: 'This spreadsheet contains old-style Excel 4.0 macros. Many scanners do not read them, so malware authors favour them.', attack: 'T1059' });
  if (macros.obfuscation.chrCalls > 30 || macros.obfuscation.longStrings > 0 || macros.obfuscation.base64Blobs > 0) add({ id: 'ole-macro-obfuscated', severity: 'high', title: 'Macro code is obfuscated', detail: `Chr() calls: ${macros.obfuscation.chrCalls}, very long strings: ${macros.obfuscation.longStrings}, base64-like blobs: ${macros.obfuscation.base64Blobs}`, plain: 'The macro code is deliberately scrambled so people and scanners cannot read it.', attack: 'T1027' });
  for (const rc of [...new Set(riskyClasses)]) add({ id: `ole-class-${rc.slice(0, 12).replace(/\W/g, '').toLowerCase()}`, severity: /Equation/.test(rc) ? 'critical' : 'high', title: rc, plain: /Equation/.test(rc) ? 'This document contains an object type that attackers have used to run code without any click.' : 'This document contains an embedded object that can run code.', attack: 'T1203' });
  if (embedded.length) add({ id: 'ole-embedded', severity: embedded.some((e) => /program|script/i.test(e.type)) ? 'critical' : 'high', title: `Embedded file${embedded.length > 1 ? 's' : ''}: ${embedded.map((e) => `${e.name} (${e.type})`).join(', ')}`, plain: 'A file is hidden inside this document and can run if you double-click its icon.', attack: 'T1027.009' });

  return { report: { streams: streams.slice(0, 200), metadata, macros, embedded, riskyClasses: [...new Set(riskyClasses)] }, anomalies, links, iocs, embeddedFiles };
}
