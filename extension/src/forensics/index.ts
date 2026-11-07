/**
 * File forensics: look inside any attachment without opening or running it,
 * and without ever sending it anywhere. Hashes are computed locally; only a
 * hash is ever used for online lookups.
 *
 * The PDF, OLE, RTF and Office readers are clean TypeScript rewrites inspired
 * by Didier Stevens' pdfid.py, pdf-parser.py, oledump.py, rtfdump.py and
 * zipdump.py (https://github.com/DidierStevens/DidierStevensSuite).
 */
import { isZip, latin1, zipEntries, zipRead } from '../lib/binary';
import { extractIocs, mergeIocs } from './ioc';
import { analyzeOle } from './ole';
import { analyzeOoxml } from './ooxml';
import { analyzePdf, dedupeLinks } from './pdf';
import { analyzeRtf } from './rtf';
import type { Anomaly, ChildFile, ExtractedLink, FileForensics, FileKind, Iocs, ZipReport } from './types';
import { EMPTY_IOCS } from './types';
import { entropy, extensionMismatch, hashes, sniff } from './util';
import type { Severity } from '../core/types';

export * from './types';
export { extractIocs, mergeIocs } from './ioc';
export { analyzePdf } from './pdf';
export { analyzeOle, decompressVba, parseCfb } from './ole';
export { analyzeOoxml } from './ooxml';
export { analyzeRtf } from './rtf';

const RANK: Record<Severity, number> = { good: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };
const NOISE_HOSTS = /^https?:\/\/(?:[^/]*\.)?(?:w3\.org|openxmlformats\.org|schemas\.microsoft\.com|purl\.org|ns\.adobe\.com|xmlsoft\.org|schemas\.xmlsoap\.org)(?:[/:]|$)/i;
const MAX_DEPTH = 2;
const MAX_CHILDREN = 12;
const MAX_CHILD_BYTES = 24 * 1024 * 1024;

interface Budget {
  children: number;
  bytes: number;
}

const ext = (name: string) => {
  const n = name.replace(/[‪-‮⁦-⁩‎‏]/g, '').toLowerCase();
  const dot = n.lastIndexOf('.');
  return dot >= 0 ? n.slice(dot + 1) : '';
};

/** Windows PE header facts: bitness, sections, compile time, .NET. */
function peFacts(b: Uint8Array): string {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  if (b.length < 0x100) return '';
  const pe = dv.getUint32(0x3c, true);
  if (pe + 0x78 > b.length || dv.getUint32(pe, true) !== 0x4550) return '';
  const machine = dv.getUint16(pe + 4, true);
  const sections = dv.getUint16(pe + 6, true);
  const stamp = dv.getUint32(pe + 8, true);
  const chars = dv.getUint16(pe + 22, true);
  const magic = dv.getUint16(pe + 24, true);
  const dirBase = pe + 24 + (magic === 0x20b ? 112 : 96);
  const clr = dirBase + 14 * 8 + 4 <= b.length ? dv.getUint32(dirBase + 14 * 8 + 4, true) : 0;
  const when = stamp > 0 && stamp < 4e9 ? new Date(stamp * 1000).toISOString().slice(0, 10) : 'unknown';
  return [machine === 0x8664 ? '64-bit' : machine === 0x14c ? '32-bit' : `machine 0x${machine.toString(16)}`, chars & 0x2000 ? 'DLL' : 'EXE', `${sections} sections`, clr ? '.NET' : 'native code', `built ${when}`].join(', ');
}

export async function analyzeFile(bytes: Uint8Array, filename = '', depth = 0, budget: Budget = { children: 0, bytes: 0 }): Promise<FileForensics> {
  const magic = sniff(bytes);
  let magicLabel = magic.label;
  const name = filename.toLowerCase();
  const anomalies: Anomaly[] = [];
  const add = (a: Anomaly) => { if (!anomalies.some((x) => x.id === a.id)) anomalies.push(a); };
  let links: ExtractedLink[] = [];
  let iocs: Iocs = EMPTY_IOCS();
  const children: ChildFile[] = [];
  let kind: FileKind = 'other';
  let truncated = false;
  const out: Partial<FileForensics> = {};
  let embedded: { name: string; bytes: Uint8Array }[] = [];

  const mismatch = extensionMismatch(ext(name), magic);
  if (mismatch) add({ id: 'type-mismatch', severity: 'high', title: mismatch, plain: 'The file is not what its name says it is. Attackers rename files so they look harmless.', attack: 'T1036.008' });

  if (magic.kind === 'pdf') {
    kind = 'pdf';
    const r = await analyzePdf(bytes);
    out.pdf = r.report;
    anomalies.push(...r.anomalies);
    links = r.links;
    iocs = r.iocs;
    embedded = r.embeddedFiles;
    truncated = r.truncated;
  } else if (magic.kind === 'ole') {
    kind = 'ole';
    const r = await analyzeOle(bytes);
    out.ole = r.report;
    for (const a of r.anomalies) add(a);
    links = r.links;
    iocs = r.iocs;
    embedded = r.embeddedFiles;
  } else if (magic.kind === 'rtf') {
    kind = 'rtf';
    const r = analyzeRtf(bytes);
    out.rtf = r.report;
    for (const a of r.anomalies) add(a);
    links = r.links;
    iocs = r.iocs;
    embedded = r.embeddedFiles;
  } else if (magic.kind === 'zip' || isZip(bytes)) {
    const list = zipEntries(bytes, 5000);
    if (list.some((e) => e.name === '[Content_Types].xml')) {
      kind = 'ooxml';
      const r = await analyzeOoxml(bytes);
      const app = { word: 'Word', excel: 'Excel', powerpoint: 'PowerPoint', unknown: 'Office' }[r.report.app];
      magicLabel = `${app} document (Office Open XML${r.report.macros.present ? ', with macros' : ''})`;
      out.ooxml = r.report;
      for (const a of r.anomalies) add(a);
      links = r.links;
      iocs = r.iocs;
      embedded = r.embeddedFiles;
    } else {
      kind = 'zip';
      const files: ZipReport['files'] = [];
      for (const e of list.filter((x) => !x.name.endsWith('/')).slice(0, 200)) {
        let type: string | undefined;
        if (!e.encrypted && e.size <= MAX_CHILD_BYTES && files.length < 60) {
          const head = await zipRead(bytes, e, 4096);
          if (head) type = sniff(head).label;
        }
        files.push({ name: e.name, size: e.size, compressed: e.compressedSize, encrypted: e.encrypted, type });
      }
      out.zip = { files };
      // Look inside documents and programs in the archive the same way.
      for (const e of list.filter((x) => !x.encrypted && !x.name.endsWith('/') && /\.(pdf|docx?|docm|xlsx?|xlsm|pptx?|pptm|rtf|html?|svg|lnk|exe|dll|js|vbs|hta|ps1|iso|img|one)$/i.test(x.name)).slice(0, 8)) {
        const data = await zipRead(bytes, e, 8 * 1024 * 1024);
        if (data) embedded.push({ name: e.name, bytes: data });
      }
    }
  } else if (magic.kind === 'executable') {
    kind = 'executable';
    add({ id: 'program-content', severity: 'critical', title: `This file is a program: ${magic.label}`, detail: peFacts(bytes) || undefined, plain: 'Whatever it is named, this file is a program. Opening it can run code on your computer.', attack: 'T1204.002' });
    const found = extractIocs(latin1(bytes, 2_000_000), { decode: false });
    iocs = { ...found.iocs, urls: found.iocs.urls.slice(0, 50) };
  } else if (magic.kind === 'shortcut') {
    kind = 'shortcut';
    const text = `${latin1(bytes, 200_000)}\n${new TextDecoder('utf-16le').decode(bytes.subarray(0, Math.min(bytes.length, 200_000)))}`.replace(/\0/g, '');
    const found = extractIocs(text, { decode: true });
    iocs = found.iocs;
    add({ id: 'lnk-file', severity: 'critical', title: 'Windows shortcut file (.lnk)', detail: found.iocs.commands[0] ?? found.iocs.executables[0], plain: 'A shortcut can run any command when double-clicked, such as downloading and starting malware.', attack: 'T1204.002' });
    for (const u of found.iocs.urls) links.push({ url: u, where: 'shortcut target', how: 'action' });
  } else if (magic.kind === 'html' || magic.kind === 'script' || magic.kind === 'other') {
    kind = magic.kind === 'html' ? 'html' : magic.kind === 'script' ? 'script' : 'other';
    const text = latin1(bytes, 3_000_000);
    if (kind === 'html' || kind === 'script' || (kind === 'other' && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(text.slice(0, 2000)))) {
      const found = extractIocs(text, { decode: true });
      iocs = found.iocs;
      if (found.iocs.commands.length && kind === 'script') add({ id: 'script-commands', severity: 'high', title: 'Script runs system commands', detail: found.iocs.commands[0], plain: 'This script starts programs or downloads data.' });
      for (const d of found.decoded.filter((x) => /program/.test(x.label))) add({ id: 'script-hidden-program', severity: 'critical', title: `Hides a ${d.label} in base64`, plain: 'A program is hidden inside encoded text.', attack: 'T1027' });
    }
  } else if (magic.kind === 'archive') {
    kind = 'zip';
    add({ id: 'archive-unreadable', severity: 'low', title: `${magic.label}: contents cannot be listed`, plain: 'Unmask can read ZIP files, but not this archive type, so what is inside is unchecked.' });
  } else if (magic.kind === 'image') kind = 'image';

  // Files inside this one get the same treatment, a couple of levels deep.
  if (depth < MAX_DEPTH) {
    for (const f of embedded) {
      if (budget.children >= MAX_CHILDREN || budget.bytes + f.bytes.length > MAX_CHILD_BYTES * 2) break;
      budget.children++;
      budget.bytes += f.bytes.length;
      children.push({ path: f.name, forensics: await analyzeFile(f.bytes, f.name, depth + 1, budget) });
    }
  }
  // What was found inside matters as much as the wrapper: bubble the worst up.
  for (const c of children) {
    for (const a of c.forensics.anomalies.filter((x) => RANK[x.severity] >= RANK.medium).slice(0, 3)) add({ id: `in:${c.path}:${a.id}`, severity: a.severity, title: `Inside ${c.path}: ${a.title}`, detail: a.detail, plain: a.plain, where: c.path, attack: a.attack });
    links.push(...c.forensics.links.map((l) => ({ ...l, where: `${c.path} → ${l.where}` })));
    iocs = mergeIocs(iocs, c.forensics.iocs);
  }

  const e = entropy(bytes);
  if (e >= 7.5 && bytes.length > 20_000 && (kind === 'other' || kind === 'executable' || kind === 'script')) add({ id: 'high-entropy', severity: 'medium', title: `Looks packed or encrypted (entropy ${e}/8)`, plain: 'The data is nearly random, which is typical of encrypted or packed payloads that hide what they are.', attack: 'T1027.002' });

  links = dedupeLinks(links.filter((l) => !(l.how === 'text' && NOISE_HOSTS.test(l.url))));
  iocs = { ...iocs, urls: [...new Set([...iocs.urls, ...links.map((l) => l.url)])].filter((u) => !NOISE_HOSTS.test(u)).slice(0, 300) };

  return {
    kind,
    magic: { label: magicLabel, mime: magic.mime },
    size: bytes.length,
    entropy: e,
    hashes: await hashes(bytes),
    anomalies: anomalies.sort((a, b) => RANK[b.severity] - RANK[a.severity]),
    links,
    iocs,
    children,
    truncated,
    ...out,
  };
}

/** The highest severity among a file's anomalies. */
export function worstSeverity(f: FileForensics): Severity {
  return f.anomalies.reduce<Severity>((w, a) => (RANK[a.severity] > RANK[w] ? a.severity : w), 'good');
}
