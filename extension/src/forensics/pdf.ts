/**
 * PDF forensics. Two ideas from Didier Stevens' tools, rewritten for the
 * browser (no code is copied):
 *   - pdfid.py: count the keywords that matter (/JavaScript, /OpenAction,
 *     /Launch, /EmbeddedFile …), note which were written with #xx escapes to
 *     dodge scanners, and measure entropy, %%EOF markers and trailing data.
 *   - pdf-parser.py: walk the objects, unpack compressed object streams,
 *     decode stream filters and follow the actions that matter.
 * Nothing is rendered or executed; the file is only read as bytes.
 */
import { latin1 } from '../lib/binary';
import { extractIocs } from './ioc';
import { EMPTY_IOCS, type Anomaly, type ExtractedLink, type Iocs, type PdfAction, type PdfEmbedded, type PdfIdRow, type PdfJavaScript, type PdfReport } from './types';
import { applyPdfFilters, entropy, hashes, sniff } from './util';

export const PDF_READ_LIMIT = 16 * 1024 * 1024;

interface Obj {
  num: number;
  gen: number;
  /** Everything between "obj" and "endobj", minus the stream data. */
  dict: string;
  /** Stream bytes, when the object has a stream. */
  stream?: Uint8Array;
  /** Set for objects that live inside an object stream. */
  inStream?: number;
}

const KEYWORDS: { key: string; note: string; risk: PdfIdRow['risk'] }[] = [
  { key: 'obj', note: 'Objects in the file.', risk: 'normal' },
  { key: 'endobj', note: 'Should match the number of objects.', risk: 'normal' },
  { key: 'stream', note: 'Data blocks (pages, images, fonts).', risk: 'normal' },
  { key: 'endstream', note: 'Should match the number of streams.', risk: 'normal' },
  { key: 'xref', note: 'Cross-reference tables. Several mean the file was edited and re-saved.', risk: 'normal' },
  { key: 'trailer', note: 'Trailer sections.', risk: 'normal' },
  { key: 'startxref', note: 'Where the cross-reference table starts.', risk: 'normal' },
  { key: '/Page', note: 'Number of pages.', risk: 'normal' },
  { key: '/Encrypt', note: 'The file is password-protected or scrambled, so scanners cannot read inside it.', risk: 'watch' },
  { key: '/ObjStm', note: 'Compressed object streams. Keywords can hide inside, so Unmask unpacks them.', risk: 'watch' },
  { key: '/JS', note: 'JavaScript code. Ordinary documents and invoices almost never need it.', risk: 'danger' },
  { key: '/JavaScript', note: 'JavaScript action. Ordinary documents and invoices almost never need it.', risk: 'danger' },
  { key: '/AA', note: 'Additional actions: code that runs on events such as opening a page.', risk: 'danger' },
  { key: '/OpenAction', note: 'Something runs automatically the moment the file is opened.', risk: 'danger' },
  { key: '/AcroForm', note: 'Fillable form. Phishing PDFs sometimes pose as a form.', risk: 'watch' },
  { key: '/JBIG2Decode', note: 'An image format with a history of reader exploits.', risk: 'danger' },
  { key: '/RichMedia', note: 'Embedded Flash or video. Not used in ordinary documents.', risk: 'danger' },
  { key: '/Launch', note: 'Tries to start a program.', risk: 'danger' },
  { key: '/EmbeddedFile', note: 'A file is hidden inside the PDF.', risk: 'danger' },
  { key: '/XFA', note: 'XML form (a large attack surface in old readers).', risk: 'danger' },
  { key: '/URI', note: 'Clickable web links.', risk: 'watch' },
];

const TOKEN_RE = /(\/[^\s/[\]<>(){}%]*)|\b(obj|endobj|stream|endstream|xref|trailer|startxref)\b/g;

const unescapeName = (name: string): { value: string; obfuscated: boolean } => {
  if (!name.includes('#')) return { value: name, obfuscated: false };
  return { value: name.replace(/#([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16))), obfuscated: true };
};

function countKeywords(text: string): Map<string, { count: number; obf: number }> {
  const wanted = new Set(KEYWORDS.map((k) => k.key));
  const out = new Map<string, { count: number; obf: number }>();
  for (const k of wanted) out.set(k, { count: 0, obf: 0 });
  for (const m of text.matchAll(TOKEN_RE)) {
    let key = m[2] ?? '';
    let obf = false;
    if (m[1]) {
      const n = unescapeName(m[1]);
      key = n.value;
      obf = n.obfuscated;
    }
    const row = out.get(key);
    if (!row) continue;
    row.count++;
    if (obf) row.obf++;
  }
  return out;
}

/* ------------------------------------------------------------ PDF syntax */

/** Reads a PDF literal or hex string starting at s[i] ('(' or '<'). */
function readString(s: string, i: number): { value: string; end: number } | null {
  if (s[i] === '(') {
    let depth = 0;
    let out = '';
    for (let j = i; j < s.length && j < i + 200_000; j++) {
      const c = s[j]!;
      if (c === '\\') {
        const n = s[j + 1] ?? '';
        j++;
        if (/[0-7]/.test(n)) {
          let oct = n;
          while (oct.length < 3 && /[0-7]/.test(s[j + 1] ?? '')) oct += s[++j];
          out += String.fromCharCode(parseInt(oct, 8) & 255);
        } else out += ({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' } as Record<string, string>)[n] ?? n;
        continue;
      }
      if (c === '(') {
        if (depth++ > 0) out += c;
        continue;
      }
      if (c === ')') {
        if (--depth === 0) return { value: out, end: j + 1 };
        out += c;
        continue;
      }
      out += c;
    }
    return null;
  }
  if (s[i] === '<' && s[i + 1] !== '<') {
    const close = s.indexOf('>', i);
    if (close < 0) return null;
    const h = s.slice(i + 1, close).replace(/[^0-9a-fA-F]/g, '');
    let out = '';
    for (let j = 0; j < h.length; j += 2) out += String.fromCharCode(parseInt(h.slice(j, j + 2).padEnd(2, '0'), 16));
    return { value: out, end: close + 1 };
  }
  return null;
}

/** Text strings may be UTF-16BE with a byte-order mark. */
function textString(v: string): string {
  if (v.startsWith('\xfe\xff')) {
    let o = '';
    for (let i = 2; i + 1 < v.length; i += 2) o += String.fromCharCode((v.charCodeAt(i) << 8) | v.charCodeAt(i + 1));
    return o;
  }
  return v;
}

/** Returns the raw text of one PDF value starting at s[i]: dict, array, string, name, ref or number. */
function readValue(s: string, start: number): { raw: string; end: number } | null {
  let i = start;
  while (i < s.length && /\s/.test(s[i]!)) i++;
  if (i >= s.length) return null;
  const c = s[i]!;
  if (c === '<' && s[i + 1] === '<') {
    let depth = 0;
    for (let j = i; j < s.length - 1; j++) {
      if (s[j] === '<' && s[j + 1] === '<') { depth++; j++; }
      else if (s[j] === '>' && s[j + 1] === '>') { if (--depth === 0) return { raw: s.slice(i, j + 2), end: j + 2 }; j++; }
      else if (s[j] === '(') { const str = readString(s, j); if (str) j = str.end - 1; }
    }
    return { raw: s.slice(i), end: s.length };
  }
  if (c === '[') {
    let depth = 0;
    for (let j = i; j < s.length; j++) {
      if (s[j] === '[') depth++;
      else if (s[j] === ']') { if (--depth === 0) return { raw: s.slice(i, j + 1), end: j + 1 }; }
      else if (s[j] === '(') { const str = readString(s, j); if (str) j = str.end - 1; }
    }
    return { raw: s.slice(i), end: s.length };
  }
  if (c === '(' || c === '<') {
    const str = readString(s, i);
    return str ? { raw: s.slice(i, str.end), end: str.end } : null;
  }
  const ref = s.slice(i, i + 40).match(/^\d+\s+\d+\s+R\b/);
  if (ref) return { raw: ref[0], end: i + ref[0].length };
  const tok = s.slice(i, i + 400).match(/^\/?[^\s/[\]<>(){}%]*/);
  return tok ? { raw: tok[0], end: i + tok[0].length } : null;
}

/**
 * The raw value of `/Key` in a dictionary, or null. Walks the dictionary key
 * by key, so a name that is a *value* (as in `/S /URI /URI (…)`) is never
 * mistaken for the key. Key names are compared after #xx unescaping.
 */
function getKey(dict: string, key: string): string | null {
  let i = dict.indexOf('<<');
  if (i < 0) return null;
  i += 2;
  const want = key.replace(/^\//, '');
  for (let guard = 0; guard < 2000; guard++) {
    while (i < dict.length && /\s/.test(dict[i]!)) i++;
    if (i >= dict.length || (dict[i] === '>' && dict[i + 1] === '>')) return null;
    const name = dict.slice(i, i + 200).match(/^\/[^\s/[\]<>(){}%]*/);
    if (!name) return null;
    i += name[0].length;
    const v = readValue(dict, i);
    if (!v) return null;
    if (unescapeName(name[0].slice(1)).value === want) return v.raw || null;
    i = v.end;
  }
  return null;
}

const refNum = (raw: string | null): number | null => {
  const m = raw?.match(/^(\d+)\s+\d+\s+R\b/);
  return m ? Number(m[1]) : null;
};

/* ------------------------------------------------------------ the parser */

interface Parsed {
  objs: Map<number, Obj>;
  trailerText: string;
}

async function parseObjects(bytes: Uint8Array, text: string): Promise<{ parsed: Parsed; unpacked: number; decoded: Map<number, Uint8Array>; hiddenText: string }> {
  const objs = new Map<number, Obj>();
  const re = /(?<![0-9])(\d{1,9})\s+(\d{1,5})\s+obj\b/g;
  const starts: { num: number; gen: number; at: number; bodyStart: number }[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) && starts.length < 30_000) starts.push({ num: Number(m[1]), gen: Number(m[2]), at: m.index, bodyStart: m.index + m[0].length });
  for (let i = 0; i < starts.length; i++) {
    const s = starts[i]!;
    const next = starts[i + 1]?.at ?? text.length;
    let end = text.indexOf('endobj', s.bodyStart);
    if (end < 0 || end > next) end = next;
    const body = text.slice(s.bodyStart, end);
    const sm = body.match(/>>\s*stream\r?\n|>>\s*stream\r(?!\n)/);
    if (!sm || sm.index === undefined) {
      objs.set(s.num, { num: s.num, gen: s.gen, dict: body });
      continue;
    }
    const dict = body.slice(0, sm.index + 2);
    const dataStart = s.bodyStart + sm.index + sm[0].length;
    let dataEnd = text.indexOf('endstream', dataStart);
    const len = Number(getKey(dict, 'Length')?.match(/^\d+$/)?.[0] ?? NaN);
    if (Number.isFinite(len) && dataStart + len <= end + 12 && text.startsWith('endstream', dataStart + len + (text[dataStart + len] === '\r' ? 2 : text[dataStart + len] === '\n' ? 1 : 0))) dataEnd = dataStart + len;
    if (dataEnd < 0) dataEnd = end;
    objs.set(s.num, { num: s.num, gen: s.gen, dict, stream: bytes.subarray(dataStart, dataEnd) });
  }

  const encrypted = /\/Encrypt\b/.test(text);
  const decoded = new Map<number, Uint8Array>();
  let budget = 24 * 1024 * 1024;
  let unpacked = 0;
  let hiddenText = '';
  for (const o of objs.values()) {
    if (!o.stream || encrypted || budget <= 0 || decoded.size >= 800) continue;
    if (/\/Subtype\s*\/Image\b|\/DCTDecode|\/JPXDecode|\/CCITTFaxDecode|\/JBIG2Decode/.test(o.dict)) continue;
    const filt = getKey(o.dict, 'Filter');
    const filters = filt ? [...filt.matchAll(/\/[A-Za-z0-9]+/g)].map((x) => x[0]) : [];
    const data = filters.length ? await applyPdfFilters(o.stream, filters, 4 * 1024 * 1024) : o.stream.subarray(0, 4 * 1024 * 1024);
    if (!data) continue;
    decoded.set(o.num, data);
    budget -= data.length;
  }

  // Unpack object streams: that is where keywords hide from simple scanners.
  for (const o of [...objs.values()]) {
    if (!/\/Type\s*\/ObjStm\b/.test(o.dict) || !decoded.has(o.num)) continue;
    const data = latin1(decoded.get(o.num)!, 4 * 1024 * 1024);
    const n = Number(getKey(o.dict, 'N') ?? 0);
    const first = Number(getKey(o.dict, 'First') ?? 0);
    if (!n || !first || n > 5000) continue;
    const pairs = [...data.slice(0, first).matchAll(/(\d+)\s+(\d+)/g)].slice(0, n).map((p) => ({ num: Number(p[1]), off: Number(p[2]) }));
    unpacked++;
    pairs.forEach((p, i) => {
      const body = data.slice(first + p.off, first + (pairs[i + 1]?.off ?? data.length - first));
      if (!objs.has(p.num)) objs.set(p.num, { num: p.num, gen: 0, dict: body, inStream: o.num });
      hiddenText += `${body}\n`;
    });
  }

  const trailerText = [...text.matchAll(/trailer\s*(<<[\s\S]{0,2000}?>>)/g)].map((t) => t[1]).join('\n');
  return { parsed: { objs, trailerText }, unpacked, decoded, hiddenText };
}

const ACTION_OWNER_KEYS = ['OpenAction', 'AA', 'A', 'O', 'C', 'WC', 'WS', 'DS', 'WP', 'DP', 'K', 'F', 'V', 'E', 'X', 'D', 'U', 'Fo', 'Bl', 'PO', 'PC', 'PV', 'PI', 'Next'];
const EVENT_NAMES: Record<string, string> = {
  OpenAction: 'when the file is opened',
  O: 'when a page opens or the pointer enters',
  C: 'when a page closes',
  WC: 'before the file closes',
  WS: 'before the file is saved',
  DS: 'after the file is saved',
  WP: 'before printing',
  DP: 'after printing',
  K: 'when a form field is edited',
  F: 'when a form field is formatted',
  V: 'when a form field is checked',
  E: 'when the pointer enters a button',
  X: 'when the pointer leaves a button',
  D: 'when a button is pressed',
  U: 'when a link or button is clicked',
  Fo: 'when a field gets focus',
  Bl: 'when a field loses focus',
  Next: 'chained after another action',
  A: 'when the link or button is clicked',
};

const JS_PATTERNS: [RegExp, string][] = [
  [/\beval\s*\(/, 'uses eval() to run hidden code'],
  [/\bunescape\s*\(|%u[0-9a-f]{4}/i, 'decodes escaped strings (a shellcode trick)'],
  [/String\.fromCharCode/, 'builds text from character codes (obfuscation)'],
  [/app\.launchURL|getURL\s*\(/, 'opens a web address'],
  [/exportDataObject|importDataObject/, 'extracts or imports embedded files'],
  [/util\.printf\s*\(/, 'calls util.printf (used by old reader exploits)'],
  [/Collab\.(collectEmailInfo|getIcon)/, 'calls Collab functions (used by old reader exploits)'],
  [/media\.newPlayer|getAnnots\s*\(/, 'calls reader functions used by old exploits'],
  [/submitForm|mailDoc|mailForm/, 'sends data out'],
  [/(.{4,40}?)\1{60,}/, 'repeats a block many times (heap spraying)'],
  [/\.replace\([^)]{0,80}\)\.replace\(/, 'chains string replacements (obfuscation)'],
];

function jsIndicators(src: string): string[] {
  const found: string[] = [];
  for (const [re, label] of JS_PATTERNS) if (re.test(src.slice(0, 100_000))) found.push(label);
  return found;
}

/** The innermost `<<…>>` dictionary around index `at` of `s`. */
function enclosingDict(s: string, at: number): { raw: string; start: number } | null {
  let depth = 0;
  for (let i = at; i >= 1; i--) {
    if (s[i] === '>' && s[i - 1] === '>') { depth++; i--; }
    else if (s[i] === '<' && s[i - 1] === '<') {
      if (depth === 0) {
        const v = readValue(s, i - 1);
        return v ? { raw: v.raw, start: i - 1 } : null;
      }
      depth--;
      i--;
    }
  }
  return null;
}

const isUnc = (t: string) => /^\\\\[^\\]/.test(t) || /^file:\/\/\/?\\\\/i.test(t) || /^\/\/[^/]/.test(t) || /^\\\\/.test(t);

export interface PdfAnalysis {
  report: PdfReport;
  anomalies: Anomaly[];
  links: ExtractedLink[];
  iocs: Iocs;
  /** Embedded files, with their bytes, so the caller can analyse them the same way. */
  embeddedFiles: { name: string; bytes: Uint8Array }[];
  truncated: boolean;
}

export async function analyzePdf(bytes: Uint8Array): Promise<PdfAnalysis> {
  const truncated = bytes.length > PDF_READ_LIMIT;
  const view = truncated ? bytes.subarray(0, PDF_READ_LIMIT) : bytes;
  const text = latin1(view, PDF_READ_LIMIT);
  const anomalies: Anomaly[] = [];
  const links: ExtractedLink[] = [];
  const add = (a: Anomaly) => { if (!anomalies.some((x) => x.id === a.id)) anomalies.push(a); };

  /* header and tail */
  const headAt = text.slice(0, 1024).indexOf('%PDF-');
  const version = text.slice(Math.max(0, headAt)).match(/^%PDF-(\d\.\d)/)?.[1] ?? null;
  const header = headAt >= 0 ? text.slice(headAt, headAt + 8).split(/\s/)[0]! : '(missing)';
  const eofs = [...text.matchAll(/%%EOF/g)];
  const lastEof = eofs.length ? eofs[eofs.length - 1]!.index! + 5 : -1;
  const bytesAfterEof = lastEof >= 0 ? Math.max(0, view.length - lastEof - (text.slice(lastEof, lastEof + 2) === '\r\n' ? 2 : /[\r\n]/.test(text[lastEof] ?? '') ? 1 : 0)) : 0;

  /* pdfid-style counts */
  const counts = countKeywords(text);
  const { parsed, unpacked, decoded, hiddenText } = await parseObjects(view, text);
  const hidden = countKeywords(hiddenText);
  const id: PdfIdRow[] = KEYWORDS.map((k) => ({
    keyword: k.key,
    count: counts.get(k.key)!.count,
    obfuscated: counts.get(k.key)!.obf,
    hiddenInStreams: hidden.get(k.key)!.count,
    note: k.note,
    risk: k.risk,
  }));
  const row = (k: string) => id.find((r) => r.keyword === k)!;
  const total = (k: string) => row(k).count + row(k).hiddenInStreams;
  const encrypted = row('/Encrypt').count > 0;

  let inside = 0;
  const streamBytes: Uint8Array[] = [];
  for (const o of parsed.objs.values()) if (o.stream) { inside += o.stream.length; if (streamBytes.length < 200) streamBytes.push(o.stream); }
  const insideEntropy = streamBytes.length ? entropy(streamBytes.reduce((a, b) => (a.length >= b.length ? a : b)), 1_000_000) : 0;
  const pages = Math.max(row('/Page').count, [...parsed.objs.values()].filter((o) => /\/Type\s*\/Page\b/.test(o.dict)).length);

  /* who points at whom: for naming the trigger of an action */
  const owners = new Map<number, string>();
  for (const o of parsed.objs.values()) {
    for (const m of o.dict.matchAll(new RegExp(`/(${ACTION_OWNER_KEYS.join('|')})\\s+(\\d+)\\s+\\d+\\s+R\\b`, 'g'))) if (!owners.has(Number(m[2]))) owners.set(Number(m[2]), m[1]!);
  }

  const resolveDict = (raw: string | null): { text: string; num: number | null } | null => {
    if (!raw) return null;
    const n = refNum(raw);
    if (n !== null) { const o = parsed.objs.get(n); return o ? { text: o.dict, num: n } : null; }
    if (raw.startsWith('<<')) return { text: raw, num: null };
    return null;
  };

  const stringOf = (raw: string | null): string | null => {
    if (!raw) return null;
    const n = refNum(raw);
    if (n !== null) {
      const d = decoded.get(n);
      if (d) return latin1(d, 2_000_000);
      const o = parsed.objs.get(n);
      const v = o ? readValue(o.dict, 0) : null;
      return v ? stringOf(v.raw) : null;
    }
    if (raw.startsWith('(') || (raw.startsWith('<') && !raw.startsWith('<<'))) {
      const s = readString(raw, 0);
      return s ? textString(s.value) : null;
    }
    return null;
  };

  const fileSpec = (raw: string | null): string | null => {
    if (!raw) return null;
    const direct = stringOf(raw);
    if (direct !== null) return direct;
    const d = resolveDict(raw);
    return d ? (stringOf(getKey(d.text, 'UF')) ?? stringOf(getKey(d.text, 'F')) ?? stringOf(getKey(d.text, 'Unix'))) : null;
  };

  /* actions and JavaScript */
  const javascript: PdfJavaScript[] = [];
  const actions: PdfAction[] = [];
  const seenAction = new Set<string>();
  const handleAction = (act: string, where: string, owner: string | null) => {
    const type = act.match(/\/S\s*\/([A-Za-z0-9#]+)/)?.[1] ?? '';
    if (!type) return;
    const key = `${where}:${type}:${act.length}:${act.slice(0, 80)}`;
    if (seenAction.has(key)) return;
    seenAction.add(key);
    const trigger = owner ? (EVENT_NAMES[owner] ?? `action ${owner}`) : 'when triggered';
    const auto = owner === 'OpenAction';
    if (type === 'JavaScript') {
      const src = stringOf(getKey(act, 'JS')) ?? '';
      const indicators = jsIndicators(src);
      javascript.push({ obj: where, trigger, length: src.length, preview: src.replace(/\s+/g, ' ').slice(0, 400), indicators });
      actions.push({ obj: where, trigger, type: 'JavaScript' });
      const found = extractIocs(src);
      for (const u of found.iocs.urls) links.push({ url: u, where: `JavaScript in ${where}`, how: 'macro' });
    } else if (type === 'URI') {
      const uri = stringOf(getKey(act, 'URI'));
      actions.push({ obj: where, trigger, type: 'URI', target: uri ?? undefined });
    } else if (type === 'Launch') {
      const win = resolveDict(getKey(act, 'Win'));
      const target = fileSpec(getKey(act, 'F')) ?? (win ? stringOf(getKey(win.text, 'F')) : null);
      const params = win ? stringOf(getKey(win.text, 'P')) : null;
      actions.push({ obj: where, trigger, type: 'Launch', target: [target, params].filter(Boolean).join(' ') || undefined });
    } else if (type === 'GoToR' || type === 'GoToE' || type === 'ImportData' || type === 'SubmitForm') {
      const target = fileSpec(getKey(act, 'F'));
      actions.push({ obj: where, trigger, type, target: target ?? undefined });
      if (target && /^(https?|ftp):/i.test(target)) links.push({ url: target, where: `${type} action in ${where}`, how: type === 'SubmitForm' ? 'form' : 'action' });
      else if (target && isUnc(target)) links.push({ url: target, where: `${type} action in ${where}`, how: 'action' });
    } else if (['Rendition', 'Movie', 'Sound', 'Hide', 'Named', 'Thread', 'GoTo', 'SetOCGState', 'Trans', 'GoTo3DView', 'RichMediaExecute'].includes(type)) {
      if (!['GoTo', 'Named', 'Thread', 'Hide', 'Trans', 'SetOCGState'].includes(type)) actions.push({ obj: where, trigger, type });
    }
    void auto;
  };

  for (const o of parsed.objs.values()) {
    const label = `obj ${o.num} ${o.gen}${o.inStream ? ` (in object stream ${o.inStream})` : ''}`;
    for (const m of o.dict.matchAll(/\/S\s*\/(JavaScript|URI|Launch|GoToR|GoToE|ImportData|SubmitForm|Rendition|Movie|Sound|RichMediaExecute|GoTo3DView)\b/g)) {
      const d = enclosingDict(o.dict, m.index!);
      if (!d) continue;
      let owner = o.dict.slice(Math.max(0, d.start - 24), d.start).match(/\/([A-Za-z]+)\s*$/)?.[1] ?? null;
      if (!owner || !ACTION_OWNER_KEYS.includes(owner)) owner = d.start <= o.dict.indexOf('<<') + 1 ? (owners.get(o.num) ?? null) : null;
      handleAction(d.raw, label, owner);
    }
    // Names tree: document-level JavaScript.
    if (/\/Names\s*\[/.test(o.dict) && /\/JS\b/.test(o.dict) === false) continue;
  }
  // JavaScript reachable through the catalog's name tree, when the action objects are plain dictionaries.
  for (const o of parsed.objs.values()) {
    const js = /\/JavaScript\s+(\d+)\s+\d+\s+R/.exec(o.dict);
    if (js && /\/Names\b/.test(o.dict)) {
      const tree = parsed.objs.get(Number(js[1]));
      for (const m of tree?.dict.matchAll(/\(([^)]{0,80})\)\s*(\d+)\s+\d+\s+R/g) ?? []) {
        const a = parsed.objs.get(Number(m[2]));
        if (a && /\/S\s*\/JavaScript/.test(a.dict) && !javascript.some((j) => j.obj.startsWith(`obj ${a.num} `))) handleAction(a.dict, `obj ${a.num} ${a.gen}`, 'OpenAction');
      }
    }
  }

  /* links and where they sit */
  const mediaBox = text.match(/\/MediaBox\s*\[\s*([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s*\]/);
  const defaultW = mediaBox ? Math.abs(Number(mediaBox[3]) - Number(mediaBox[1])) : 612;
  const defaultH = mediaBox ? Math.abs(Number(mediaBox[4]) - Number(mediaBox[2])) : 792;
  const pageOfAnnot = new Map<number, number>();
  let pageIndex = 0;
  const pageBoxes = new Map<number, [number, number]>();
  for (const o of [...parsed.objs.values()].sort((a, b) => a.num - b.num)) {
    if (!/\/Type\s*\/Page\b/.test(o.dict)) continue;
    pageIndex++;
    const mb = o.dict.match(/\/MediaBox\s*\[\s*([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s*\]/);
    pageBoxes.set(pageIndex, mb ? [Math.abs(Number(mb[3]) - Number(mb[1])), Math.abs(Number(mb[4]) - Number(mb[2]))] : [defaultW, defaultH]);
    const annots = getKey(o.dict, 'Annots');
    const list = annots?.startsWith('[') ? annots : (parsed.objs.get(refNum(annots) ?? -1)?.dict ?? '');
    for (const r of list.matchAll(/(\d+)\s+\d+\s+R/g)) pageOfAnnot.set(Number(r[1]), pageIndex);
  }
  for (const o of parsed.objs.values()) {
    if (!/\/Subtype\s*\/Link\b/.test(o.dict)) continue;
    const a = getKey(o.dict, 'A');
    const act = resolveDict(a);
    const uri = act ? stringOf(getKey(act.text, 'URI')) : stringOf(getKey(o.dict, 'URI'));
    if (!uri) continue;
    const rect = o.dict.match(/\/Rect\s*\[\s*([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s*\]/);
    const page = pageOfAnnot.get(o.num) ?? 1;
    const [pw, ph] = pageBoxes.get(page) ?? [defaultW, defaultH];
    const coverage = rect ? (Math.abs(Number(rect[3]) - Number(rect[1])) * Math.abs(Number(rect[4]) - Number(rect[2]))) / (pw * ph || 1) : 0;
    links.push({ url: uri.trim(), where: `link on page ${page}`, how: 'link', coversPage: coverage > 0.6 });
  }
  // URI actions that are not link annotations (OpenAction, form buttons) and every URI string anywhere, e.g. in compressed streams.
  const allText = `${text}\n${[...decoded.values()].map((d) => latin1(d, 1_000_000)).join('\n')}`;
  for (const m of allText.matchAll(/\/URI\s*(\((?:\\.|[^\\)]){1,2000}\)|<[0-9a-fA-F\s]{2,4000}>)/g)) {
    const s = readString(m[1]!, 0);
    const u = s ? textString(s.value).trim() : '';
    if (u && !links.some((l) => l.url === u)) links.push({ url: u, where: 'link action', how: 'link' });
  }

  /* embedded files */
  const embedded: PdfEmbedded[] = [];
  const embeddedFiles: { name: string; bytes: Uint8Array }[] = [];
  const names = new Map<number, string>();
  for (const o of parsed.objs.values()) {
    if (!/\/EF\b/.test(o.dict)) continue;
    const ef = resolveDict(getKey(o.dict, 'EF'));
    const fn = stringOf(getKey(o.dict, 'UF')) ?? stringOf(getKey(o.dict, 'F')) ?? 'unnamed';
    const f = ef ? (refNum(getKey(ef.text, 'F')) ?? refNum(getKey(ef.text, 'UF'))) : null;
    if (f !== null) names.set(f, fn);
  }
  for (const o of parsed.objs.values()) {
    if (!o.stream || !/\/Type\s*\/EmbeddedFile\b|\/Subtype\s*\/[A-Za-z]+\s*\/Type\s*\/EmbeddedFile\b/.test(o.dict) && !names.has(o.num)) continue;
    const data = decoded.get(o.num) ?? o.stream;
    const name = names.get(o.num) ?? `embedded-${o.num}`;
    embedded.push({ name, size: data.length, type: sniff(data).label, sha256: (await hashes(data)).sha256 });
    if (embeddedFiles.length < 8) embeddedFiles.push({ name, bytes: data.subarray(0, 16 * 1024 * 1024) });
  }

  /* metadata */
  const metadata: Record<string, string> = {};
  const info = resolveDict(getKey(parsed.trailerText, 'Info') ?? [...parsed.objs.values()].map((o) => /\/Producer|\/Creator|\/Author/.test(o.dict) ? `${o.num} 0 R` : '').find(Boolean) ?? null);
  if (info) for (const k of ['Title', 'Author', 'Subject', 'Creator', 'Producer', 'CreationDate', 'ModDate']) { const v = stringOf(getKey(info.text, k)); if (v) metadata[k] = v.replace(/[^\x20-\x7e]/g, '').slice(0, 200); }
  const xmp = [...decoded.values()].map((d) => latin1(d, 200_000)).find((t) => /<x:xmpmeta|<rdf:RDF/.test(t));
  if (xmp) { const tool = xmp.match(/<xmp:CreatorTool>([^<]{1,200})</)?.[1]; if (tool && !metadata.Creator) metadata.Creator = tool; }

  /* what the pages say (approximate: fonts can remap letters) */
  let pageText = '';
  for (const d of decoded.values()) {
    if (pageText.length > 40_000) break;
    const t = latin1(d, 400_000);
    if (!/\bBT\b/.test(t) || !/\bET\b/.test(t)) continue;
    const parts: string[] = [];
    for (const m of t.matchAll(/\(((?:\\.|[^\\)]){1,400})\)\s*Tj|\[((?:\\.|[^\]]){1,2000})\]\s*TJ/g)) {
      if (m[1] !== undefined) parts.push(m[1]);
      else for (const s2 of m[2]!.matchAll(/\(((?:\\.|[^\\)]){0,400})\)/g)) parts.push(s2[1]!);
      if (parts.join('').length > 20_000) break;
    }
    const joined = parts.join('').replace(/\\([nrt])/g, ' ').replace(/\\([()\\])/g, '$1').replace(/\\[0-7]{1,3}/g, '').replace(/\s+/g, ' ').trim();
    if (joined && (joined.match(/[A-Za-z]/g)?.length ?? 0) / joined.length > 0.5) pageText += `${joined} `;
  }
  const textPreview = pageText.trim().slice(0, 600);

  /* findings */
  const jsAuto = javascript.some((j) => /opened/.test(j.trigger));
  if (javascript.length || total('/JS') + total('/JavaScript') > 0) {
    const ind = [...new Set(javascript.flatMap((j) => j.indicators))];
    add({
      id: 'pdf-javascript',
      severity: ind.length || jsAuto ? 'critical' : 'high',
      title: `PDF contains JavaScript${javascript.length ? ` (${javascript.length} script${javascript.length === 1 ? '' : 's'})` : ''}`,
      detail: [jsAuto ? 'runs when the file is opened' : '', ...ind].filter(Boolean).join('; ') || undefined,
      plain: jsAuto ? 'This PDF runs code the moment it opens. Ordinary documents never do that.' : 'This PDF contains program code. Invoices and letters do not need it.',
      where: javascript[0]?.obj,
      attack: 'T1059.007',
    });
  }
  if (actions.some((a) => a.type === 'Launch') || total('/Launch') > 0) add({ id: 'pdf-launch', severity: 'critical', title: 'PDF tries to launch a program', detail: actions.filter((a) => a.type === 'Launch').map((a) => a.target).filter(Boolean).join('; ') || undefined, plain: 'This PDF asks your computer to start another program.', attack: 'T1204.002' });
  if (embedded.length || total('/EmbeddedFile') > 0) add({ id: 'pdf-embedded', severity: 'high', title: `PDF has ${embedded.length || 'hidden'} file${embedded.length === 1 ? '' : 's'} embedded inside it`, detail: embedded.map((e) => `${e.name} (${e.type})`).join('; ') || undefined, plain: 'Another file is hidden inside this PDF. Attackers use this to smuggle programs and documents.', attack: 'T1027.009' });
  if (actions.some((a) => a.type === 'SubmitForm') || /\/SubmitForm\b/.test(text)) add({ id: 'pdf-submit', severity: 'high', title: 'PDF has a form that sends what you type to a website', plain: 'Anything you type into this PDF can be sent to a website.', attack: 'T1056' });
  const remote = actions.filter((a) => (a.type === 'GoToR' || a.type === 'GoToE' || a.type === 'ImportData') && a.target && (isUnc(a.target) || /^(https?|ftp):/i.test(a.target)));
  if (remote.length) add({ id: 'pdf-remote-goto', severity: 'high', title: 'PDF opens a file from another computer', detail: remote.map((a) => a.target).join('; '), plain: 'Opening this PDF can contact a remote server, which can leak your Windows sign-in hash.', attack: 'T1187' });
  if (links.some((l) => /^(javascript|file|smb|data):/i.test(l.url) || isUnc(l.url))) add({ id: 'pdf-bad-link', severity: 'high', title: 'PDF link runs code or opens a network file share', plain: 'A link in this PDF does not go to a normal web page.' });
  if (row('/RichMedia').count > 0) add({ id: 'pdf-richmedia', severity: 'high', title: 'PDF embeds Flash or other rich media', plain: 'Ordinary documents do not embed Flash or video players. This is a classic exploit carrier.', attack: 'T1203' });
  if (row('/XFA').count > 0) add({ id: 'pdf-xfa', severity: 'medium', title: 'PDF uses XFA forms', plain: 'An old, rarely needed form format with a history of reader bugs.', attack: 'T1203' });
  if (row('/JBIG2Decode').count > 0) add({ id: 'pdf-jbig2', severity: 'medium', title: 'PDF uses JBIG2 image compression', plain: 'A rarely used image format that has carried reader exploits.', attack: 'T1203' });
  if (encrypted) add({ id: 'pdf-encrypted', severity: 'medium', title: 'PDF is encrypted', plain: 'The contents are scrambled, so virus scanners cannot read inside. Phishing PDFs sometimes do this on purpose.' });
  const coverLinks = links.filter((l) => l.coversPage);
  if (coverLinks.length) add({ id: 'pdf-fullpage-link', severity: 'medium', title: 'One link covers most of a page', detail: coverLinks[0]!.url, plain: 'The whole page is one big invisible button. A common trick so any click leaves for a phishing site.', attack: 'T1566.002' });
  const hiddenDanger = id.filter((r) => r.risk === 'danger' && r.hiddenInStreams > 0);
  if (hiddenDanger.length) add({ id: 'pdf-hidden-keywords', severity: 'high', title: 'Risky features hidden in compressed object streams', detail: hiddenDanger.map((r) => `${r.keyword} ×${r.hiddenInStreams}`).join(', '), plain: 'Risky features were packed inside compressed data, where simple scanners do not look.', attack: 'T1027' });
  const obf = id.filter((r) => r.obfuscated > 0 && r.risk !== 'normal');
  if (obf.length) add({ id: 'pdf-name-obfuscation', severity: 'high', title: 'Keywords written with hex escapes to dodge scanners', detail: obf.map((r) => `${r.keyword} ×${r.obfuscated}`).join(', '), plain: 'Names in this PDF were spelled in a disguised way so security tools would miss them.', attack: 'T1027' });
  if (headAt > 0) add({ id: 'pdf-junk-header', severity: 'medium', title: `${headAt} bytes of data before the %PDF header`, plain: 'Data was put in front of the PDF. Readers still open it, but some scanners do not recognise it.' });
  if (headAt < 0) add({ id: 'pdf-no-header', severity: 'medium', title: 'No %PDF header found', plain: 'The file claims to be a PDF but does not start like one.' });
  if (bytesAfterEof > 1024) add({ id: 'pdf-trailing-data', severity: 'medium', title: `${bytesAfterEof.toLocaleString()} bytes of data after the end of the PDF`, plain: 'Extra data was appended after the end of the file, a place to hide a payload.', attack: 'T1027.009' });
  if (eofs.length > 2) add({ id: 'pdf-incremental', severity: 'low', title: `Saved ${eofs.length} times (${eofs.length} %%EOF markers)`, plain: 'The file was edited and re-saved several times. Earlier versions can still be inside it.' });
  const objCount = row('obj').count, endobjCount = row('endobj').count;
  if (Math.abs(objCount - endobjCount) > 2) add({ id: 'pdf-malformed', severity: 'low', title: `${objCount} objects but ${endobjCount} endobj markers`, plain: 'The structure is damaged or hand-made, which is common for malicious PDFs.' });
  if (row('/ObjStm').count > 0 && !hiddenDanger.length) void 0;

  // Indicators come from what people can read and what code can do, not from raw file bytes
  // (metadata and signatures are full of harmless web addresses).
  const found = extractIocs([pageText, ...javascript.map((j) => j.preview), ...actions.map((x) => x.target ?? '')].join('\n'), { decode: true });
  for (const u of found.iocs.urls) if (!links.some((l) => l.url === u)) links.push({ url: u, where: 'text on the pages or in code', how: 'text' });

  const report: PdfReport = {
    header,
    version,
    pages,
    objects: parsed.objs.size,
    encrypted,
    id,
    eofCount: eofs.length,
    bytesAfterEof,
    entropy: { total: entropy(view), insideStreams: insideEntropy, outsideStreams: entropy(Uint8Array.from(text.replace(/stream\r?\n[\s\S]*?endstream/g, '').slice(0, 1_000_000), (c) => c.charCodeAt(0) & 255)) },
    metadata,
    javascript: javascript.slice(0, 20),
    actions: actions.slice(0, 40),
    embedded,
    textPreview,
    objectStreamsUnpacked: unpacked,
  };
  void inside;
  return { report, anomalies, links: dedupeLinks(links), iocs: { ...EMPTY_IOCS(), ...found.iocs }, embeddedFiles, truncated };
}

export function dedupeLinks(links: ExtractedLink[], max = 300): ExtractedLink[] {
  const seen = new Set<string>();
  const out: ExtractedLink[] = [];
  for (const l of links) {
    if (!l.url || seen.has(l.url)) continue;
    seen.add(l.url);
    out.push(l);
    if (out.length >= max) break;
  }
  return out;
}
