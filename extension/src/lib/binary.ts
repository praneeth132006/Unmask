/**
 * Small, defensive readers for the file formats phishing attachments use:
 * ZIP (and Office files, which are ZIPs), PDF streams, and deflate data.
 * Every reader caps how much it inflates, so a zip bomb can't freeze the panel.
 */

export const MAX_INFLATE = 8 * 1024 * 1024;

export function latin1(bytes: Uint8Array, max = 4_000_000): string {
  let s = '';
  const end = Math.min(bytes.length, max);
  for (let i = 0; i < end; i += 8192) s += String.fromCharCode(...bytes.subarray(i, Math.min(i + 8192, end)));
  return s;
}

export function fromLatin1(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

/** Inflates zlib ('deflate') or raw deflate data, stopping at `limit` bytes. Null if the data is corrupt. */
export async function inflate(data: Uint8Array, format: 'deflate' | 'deflate-raw', limit = MAX_INFLATE): Promise<Uint8Array | null> {
  if (typeof DecompressionStream === 'undefined') return null;
  try {
    const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream(format));
    const reader = stream.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
      if (total >= limit) {
        void reader.cancel().catch(() => {});
        break;
      }
    }
    const out = new Uint8Array(Math.min(total, limit));
    let at = 0;
    for (const c of chunks) {
      const take = Math.min(c.length, out.length - at);
      out.set(c.subarray(0, take), at);
      at += take;
      if (at >= out.length) break;
    }
    return out;
  } catch {
    return null;
  }
}

const u16 = (b: Uint8Array, o: number) => b[o]! | (b[o + 1]! << 8);
const u32 = (b: Uint8Array, o: number) => (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0;

export interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  size: number;
  offset: number;
  encrypted: boolean;
}

export function isZip(b: Uint8Array): boolean {
  return b.length > 22 && b[0] === 0x50 && b[1] === 0x4b && (b[2] === 0x03 || b[2] === 0x05);
}

/** Lists a ZIP's files from its central directory. Empty for anything that isn't a readable ZIP. */
export function zipEntries(b: Uint8Array, max = 2000): ZipEntry[] {
  // The end-of-central-directory record is in the last 22 + 65535 bytes.
  let eocd = -1;
  for (let i = b.length - 22; i >= Math.max(0, b.length - 22 - 65535); i--) {
    if (b[i] === 0x50 && b[i + 1] === 0x4b && b[i + 2] === 0x05 && b[i + 3] === 0x06) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return [];
  const count = u16(b, eocd + 10);
  let p = u32(b, eocd + 16);
  const out: ZipEntry[] = [];
  const decoder = new TextDecoder();
  for (let n = 0; n < count && n < max && p + 46 <= b.length; n++) {
    if (u32(b, p) !== 0x02014b50) break;
    const flags = u16(b, p + 8);
    const nameLen = u16(b, p + 28);
    const extraLen = u16(b, p + 30);
    const commentLen = u16(b, p + 32);
    out.push({
      name: decoder.decode(b.subarray(p + 46, p + 46 + nameLen)),
      method: u16(b, p + 10),
      compressedSize: u32(b, p + 20),
      size: u32(b, p + 24),
      offset: u32(b, p + 42),
      encrypted: (flags & 1) === 1,
    });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

/** Reads one entry's bytes (stored or deflated). Null when encrypted, unsupported or corrupt. */
export async function zipRead(b: Uint8Array, e: ZipEntry, limit = MAX_INFLATE): Promise<Uint8Array | null> {
  if (e.encrypted || e.offset + 30 > b.length || u32(b, e.offset) !== 0x04034b50) return null;
  const start = e.offset + 30 + u16(b, e.offset + 26) + u16(b, e.offset + 28);
  const data = b.subarray(start, Math.min(b.length, start + e.compressedSize));
  if (e.method === 0) return data.subarray(0, limit);
  if (e.method === 8) return inflate(data, 'deflate-raw', limit);
  return null;
}

export interface PdfStream {
  /** The stream's dictionary source, e.g. "<< /Filter /FlateDecode /Length 120 >>". */
  dict: string;
  data: Uint8Array;
}

/** Finds every `stream … endstream` block in a PDF, with the dictionary in front of it. */
export function pdfStreams(b: Uint8Array, max = 400): PdfStream[] {
  const text = latin1(b, 20_000_000);
  const out: PdfStream[] = [];
  const re = /stream\r?\n/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) && out.length < max) {
    const dictEnd = text.lastIndexOf('>>', m.index);
    const objStart = text.lastIndexOf(' obj', m.index);
    if (dictEnd < 0 || objStart < 0 || dictEnd < objStart) continue;
    const dict = text.slice(objStart + 4, dictEnd + 2);
    const start = m.index + m[0].length;
    const len = Number(dict.match(/\/Length\s+(\d+)(?!\s+\d+\s+R)/)?.[1] ?? NaN);
    let end = Number.isFinite(len) && start + len <= text.length ? start + len : text.indexOf('endstream', start);
    if (end < 0) break;
    out.push({ dict, data: b.subarray(start, end) });
    re.lastIndex = end;
  }
  return out;
}

/** Decodes a stream's data when it is unfiltered or FlateDecode; null for other filters. */
export async function pdfStreamData(s: PdfStream, limit = MAX_INFLATE): Promise<Uint8Array | null> {
  const filters = [...s.dict.matchAll(/\/(FlateDecode|Fl|DCTDecode|ASCIIHexDecode|ASCII85Decode|LZWDecode|JBIG2Decode|JPXDecode|CCITTFaxDecode|RunLengthDecode)\b/g)].map((x) => x[1]);
  if (!filters.length) return s.data.subarray(0, limit);
  if (filters.length === 1 && (filters[0] === 'FlateDecode' || filters[0] === 'Fl')) return inflate(s.data, 'deflate', limit);
  return null;
}

/** The PDF's text plus its inflated streams, for keyword and URI searches. */
export async function pdfSearchText(b: Uint8Array, limit = 16 * 1024 * 1024): Promise<string> {
  let text = latin1(b, 8_000_000);
  for (const s of pdfStreams(b)) {
    if (text.length >= limit) break;
    if (/\/Subtype\s*\/Image/.test(s.dict)) continue;
    const data = await pdfStreamData(s, 2 * 1024 * 1024);
    if (data && data !== s.data) text += `\n${latin1(data)}`;
  }
  return text;
}

/** Reads a PDF literal string body: handles \( \) \\ and octal escapes. */
function pdfLiteral(s: string): string {
  return s.replace(/\\([nrtbf()\\]|[0-7]{1,3})/g, (_, e: string) => {
    if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8));
    return ({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' } as Record<string, string>)[e] ?? e;
  });
}

/** Every /URI action target in the PDF text. */
export function pdfUris(text: string): string[] {
  const out = new Set<string>();
  for (const m of text.matchAll(/\/URI\s*\(((?:\\.|[^\\)]){1,2000})\)/g)) out.add(pdfLiteral(m[1]!).trim());
  for (const m of text.matchAll(/\/URI\s*<([0-9a-fA-F\s]{2,4000})>/g)) {
    const hex = m[1]!.replace(/\s/g, '');
    let s = '';
    for (let i = 0; i + 1 < hex.length; i += 2) s += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
    out.add(s.trim());
  }
  return [...out].filter(Boolean);
}
