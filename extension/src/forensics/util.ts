/**
 * Byte-level helpers for the forensics engine: file-type sniffing, entropy,
 * hashes and the simple PDF stream filters. All pure functions.
 */
import { inflate, latin1 } from '../lib/binary';
import type { FileHashes } from './types';

export const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** Shannon entropy in bits per byte over at most the first 4 MB. */
export function entropy(bytes: Uint8Array, max = 4 * 1024 * 1024): number {
  const n = Math.min(bytes.length, max);
  if (!n) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < n; i++) counts[bytes[i]!]!++;
  let e = 0;
  for (const c of counts) {
    if (!c) continue;
    const p = c / n;
    e -= p * Math.log2(p);
  }
  return Math.round(e * 100) / 100;
}

const startsWith = (b: Uint8Array, sig: number[], at = 0) => sig.every((v, i) => b[at + i] === v);
const ascii = (b: Uint8Array, start: number, len: number) => String.fromCharCode(...b.subarray(start, start + len));

export interface MagicResult {
  kind: 'pdf' | 'zip' | 'ole' | 'rtf' | 'html' | 'script' | 'image' | 'executable' | 'shortcut' | 'archive' | 'text' | 'other';
  label: string;
  mime: string | null;
}

/** What the content says the file is. Only the first bytes are looked at. */
export function sniff(b: Uint8Array): MagicResult {
  if (b.length >= 5 && ascii(b, 0, 5) === '%PDF-') return { kind: 'pdf', label: 'PDF document', mime: 'application/pdf' };
  // A PDF with junk in front: Acrobat still opens it, most scanners do not.
  if (b.length > 8) {
    const head = ascii(b, 0, Math.min(b.length, 1024));
    if (head.includes('%PDF-')) return { kind: 'pdf', label: 'PDF document (with data before the header)', mime: 'application/pdf' };
  }
  if (b[0] === 0x4d && b[1] === 0x5a) {
    // MZ: a Windows program, unless it is too small to hold a PE header.
    const pe = b.length > 0x40 ? (b[0x3c]! | (b[0x3d]! << 8) | (b[0x3e]! << 16)) : 0;
    const isPe = pe > 0 && pe + 4 < b.length && startsWith(b, [0x50, 0x45, 0, 0], pe);
    return { kind: 'executable', label: isPe ? 'Windows program (PE)' : 'DOS/Windows program (MZ)', mime: 'application/vnd.microsoft.portable-executable' };
  }
  if (startsWith(b, [0x7f, 0x45, 0x4c, 0x46])) return { kind: 'executable', label: 'Linux program (ELF)', mime: 'application/x-elf' };
  if (startsWith(b, [0xcf, 0xfa, 0xed, 0xfe]) || startsWith(b, [0xce, 0xfa, 0xed, 0xfe]) || startsWith(b, [0xca, 0xfe, 0xba, 0xbe])) return { kind: 'executable', label: 'macOS program (Mach-O) or Java class', mime: 'application/x-mach-binary' };
  if (startsWith(b, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return { kind: 'ole', label: 'Legacy Office file (OLE2: .doc, .xls, .ppt, .msi, .msg)', mime: 'application/x-ole-storage' };
  if (startsWith(b, [0x50, 0x4b, 0x03, 0x04]) || startsWith(b, [0x50, 0x4b, 0x05, 0x06])) return { kind: 'zip', label: 'ZIP container (also .docx, .xlsx, .pptx, .jar, .apk)', mime: 'application/zip' };
  if (ascii(b, 0, 5) === '{\\rtf') return { kind: 'rtf', label: 'Rich Text Format', mime: 'application/rtf' };
  if (startsWith(b, [0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0])) return { kind: 'shortcut', label: 'Windows shortcut (.lnk)', mime: 'application/x-ms-shortcut' };
  if (startsWith(b, [0x52, 0x61, 0x72, 0x21])) return { kind: 'archive', label: 'RAR archive', mime: 'application/vnd.rar' };
  if (startsWith(b, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return { kind: 'archive', label: '7-Zip archive', mime: 'application/x-7z-compressed' };
  if (startsWith(b, [0x1f, 0x8b])) return { kind: 'archive', label: 'gzip archive', mime: 'application/gzip' };
  if (startsWith(b, [0x42, 0x5a, 0x68])) return { kind: 'archive', label: 'bzip2 archive', mime: 'application/x-bzip2' };
  if (startsWith(b, [0x4d, 0x53, 0x43, 0x46])) return { kind: 'archive', label: 'Cabinet archive (.cab)', mime: 'application/vnd.ms-cab-compressed' };
  if (b.length > 0x8006 && ascii(b, 0x8001, 5) === 'CD001') return { kind: 'archive', label: 'Disk image (ISO)', mime: 'application/x-iso9660-image' };
  if (startsWith(b, [0x89, 0x50, 0x4e, 0x47])) return { kind: 'image', label: 'PNG image', mime: 'image/png' };
  if (startsWith(b, [0xff, 0xd8, 0xff])) return { kind: 'image', label: 'JPEG image', mime: 'image/jpeg' };
  if (ascii(b, 0, 3) === 'GIF') return { kind: 'image', label: 'GIF image', mime: 'image/gif' };
  const head = ascii(b, 0, Math.min(b.length, 2048)).replace(/^﻿/, '').trimStart().toLowerCase();
  if (/^(<!doctype html|<html|<head|<body|<script|<form|<meta)/.test(head)) return { kind: 'html', label: 'HTML page', mime: 'text/html' };
  if (/^<svg|^<\?xml[^>]*\?>\s*<svg/.test(head)) return { kind: 'html', label: 'SVG image (can contain scripts)', mime: 'image/svg+xml' };
  if (/^#!\s*\//.test(head) || /^(@echo off|powershell|\$ErrorActionPreference|set-executionpolicy)/i.test(head)) return { kind: 'script', label: 'Script', mime: 'text/plain' };
  return { kind: 'other', label: 'Unknown or plain data', mime: null };
}

/** Extensions that match a sniffed kind; used to catch a file whose name lies about its type. */
const EXT_BY_KIND: Record<string, RegExp> = {
  pdf: /^pdf$/,
  zip: /^(zip|docx|docm|dotx|dotm|xlsx|xlsm|xlsb|xltx|xltm|pptx|pptm|potx|potm|ppsx|ppsm|odt|ods|odp|jar|apk|xpi|vsdx|one|msix|appx|nupkg|epub)$/,
  ole: /^(doc|dot|xls|xlt|ppt|pot|pps|msi|msg|msp|mst|vsd|pub|wiz|xla|ppa|hwp)$/,
  rtf: /^(rtf|doc)$/,
  image: /^(png|jpe?g|gif|bmp|webp|ico|tiff?)$/,
};

/** A short explanation when the content does not match the file name, or null. */
export function extensionMismatch(ext: string, magic: MagicResult): string | null {
  if (!ext) return null;
  const rule = EXT_BY_KIND[magic.kind];
  if (magic.kind === 'executable' && !/^(exe|dll|scr|sys|ocx|cpl|com|so|dylib|bin|elf|class|xll|drv|efi|node)$/.test(ext)) return `Named .${ext} but the content is a ${magic.label.toLowerCase()}`;
  if (magic.kind === 'shortcut' && ext !== 'lnk') return `Named .${ext} but the content is a Windows shortcut`;
  if (rule && !rule.test(ext) && !/^(bin|dat|tmp|txt|)$/.test(ext) && /^(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|csv)$/.test(ext)) return `Named .${ext} but the content is a ${magic.label.toLowerCase()}`;
  if ((magic.kind === 'html' || magic.kind === 'script') && /^(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|csv|rtf)$/.test(ext)) return `Named .${ext} but the content is ${magic.kind === 'html' ? 'a web page' : 'a script'}`;
  return null;
}

/* ---------------------------------------------------------------- hashes */

async function digest(algo: 'SHA-1' | 'SHA-256', bytes: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest(algo, bytes as BufferSource)));
}

/** MD5 (for matching older threat-intel records; never used for security decisions). */
export function md5(bytes: Uint8Array): string {
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;
  const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
  const len = bytes.length;
  const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(bytes);
  padded[len] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, (len << 3) >>> 0, true);
  view.setUint32(padded.length - 4, Math.floor(len / 2 ** 29), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Uint32Array(16);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = view.getUint32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F: number, g: number;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i]! + M[g]!) >>> 0;
      A = D; D = C; C = B;
      B = (B + ((F << S[i]!) | (F >>> (32 - S[i]!)))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16);
  const ov = new DataView(out.buffer);
  [a0, b0, c0, d0].forEach((v, i) => ov.setUint32(i * 4, v, true));
  return hex(out);
}

export async function hashes(bytes: Uint8Array): Promise<FileHashes> {
  return { sha256: await digest('SHA-256', bytes), sha1: await digest('SHA-1', bytes), md5: bytes.length <= 64 * 1024 * 1024 ? md5(bytes) : '' };
}

/* ---------------------------------------------------- PDF stream filters */

export const fromAscii = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);

export function asciiHexDecode(s: string): Uint8Array {
  const clean = s.replace(/>.*$/s, '').replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(Math.ceil(clean.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2).padEnd(2, '0'), 16);
  return out;
}

export function ascii85Decode(s: string): Uint8Array {
  const body = s.replace(/^\s*<~/, '').replace(/~>.*$/s, '').replace(/\s/g, '');
  const out: number[] = [];
  let group: number[] = [];
  for (const ch of body) {
    if (ch === 'z' && !group.length) { out.push(0, 0, 0, 0); continue; }
    const v = ch.charCodeAt(0) - 33;
    if (v < 0 || v > 84) continue;
    group.push(v);
    if (group.length === 5) {
      let n = 0;
      for (const g of group) n = n * 85 + g;
      out.push((n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
      group = [];
    }
  }
  if (group.length > 1) {
    const pad = 5 - group.length;
    while (group.length < 5) group.push(84);
    let n = 0;
    for (const g of group) n = n * 85 + g;
    const bytes = [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
    out.push(...bytes.slice(0, 4 - pad));
  }
  return Uint8Array.from(out);
}

export function runLengthDecode(b: Uint8Array): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < b.length && out.length < 16 * 1024 * 1024;) {
    const n = b[i++]!;
    if (n === 128) break;
    if (n < 128) { for (let k = 0; k <= n && i < b.length; k++) out.push(b[i++]!); }
    else { const v = b[i++]; for (let k = 0; k < 257 - n; k++) out.push(v ?? 0); }
  }
  return Uint8Array.from(out);
}

/** PDF/TIFF-style LZW (early change = 1). */
export function lzwDecode(b: Uint8Array): Uint8Array {
  const out: number[] = [];
  let table: number[][] = [];
  const reset = () => { table = Array.from({ length: 256 }, (_, i) => [i]); table.push([], []); };
  reset();
  let bits = 9, acc = 0, nbits = 0, prev: number[] | null = null;
  for (let i = 0; i < b.length; ) {
    while (nbits < bits && i < b.length) { acc = (acc << 8) | b[i++]!; nbits += 8; }
    if (nbits < bits) break;
    const code = (acc >> (nbits - bits)) & ((1 << bits) - 1);
    nbits -= bits;
    acc &= (1 << nbits) - 1;
    if (code === 256) { reset(); bits = 9; prev = null; continue; }
    if (code === 257) break;
    let entry: number[];
    if (code < table.length) entry = table[code]!;
    else if (prev) entry = [...prev, prev[0]!];
    else break;
    out.push(...entry);
    if (prev) table.push([...prev, entry[0]!]);
    prev = entry;
    if (table.length + 1 >= 2048) bits = 12;
    else if (table.length + 1 >= 1024) bits = 11;
    else if (table.length + 1 >= 512) bits = 10;
    if (out.length > 16 * 1024 * 1024) break;
  }
  return Uint8Array.from(out);
}

/** Applies a PDF /Filter chain. Returns null when a filter is unsupported (images, encryption). */
export async function applyPdfFilters(data: Uint8Array, filters: string[], limit = 8 * 1024 * 1024): Promise<Uint8Array | null> {
  let cur = data;
  for (const raw of filters) {
    const f = raw.replace(/^\//, '');
    if (f === 'FlateDecode' || f === 'Fl') {
      const r = await inflate(cur, 'deflate', limit);
      if (!r) return null;
      cur = r;
    } else if (f === 'ASCIIHexDecode' || f === 'AHx') cur = asciiHexDecode(latin1(cur, limit));
    else if (f === 'ASCII85Decode' || f === 'A85') cur = ascii85Decode(latin1(cur, limit));
    else if (f === 'RunLengthDecode' || f === 'RL') cur = runLengthDecode(cur);
    else if (f === 'LZWDecode' || f === 'LZW') cur = lzwDecode(cur);
    else return null;
  }
  return cur;
}

export const defang = (s: string): string => s.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
