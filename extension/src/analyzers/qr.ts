/**
 * QR-code phishing ("quishing"): a QR code in an image or PDF sends you to a
 * site on your phone, where the address is hard to check and desktop filters
 * never saw the link. Unmask decodes QR codes in the email's own images
 * (attachments, inline images, data: images, images inside PDFs) and puts
 * every decoded link through the normal link checks. Remote images are not
 * downloaded: that would tell the sender you opened the email.
 *
 * QR codes drawn without any image are read too: a grid of black and white
 * table cells, or lines of Unicode block characters (█ ▀ ▄). Phishers use
 * these because image scanners find nothing to scan.
 */
import jsQR from 'jsqr';
import type { Finding, ParsedAttachment, ParsedEmail, QrCode } from '../core/types';
import type { RawLink } from './content';
import { pdfStreamData, pdfStreams } from '../lib/binary';

export interface Pixels {
  data: Uint8ClampedArray;
  width: number;
  height: number;
}

/** Turns image bytes (PNG, JPEG, GIF, WebP, BMP) into RGBA pixels. Injected: the browser does it with a canvas. */
export type ImageDecoder = (bytes: Uint8Array, mimeType: string) => Promise<Pixels | null>;

const MAX_IMAGES = 16;
const MAX_IMAGE_BYTES = 10 * 1024 * 1024;
const IMAGE_MIME = /^image\/(png|jpe?g|gif|webp|bmp)$/i;

export function decodeQr(px: Pixels): string | null {
  if (px.width < 21 || px.height < 21 || px.data.length < px.width * px.height * 4) return null;
  try {
    return jsQR(px.data, px.width, px.height, { inversionAttempts: 'attemptBoth' })?.data || null;
  } catch {
    return null;
  }
}

/** 8-bit gray or RGB samples (as stored in a PDF image) to RGBA. */
export function samplesToRgba(samples: Uint8Array, width: number, height: number, components: 1 | 3): Pixels | null {
  const n = width * height;
  if (samples.length < n * components) return null;
  const data = new Uint8ClampedArray(n * 4);
  for (let i = 0; i < n; i++) {
    const r = samples[i * components]!;
    data[i * 4] = r;
    data[i * 4 + 1] = components === 3 ? samples[i * 3 + 1]! : r;
    data[i * 4 + 2] = components === 3 ? samples[i * 3 + 2]! : r;
    data[i * 4 + 3] = 255;
  }
  return { data, width, height };
}

/** Images inside a PDF: JPEG streams are decoded by the browser, 8-bit Flate images directly. */
async function pdfImages(bytes: Uint8Array, decode: ImageDecoder | undefined): Promise<Pixels[]> {
  const out: Pixels[] = [];
  for (const s of pdfStreams(bytes)) {
    if (out.length >= MAX_IMAGES || !/\/Subtype\s*\/Image\b/.test(s.dict)) continue;
    const width = Number(s.dict.match(/\/Width\s+(\d+)/)?.[1] ?? 0);
    const height = Number(s.dict.match(/\/Height\s+(\d+)/)?.[1] ?? 0);
    if (width < 21 || height < 21 || width * height > 16_000_000) continue;
    if (/\/DCTDecode\b/.test(s.dict)) {
      const px = decode ? await decode(s.data, 'image/jpeg').catch(() => null) : null;
      if (px) out.push(px);
      continue;
    }
    // Only plain 8-bit gray/RGB without predictors; anything fancier is skipped rather than misread.
    if (!/\/BitsPerComponent\s+8\b/.test(s.dict) || /\/DecodeParms|\/Predictor/.test(s.dict)) continue;
    const components = /\/DeviceRGB\b/.test(s.dict) ? 3 : /\/DeviceGray\b/.test(s.dict) ? 1 : 0;
    if (!components) continue;
    const samples = await pdfStreamData(s, width * height * components + 16);
    const px = samples && samplesToRgba(samples, width, height, components);
    if (px) out.push(px);
  }
  return out;
}

function dataUrlImages(html: string | null): { name: string; bytes: Uint8Array; mime: string }[] {
  if (!html) return [];
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const out: { name: string; bytes: Uint8Array; mime: string }[] = [];
  doc.querySelectorAll('img[src^="data:image/" i]').forEach((img, i) => {
    const m = (img.getAttribute('src') ?? '').match(/^data:(image\/[a-z+.-]+);base64,([a-z0-9+/=\s]+)$/i);
    if (!m || out.length >= MAX_IMAGES || m[2]!.length > MAX_IMAGE_BYTES * 1.4) return;
    try {
      const bin = atob(m[2]!.replace(/\s/g, ''));
      const bytes = new Uint8Array(bin.length);
      for (let j = 0; j < bin.length; j++) bytes[j] = bin.charCodeAt(j);
      out.push({ name: img.getAttribute('alt') || `embedded image ${i + 1}`, bytes, mime: m[1]! });
    } catch {
      // bad base64: skip
    }
  });
  return out;
}

/** A grid of dark/light modules, drawn 4 pixels each with a 4-module quiet zone. */
export function gridToPixels(grid: boolean[][]): Pixels | null {
  const rows = grid.length;
  const cols = Math.max(0, ...grid.map((r) => r.length));
  if (rows < 21 || cols < 21 || rows > 200 || cols > 200) return null;
  const scale = 4;
  const w = (cols + 8) * scale;
  const h = (rows + 8) * scale;
  const data = new Uint8ClampedArray(w * h * 4).fill(255);
  for (let y = 0; y < rows; y++)
    for (let x = 0; x < cols; x++) {
      if (!grid[y]![x]) continue;
      for (let dy = 0; dy < scale; dy++)
        for (let dx = 0; dx < scale; dx++) {
          const i = (((y + 4) * scale + dy) * w + (x + 4) * scale + dx) * 4;
          data[i] = data[i + 1] = data[i + 2] = 0;
        }
    }
  return { data, width: w, height: h };
}

/** How dark a CSS colour is, or null when it isn't one we can read. */
function isDark(color: string): boolean | null {
  const c = color.trim().toLowerCase();
  if (!c) return null;
  if (c === 'black') return true;
  if (c === 'white' || c === 'transparent') return false;
  let r: number, g: number, b: number;
  const hex = c.match(/^#([0-9a-f]{3}|[0-9a-f]{6})$/);
  const rgb = c.match(/^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)/);
  if (hex) {
    const h = hex[1]!.length === 3 ? hex[1]!.split('').map((d) => d + d).join('') : hex[1]!;
    [r, g, b] = [0, 2, 4].map((o) => parseInt(h.slice(o, o + 2), 16)) as [number, number, number];
  } else if (rgb) [r, g, b] = [Number(rgb[1]), Number(rgb[2]), Number(rgb[3])];
  else return null;
  return 0.299 * r + 0.587 * g + 0.114 * b < 128;
}

function cellColor(el: Element): string {
  const style = el.getAttribute('style') ?? '';
  return style.match(/background(?:-color)?\s*:\s*([^;]+)/i)?.[1]?.replace(/!important/, '').trim() ?? el.getAttribute('bgcolor') ?? '';
}

/** QR codes drawn as an HTML table of black and white cells. */
export function tableQrGrids(html: string | null): boolean[][][] {
  if (!html || !/<t[dh][\s>]/i.test(html)) return [];
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const out: boolean[][][] = [];
  for (const table of [...doc.querySelectorAll('table')].slice(0, 50)) {
    const rows = [...table.querySelectorAll(':scope > tr, :scope > tbody > tr, :scope > thead > tr')];
    if (rows.length < 21) continue;
    const grid: boolean[][] = [];
    let readable = true;
    for (const tr of rows) {
      const row: boolean[] = [];
      for (const td of tr.querySelectorAll(':scope > td, :scope > th')) {
        const dark = isDark(cellColor(td)) ?? isDark(cellColor(tr)) ?? false;
        const span = Math.min(Number(td.getAttribute('colspan') ?? 1) || 1, 200);
        for (let i = 0; i < span; i++) row.push(dark);
      }
      if (row.length < 21) { readable = false; break; }
      grid.push(row);
    }
    if (readable && grid.some((r) => r.includes(true))) out.push(grid);
  }
  return out;
}

/** QR codes drawn with Unicode blocks: █ full, ▀ upper half, ▄ lower half (two module rows per line). */
export function textQrGrids(text: string | null): boolean[][][] {
  if (!text || !/[█▀▄]/.test(text)) return [];
  const out: boolean[][][] = [];
  let block: string[] = [];
  const flush = () => {
    if (block.length >= 10) {
      // Lines are often indented by the same amount; that indent is not part of the code.
      const indent = Math.min(...block.map((l) => l.match(/^ */)![0].length));
      block = block.map((l) => l.slice(indent));
      const half = block.some((l) => /[▀▄]/.test(l));
      const grid: boolean[][] = [];
      for (const line of block) {
        const chars = [...line];
        if (half) {
          grid.push(chars.map((c) => c === '█' || c === '▀'));
          grid.push(chars.map((c) => c === '█' || c === '▄'));
        } else grid.push(chars.map((c) => c === '█'));
      }
      // A full block drawn twice as wide as tall ("██" per module) is common; squash it back.
      const doubled = !half && grid.every((r) => r.length % 2 === 0) && grid[0]!.length >= grid.length * 1.8;
      out.push(doubled ? grid.map((r) => r.filter((_, i) => i % 2 === 0)) : grid);
    }
    block = [];
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\u00a0/g, ' ').replace(/\s+$/, '');
    if (/^[\s█▀▄]+$/.test(line) && /[█▀▄]/.test(line)) block.push(line);
    else flush();
  }
  flush();
  return out;
}

function isPdf(a: ParsedAttachment): boolean {
  return a.mimeType === 'application/pdf' || /\.pdf$/i.test(a.filename) || (a.content[0] === 0x25 && a.content[1] === 0x50 && a.content[2] === 0x44 && a.content[3] === 0x46);
}

/** Finds and decodes every QR code in the email's own images and PDFs. */
export async function findQrCodes(email: ParsedEmail, decode?: ImageDecoder): Promise<QrCode[]> {
  const codes: QrCode[] = [];
  const add = (origin: string, text: string | null) => {
    if (text && !codes.some((c) => c.text === text && c.origin === origin)) codes.push({ origin, text });
  };
  let images = 0;

  for (const a of email.attachments) {
    if (a.size > MAX_IMAGE_BYTES * 2) continue;
    if (IMAGE_MIME.test(a.mimeType) && decode && images < MAX_IMAGES) {
      images++;
      const px = await decode(a.content, a.mimeType).catch(() => null);
      if (px) add(a.filename || 'inline image', decodeQr(px));
    } else if (isPdf(a)) {
      for (const px of await pdfImages(a.content, decode)) add(`image in ${a.filename}`, decodeQr(px));
    }
  }
  for (const grid of tableQrGrids(email.html)) {
    const px = gridToPixels(grid);
    if (px) add('QR code drawn with table cells', decodeQr(px));
  }
  for (const grid of textQrGrids(email.text)) {
    const px = gridToPixels(grid);
    if (px) add('QR code drawn with text characters', decodeQr(px));
  }
  if (decode) {
    for (const img of dataUrlImages(email.html)) {
      if (images++ >= MAX_IMAGES) break;
      const px = await decode(img.bytes, img.mime).catch(() => null);
      if (px) add(img.name, decodeQr(px));
    }
  }
  return codes;
}

export function qrLinks(codes: QrCode[]): RawLink[] {
  return codes.filter((c) => /^https?:\/\//i.test(c.text.trim())).map((c) => ({ href: c.text.trim(), text: '', source: 'qr' as const, origin: `QR code in ${c.origin}` }));
}

export function qrFindings(codes: QrCode[]): Finding[] {
  if (!codes.length) return [];
  const urls = codes.filter((c) => /^https?:\/\//i.test(c.text.trim()));
  const hosts = [...new Set(urls.map((c) => { try { return new URL(c.text.trim()).hostname; } catch { return ''; } }).filter(Boolean))];
  const where = [...new Set(codes.map((c) => c.origin))].slice(0, 3).join(', ');
  if (!urls.length) {
    return [{ id: 'qr-code', category: 'content', severity: 'info', points: 0, target: { kind: 'tab', tab: 'links' }, title: `Contains a QR code (${where})`, detail: `It decodes to: ${codes[0]!.text.slice(0, 120)}` }];
  }
  return [
    {
      id: 'qr-code',
      category: 'links',
      severity: 'medium',
      points: 10,
      target: { kind: 'tab', tab: 'links' },
      title: urls.length > 1 ? `Contains ${urls.length} QR codes that open websites` : 'Contains a QR code that opens a website',
      detail: `Found in ${where}. It goes to ${hosts.join(', ')}. QR codes move you to your phone, where the real address is easy to miss and email filters can't follow. Check the address on the Links tab before scanning.`,
    },
  ];
}
