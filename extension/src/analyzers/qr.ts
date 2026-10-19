/**
 * QR-code phishing ("quishing"): a QR code in an image or PDF sends you to a
 * site on your phone, where the address is hard to check and desktop filters
 * never saw the link. Unmask decodes QR codes in the email's own images
 * (attachments, inline images, data: images, images inside PDFs) and puts
 * every decoded link through the normal link checks. Remote images are not
 * downloaded: that would tell the sender you opened the email.
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
