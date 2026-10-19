import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export function fixture(name: string): string {
  return readFileSync(join(__dirname, 'fixtures', name), 'utf8');
}

async function deflateRaw(data: Uint8Array, format: 'deflate' | 'deflate-raw' = 'deflate-raw'): Promise<Uint8Array> {
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new CompressionStream(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Builds a real ZIP (stored or deflated entries) for tests. CRCs are left at 0; the readers don't check them. */
export async function makeZip(files: { name: string; data: Uint8Array; deflate?: boolean }[]): Promise<Uint8Array> {
  const parts: number[] = [];
  const central: number[] = [];
  const le = (n: number, bytes: number) => Array.from({ length: bytes }, (_, i) => (n >>> (8 * i)) & 0xff);
  for (const f of files) {
    const name = [...new TextEncoder().encode(f.name)];
    const body = f.deflate ? await deflateRaw(f.data) : f.data;
    const method = f.deflate ? 8 : 0;
    const offset = parts.length;
    parts.push(...le(0x04034b50, 4), ...le(20, 2), ...le(0, 2), ...le(method, 2), ...le(0, 4), ...le(0, 4), ...le(body.length, 4), ...le(f.data.length, 4), ...le(name.length, 2), ...le(0, 2), ...name, ...body);
    central.push(...le(0x02014b50, 4), ...le(20, 2), ...le(20, 2), ...le(0, 2), ...le(method, 2), ...le(0, 4), ...le(0, 4), ...le(body.length, 4), ...le(f.data.length, 4), ...le(name.length, 2), ...le(0, 2), ...le(0, 2), ...le(0, 2), ...le(0, 2), ...le(0, 4), ...le(offset, 4), ...name);
  }
  const cdOffset = parts.length;
  const eocd = [...le(0x06054b50, 4), ...le(0, 2), ...le(0, 2), ...le(files.length, 2), ...le(files.length, 2), ...le(central.length, 4), ...le(cdOffset, 4), ...le(0, 2)];
  return new Uint8Array([...parts, ...central, ...eocd]);
}

/** A minimal one-page PDF with link annotations; `compressedUris` go in a FlateDecode stream. */
export async function makePdf(opts: { uris?: string[]; compressedUris?: string[]; extra?: string; images?: { width: number; height: number; gray: Uint8Array }[] }): Promise<Uint8Array> {
  const esc = (s: string) => s.replace(/[()\\]/g, '\\$&');
  const chunks: (string | Uint8Array)[] = ['%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n'];
  const annots = (opts.uris ?? []).map((u) => `<< /Type /Annot /Subtype /Link /A << /S /URI /URI (${esc(u)}) >> >>`).join(' ');
  chunks.push(`3 0 obj << /Type /Page /Parent 2 0 R /Annots [${annots}] ${opts.extra ?? ''} >> endobj\n`);
  if (opts.compressedUris?.length) {
    const body = await deflateRaw(new TextEncoder().encode(opts.compressedUris.map((u) => `<< /S /URI /URI (${esc(u)}) >>`).join('\n')), 'deflate');
    chunks.push(`4 0 obj << /Type /ObjStm /Filter /FlateDecode /Length ${body.length} >>\nstream\n`, body, '\nendstream endobj\n');
  }
  let n = 5;
  for (const img of opts.images ?? []) {
    const body = await deflateRaw(img.gray, 'deflate');
    chunks.push(`${n++} 0 obj << /Type /XObject /Subtype /Image /Width ${img.width} /Height ${img.height} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length ${body.length} >>\nstream\n`, body, '\nendstream endobj\n');
  }
  chunks.push('trailer << /Root 1 0 R >>\n%%EOF\n');
  const bytes = chunks.map((c) => (typeof c === 'string' ? new Uint8Array([...c].map((ch) => ch.charCodeAt(0))) : c));
  const out = new Uint8Array(bytes.reduce((n2, b) => n2 + b.length, 0));
  let at = 0;
  for (const b of bytes) {
    out.set(b, at);
    at += b.length;
  }
  return out;
}
