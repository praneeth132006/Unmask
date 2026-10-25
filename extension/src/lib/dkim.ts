/**
 * DKIM (RFC 6376), done on your computer: parse the signatures, rebuild the
 * exact bytes that were signed, and recompute the body hash. A body hash
 * that doesn't match means the text was changed after it was signed, and
 * that needs no network at all. Checking the signature itself needs the
 * sender's public key from DNS, which `integrations/dkimVerify.ts` fetches.
 */
import type { DkimSignatureInfo } from '../core/types';
import { parseTags, unfold, type RawHeader, type RawMessage } from './rawMessage';

export interface DkimSignature extends DkimSignatureInfo {
  /** The parsed tags, for the online check. */
  tags: Record<string, string>;
  header: RawHeader;
}

export const toBytes = (binary: string): Uint8Array => Uint8Array.from(binary, (c) => c.charCodeAt(0) & 0xff);

function base64(bytes: ArrayBuffer): string {
  let s = '';
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}

export function canonicalizeBody(body: string, mode: 'simple' | 'relaxed'): string {
  let lines = body.split('\r\n');
  if (mode === 'relaxed') lines = lines.map((l) => l.replace(/[ \t]+/g, ' ').replace(/ $/, ''));
  // Both modes ignore empty lines at the end.
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  if (!lines.length) return mode === 'simple' ? '\r\n' : '';
  return `${lines.join('\r\n')}\r\n`;
}

export function canonicalizeHeader(h: RawHeader, mode: 'simple' | 'relaxed'): string {
  if (mode === 'simple') return h.raw;
  return `${h.key}:${unfold(h.rawValue).replace(/\r\n/g, '').replace(/[ \t]+/g, ' ').trim()}`;
}

/**
 * The headers a signature covers, in h= order. Each name takes the next
 * instance from the bottom; names with no instance left contribute nothing
 * (that's how senders "oversign" to block added copies).
 */
export function selectSignedHeaders(headers: RawHeader[], signed: string[]): RawHeader[] {
  const used = new Set<RawHeader>();
  const out: RawHeader[] = [];
  for (const name of signed) {
    for (let i = headers.length - 1; i >= 0; i--) {
      const h = headers[i]!;
      if (h.key === name && !used.has(h)) {
        used.add(h);
        out.push(h);
        break;
      }
    }
  }
  return out;
}

/** The exact text the signature was computed over (RFC 6376 §3.7), as a binary string. */
export function signedData(msg: RawMessage, sig: DkimSignature): string {
  const mode = sig.canonicalization.split('/')[0] === 'relaxed' ? 'relaxed' : 'simple';
  const parts = selectSignedHeaders(msg.headers.filter((h) => h !== sig.header), sig.signedHeaders).map((h) => `${canonicalizeHeader(h, mode)}\r\n`);
  // The signature header itself, with an empty b= value and no final CRLF.
  const raw = sig.header.raw.replace(/((?:^|;)[ \t\r\n]*b[ \t\r\n]*=)[^;]*/i, '$1');
  const self: RawHeader = { ...sig.header, raw, rawValue: raw.slice(raw.indexOf(':') + 1) };
  return parts.join('') + canonicalizeHeader(self, mode);
}

const seconds = (v: string | undefined) => (v && /^\d+$/.test(v) ? Number(v) * 1000 : null);

export async function hashBody(body: string, sig: Pick<DkimSignature, 'canonicalization' | 'bodyLength' | 'algorithm'>): Promise<string> {
  const mode = sig.canonicalization.split('/')[1] === 'relaxed' ? 'relaxed' : 'simple';
  let canon = canonicalizeBody(body, mode);
  if (sig.bodyLength !== null) canon = canon.slice(0, sig.bodyLength);
  const algo = sig.algorithm.endsWith('sha1') ? 'SHA-1' : 'SHA-256';
  return base64(await crypto.subtle.digest(algo, toBytes(canon) as BufferSource));
}

/** Every DKIM-Signature, with the local body-hash check done. */
export async function readDkimSignatures(msg: RawMessage): Promise<DkimSignature[]> {
  const out: DkimSignature[] = [];
  for (const header of msg.headers.filter((h) => h.key === 'dkim-signature')) {
    const tags = parseTags(header.rawValue);
    if (!tags.d || !tags.b || !tags.bh) continue;
    const c = (tags.c ?? 'simple/simple').toLowerCase();
    const sig: DkimSignature = {
      header,
      tags,
      domain: tags.d.toLowerCase(),
      selector: (tags.s ?? '').toLowerCase(),
      algorithm: (tags.a ?? 'rsa-sha256').toLowerCase(),
      signedHeaders: (tags.h ?? '').toLowerCase().split(':').map((s) => s.trim()).filter(Boolean),
      canonicalization: c.includes('/') ? c : `${c}/simple`,
      bodyLength: tags.l && /^\d+$/.test(tags.l) ? Number(tags.l) : null,
      signedAt: seconds(tags.t),
      expiresAt: seconds(tags.x),
      bodyHash: 'unsupported',
    };
    if (/sha(1|256)$/.test(sig.algorithm)) {
      try {
        sig.bodyHash = (await hashBody(msg.body, sig)) === tags.bh ? 'match' : 'mismatch';
      } catch {
        sig.bodyHash = 'unsupported';
      }
    }
    out.push(sig);
  }
  return out;
}

/** The public info for the report, without the raw header. */
export function publicInfo(sig: DkimSignature): DkimSignatureInfo {
  const { header: _h, tags: _t, ...info } = sig;
  return info;
}
