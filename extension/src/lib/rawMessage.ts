/**
 * The email exactly as it was sent, byte for byte, for the checks that need
 * more than the parsed fields: DKIM body hashes and signatures, ARC, and the
 * order of the headers. postal-mime decodes and reorders; this doesn't.
 *
 * Text is kept as a "binary string" (one char per byte, latin1), so hashing
 * it later gives the hash of the original bytes.
 */

export interface RawHeader {
  /** Field name as written, e.g. "DKIM-Signature". */
  name: string;
  /** Lowercase name for lookups. */
  key: string;
  /** The whole field as sent, folding included, without the final CRLF: "DKIM-Signature: v=1;\r\n\ta=…". */
  raw: string;
  /** Everything after the colon, folding included. */
  rawValue: string;
}

export interface RawMessage {
  /** In the order they appear: the most recent (added by the last server) first. */
  headers: RawHeader[];
  /** Body after the blank line, CRLF line endings. */
  body: string;
  /** Line endings had to be rebuilt (the source used bare LF), so signatures may not verify. */
  rebuiltLineEndings: boolean;
}

function toBinaryString(raw: string | ArrayBuffer | Uint8Array): string {
  const bytes = typeof raw === 'string' ? new TextEncoder().encode(raw) : raw instanceof Uint8Array ? raw : new Uint8Array(raw);
  let out = '';
  for (let i = 0; i < bytes.length; i += 0x8000) out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return out;
}

/**
 * Splits a raw message into header fields and body. Gmail's "Show original"
 * and copy/paste often drop the CR of CRLF; those line endings are rebuilt,
 * which is what the message had on the wire in almost every case.
 */
export function splitRawMessage(raw: string | ArrayBuffer | Uint8Array): RawMessage {
  let text = toBinaryString(raw);
  const rebuiltLineEndings = /(^|[^\r])\n/.test(text);
  if (rebuiltLineEndings) text = text.replace(/\r?\n/g, '\r\n');
  // A leading "From " mbox line is not part of the message.
  text = text.replace(/^From [^\r\n]*\r\n/, '');
  const end = text.indexOf('\r\n\r\n');
  const head = end >= 0 ? text.slice(0, end + 2) : text;
  const body = end >= 0 ? text.slice(end + 4) : '';

  const headers: RawHeader[] = [];
  for (const line of head.split(/\r\n/)) {
    if (!line) continue;
    const last = headers[headers.length - 1];
    if (/^[ \t]/.test(line) && last) {
      last.raw += `\r\n${line}`;
      last.rawValue += `\r\n${line}`;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim();
    headers.push({ name, key: name.toLowerCase(), raw: line, rawValue: line.slice(colon + 1) });
  }
  return { headers, body, rebuiltLineEndings };
}

/** A header's value with folding removed and outer whitespace trimmed. */
export function unfold(value: string): string {
  return value.replace(/\r?\n(?=[ \t])/g, '').trim();
}

/** Removes RFC 5322 (parenthesised) comments, which may nest. */
export function stripComments(value: string): string {
  let out = '';
  let depth = 0;
  for (const ch of value) {
    if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    else if (depth === 0) out += ch;
  }
  return out;
}

/** Parses "a=1; b=2" tag lists (DKIM, ARC). Whitespace inside values is removed. */
export function parseTags(value: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of unfold(value).split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const k = part.slice(0, eq).trim().toLowerCase();
    if (k && !(k in tags)) tags[k] = part.slice(eq + 1).replace(/\s+/g, '');
  }
  return tags;
}
