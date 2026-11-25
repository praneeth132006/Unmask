/**
 * Apps Script has V8 but no browser APIs. The engine needs a few of them:
 * DOMParser (linkedom, pure JavaScript), TextDecoder, atob/btoa and a SHA
 * digest, which Apps Script's Utilities service provides.
 */

declare const Utilities: {
  newBlob(bytes: number[]): { getDataAsString(charset?: string): string };
  base64Decode(s: string): number[];
  base64Encode(bytes: number[] | string): string;
  computeDigest(alg: unknown, bytes: number[]): number[];
  DigestAlgorithm: { SHA_1: unknown; SHA_256: unknown };
};

const g = globalThis as Record<string, unknown>;
const signed = (u: Uint8Array) => Array.from(u, (b) => (b > 127 ? b - 256 : b));
const unsigned = (a: number[]) => Uint8Array.from(a, (b) => b & 255);

// A minimal Blob: postal-mime collects message parts in Blobs and reads them back with arrayBuffer().
if (!g.Blob) {
  g.Blob = class Blob {
    private readonly bytes: Uint8Array;
    readonly type: string;
    constructor(parts: (ArrayBuffer | ArrayBufferView | string | Blob)[] = [], opts: { type?: string } = {}) {
      const chunks = parts.map((p) =>
        typeof p === 'string' ? new (g.TextEncoder as { new (): { encode(s: string): Uint8Array } })().encode(p)
          : p instanceof Blob ? (p as unknown as { bytes: Uint8Array }).bytes
            : p instanceof ArrayBuffer ? new Uint8Array(p) : new Uint8Array(p.buffer, p.byteOffset, p.byteLength));
      const size = chunks.reduce((n, c) => n + c.length, 0);
      this.bytes = new Uint8Array(size);
      let at = 0;
      for (const c of chunks) { this.bytes.set(c, at); at += c.length; }
      this.type = opts.type ?? '';
    }
    get size() { return this.bytes.length; }
    async arrayBuffer() { return this.bytes.slice().buffer; }
    async text() { return new (g.TextDecoder as { new (): { decode(b: Uint8Array): string } })().decode(this.bytes); }
  };
}
if (!g.TextDecoder) {
  g.TextDecoder = class {
    readonly encoding: string;
    constructor(label = 'utf-8') { this.encoding = label.toLowerCase(); }
    decode(input?: ArrayBuffer | ArrayBufferView): string {
      if (!input) return '';
      const u = input instanceof Uint8Array ? input : ArrayBuffer.isView(input) ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength) : new Uint8Array(input);
      const cs = this.encoding === 'utf8' ? 'UTF-8' : this.encoding;
      try { return Utilities.newBlob(signed(u)).getDataAsString(cs); } catch { return Utilities.newBlob(signed(u)).getDataAsString('ISO-8859-1'); }
    }
  };
}
if (!g.TextEncoder) {
  g.TextEncoder = class {
    encode(s = ''): Uint8Array {
      const out: number[] = [];
      for (const ch of s) {
        let c = ch.codePointAt(0)!;
        if (c < 0x80) out.push(c);
        else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
        else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
        else { c -= 0; out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63)); }
      }
      return Uint8Array.from(out);
    }
  };
}
if (!g.atob) g.atob = (s: string) => String.fromCharCode(...unsigned(Utilities.base64Decode(s)));
if (!g.btoa) g.btoa = (s: string) => Utilities.base64Encode(Array.from(s, (c) => { const n = c.charCodeAt(0); return n > 127 ? n - 256 : n; }));
if (!(g.crypto as { subtle?: unknown } | undefined)?.subtle) {
  g.crypto = {
    getRandomValues: <T extends ArrayBufferView>(a: T) => a,
    subtle: {
      digest: async (alg: string | { name: string }, data: ArrayBuffer | ArrayBufferView) => {
        const name = (typeof alg === 'string' ? alg : alg.name).toUpperCase();
        const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
        const out = Utilities.computeDigest(name === 'SHA-1' ? Utilities.DigestAlgorithm.SHA_1 : Utilities.DigestAlgorithm.SHA_256, signed(bytes));
        return unsigned(out).buffer;
      },
    },
  };
}

export {};
