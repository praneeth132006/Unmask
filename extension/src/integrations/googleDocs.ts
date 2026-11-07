/**
 * Phishing often hides in a shared Google Doc, Sheet, Slides file or Drive
 * file: the link is on google.com, so it looks safe, but the page inside is
 * attacker-made. For a file shared with "anyone with the link", Google offers
 * a download in Office format. Unmask fetches that copy anonymously (no
 * cookies, not signed in as you), reads it like any attachment, and never
 * opens or runs it. A private file simply cannot be read.
 */
export type GoogleDocKind = 'document' | 'spreadsheet' | 'presentation' | 'drive-file';

export interface GoogleDocRef {
  kind: GoogleDocKind;
  id: string;
  /** The link as it appeared in the email. */
  url: string;
  /** Where the Office-format copy can be downloaded. */
  exportUrl: string;
  fileName: string;
  label: string;
}

export const GOOGLE_DOC_ORIGINS = ['https://docs.google.com/*', 'https://drive.google.com/*'];

const ID = '[A-Za-z0-9_-]{20,}';

export function googleDocRef(url: string): GoogleDocRef | null {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase();
  if (host === 'docs.google.com') {
    const m = u.pathname.match(new RegExp(`^/(document|spreadsheets|presentation)/(?:u/\\d+/)?d/(${ID})`));
    if (!m) return null;
    const id = m[2]!;
    if (m[1] === 'document') return { kind: 'document', id, url, exportUrl: `https://docs.google.com/document/d/${id}/export?format=docx`, fileName: `google-doc-${id.slice(0, 8)}.docx`, label: 'Google Doc' };
    if (m[1] === 'spreadsheets') return { kind: 'spreadsheet', id, url, exportUrl: `https://docs.google.com/spreadsheets/d/${id}/export?format=xlsx`, fileName: `google-sheet-${id.slice(0, 8)}.xlsx`, label: 'Google Sheet' };
    return { kind: 'presentation', id, url, exportUrl: `https://docs.google.com/presentation/d/${id}/export/pptx`, fileName: `google-slides-${id.slice(0, 8)}.pptx`, label: 'Google Slides' };
  }
  if (host === 'drive.google.com') {
    const id = u.pathname.match(new RegExp(`^/file/(?:u/\\d+/)?d/(${ID})`))?.[1] ?? u.searchParams.get('id')?.match(new RegExp(`^${ID}$`))?.[0];
    if (!id) return null;
    return { kind: 'drive-file', id, url, exportUrl: `https://drive.google.com/uc?export=download&id=${id}`, fileName: `google-drive-${id.slice(0, 8)}`, label: 'Google Drive file' };
  }
  return null;
}

/** Every distinct Google file link among a list of URLs. */
export function googleDocLinks(urls: string[]): GoogleDocRef[] {
  const seen = new Set<string>();
  const out: GoogleDocRef[] = [];
  for (const url of urls) {
    const r = googleDocRef(url);
    if (r && !seen.has(r.id)) {
      seen.add(r.id);
      out.push(r);
    }
  }
  return out;
}

export const MAX_GOOGLE_FILE = 15 * 1024 * 1024;

export class PrivateGoogleFile extends Error {}

/** Downloads the Office-format copy anonymously. Throws PrivateGoogleFile when it needs a sign-in. */
export async function fetchGoogleFile(ref: GoogleDocRef, fetchFn: typeof fetch = fetch): Promise<Uint8Array> {
  const res = await fetchFn(ref.exportUrl, { credentials: 'omit', redirect: 'follow', referrerPolicy: 'no-referrer' });
  if (res.status === 401 || res.status === 403 || res.status === 404) throw new PrivateGoogleFile(`Google says this ${ref.label.toLowerCase()} is private or gone (HTTP ${res.status}). Unmask can only read files shared with “anyone with the link”. A private file also means the sender can change it later.`);
  if (!res.ok) throw new Error(`Google answered HTTP ${res.status}.`);
  const type = res.headers.get('content-type') ?? '';
  const declared = Number(res.headers.get('content-length') ?? 0);
  if (declared > MAX_GOOGLE_FILE) throw new Error(`This file is ${(declared / 1048576).toFixed(0)} MB, over the 15 MB limit Unmask reads.`);
  const buf = new Uint8Array(await res.arrayBuffer());
  if (buf.length > MAX_GOOGLE_FILE) throw new Error('This file is over the 15 MB limit Unmask reads.');
  if (/text\/html/i.test(type) || (buf[0] === 0x3c && /<html|<!doctype/i.test(new TextDecoder().decode(buf.subarray(0, 300))))) {
    const head = new TextDecoder().decode(buf.subarray(0, 6000));
    if (/ServiceLogin|accounts\.google\.com|Sign in/i.test(head)) throw new PrivateGoogleFile(`This ${ref.label.toLowerCase()} needs a Google sign-in, so it is not shared publicly. Unmask can only read files shared with “anyone with the link”.`);
    if (/virus scan|too large|can’t scan|can't scan/i.test(head)) throw new Error('Google could not offer this file for direct download (too large to scan). Open it carefully in a private window instead.');
    throw new Error('Google returned a web page instead of the file, so there is nothing to analyse.');
  }
  return buf;
}
