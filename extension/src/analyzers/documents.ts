/**
 * Looks inside attachments: links hidden in PDFs and Office files, macros,
 * external templates, embedded objects, and the file list of ZIP archives.
 * Nothing is executed or rendered; files are only parsed as bytes.
 */
import type { AttachmentContents, LinkFlag } from '../core/types';
import { isZip, latin1, pdfSearchText, pdfUris, zipEntries, zipRead } from '../lib/binary';

const RISKY_INSIDE = /\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|wsh|hta|ps1|msi|jar|lnk|cpl|reg|dll|iso|img|vhdx?|html?|svg|one|docm|xlsm|pptm|xll|url|chm|apk|app|dmg)$/i;
const EXECUTABLE_INSIDE = /\.(exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|wsf|wsh|hta|ps1|msi|jar|lnk|cpl|reg|dll|xll|url|chm|apk)$/i;
const ARCHIVE_INSIDE = /\.(zip|rar|7z|gz|tar|iso|img|cab)$/i;

const f = (id: string, severity: LinkFlag['severity'], label: string): LinkFlag => ({ id, severity, label });

function uniqueUrls(urls: string[], max = 200): string[] {
  return [...new Set(urls.map((u) => u.trim()).filter((u) => /^(https?|ftp|file|javascript|data|smb):/i.test(u)))].slice(0, max);
}

async function inspectPdf(bytes: Uint8Array): Promise<{ flags: LinkFlag[]; contents: AttachmentContents }> {
  const text = await pdfSearchText(bytes);
  const links = uniqueUrls(pdfUris(text));
  const flags: LinkFlag[] = [];
  if (/\/(JavaScript|JS)\b/.test(text)) flags.push(f('pdf-javascript', 'high', 'PDF contains JavaScript'));
  if (/\/Launch\b/.test(text)) flags.push(f('pdf-launch', 'critical', 'PDF tries to launch a program'));
  if (/\/EmbeddedFile\b/.test(text)) flags.push(f('pdf-embedded', 'high', 'PDF has files embedded inside it'));
  if (/\/SubmitForm\b/.test(text)) flags.push(f('pdf-submit', 'high', 'PDF has a form that sends what you type to a website'));
  if (links.some((l) => /^(javascript|file|smb):/i.test(l))) flags.push(f('pdf-bad-link', 'high', 'PDF link runs code or opens a network file share'));
  // A one-page "document" whose only content is a big link is the classic credential-phishing PDF.
  const pages = (text.match(/\/Type\s*\/Page\b/g) ?? []).length;
  if (links.length && pages <= 2) flags.push(f('pdf-lure', 'medium', `${pages || 1}-page PDF built around ${links.length === 1 ? 'a link' : `${links.length} links`}: a common way to slip phishing links past filters`));
  return { flags, contents: { kind: 'pdf', links, files: [], macros: false } };
}

async function inspectOoxml(bytes: Uint8Array): Promise<{ flags: LinkFlag[]; contents: AttachmentContents }> {
  const entries = zipEntries(bytes);
  const flags: LinkFlag[] = [];
  const macros = entries.some((e) => /vbaProject\.bin$/i.test(e.name) || /\/macrosheets\//i.test(e.name));
  if (macros) flags.push(f('office-macros', 'high', 'Contains macros (code that can run when you click "Enable content")'));
  if (entries.some((e) => /\/embeddings\/.*\.(bin|exe|ole)$/i.test(e.name) || /oleObject\d*\.bin$/i.test(e.name))) flags.push(f('office-ole', 'medium', 'Contains embedded objects (OLE)'));

  const links: string[] = [];
  let template = false;
  for (const e of entries.filter((x) => /\.rels$/i.test(x.name)).slice(0, 60)) {
    const xml = await zipRead(bytes, e, 1024 * 1024);
    if (!xml) continue;
    const text = new TextDecoder().decode(xml);
    for (const rel of text.matchAll(/<Relationship\b[^>]*>/g)) {
      const tag = rel[0];
      if (!/TargetMode\s*=\s*"External"/i.test(tag)) continue;
      const target = tag.match(/Target\s*=\s*"([^"]+)"/i)?.[1]?.replace(/&amp;/g, '&');
      if (!target) continue;
      if (/attachedTemplate|oleObject|frame|subDocument/i.test(tag) && /^(https?|file|\\\\)/i.test(target)) template = true;
      links.push(target);
    }
  }
  if (template) flags.push(f('office-remote-template', 'critical', 'Loads a template or object from the internet when opened (template injection)'));

  const main = entries.find((e) => /^word\/document\.xml$/i.test(e.name));
  if (main) {
    const xml = await zipRead(bytes, main, 4 * 1024 * 1024);
    if (xml && /DDEAUTO|\bDDE\b\s*"/i.test(new TextDecoder().decode(xml))) flags.push(f('office-dde', 'high', 'Uses DDE fields that can run commands'));
  }
  return { flags, contents: { kind: 'office', links: uniqueUrls(links), files: [], macros } };
}

function inspectOle(bytes: Uint8Array): { flags: LinkFlag[]; contents: AttachmentContents } {
  // Legacy .doc/.xls/.ppt are OLE compound files; the VBA project's stream names appear in UTF-16.
  const text = latin1(bytes, 8_000_000).replace(/\0/g, '');
  const macros = /_VBA_PROJECT|VBA\b.{0,40}(ThisDocument|ThisWorkbook|Module1)|Attribute VB_Name/.test(text);
  const flags = macros ? [f('office-macros', 'high', 'Contains macros (code that can run when you click "Enable content")')] : [];
  return { flags, contents: { kind: 'office', links: uniqueUrls([...text.matchAll(/https?:\/\/[^\s"'<>\0]{4,300}/g)].map((m) => m[0])), files: [], macros } };
}

function inspectRtf(bytes: Uint8Array): { flags: LinkFlag[]; contents: AttachmentContents } {
  const text = latin1(bytes, 8_000_000);
  const flags: LinkFlag[] = [];
  if (/\\object\b|\\objdata\b/.test(text)) flags.push(f('rtf-object', 'high', 'RTF document with an embedded object (used by Office exploits)'));
  const links = [...text.matchAll(/HYPERLINK\s+"([^"]+)"/g)].map((m) => m[1]!);
  return { flags, contents: { kind: 'office', links: uniqueUrls(links), files: [], macros: false } };
}

function inspectZip(bytes: Uint8Array): { flags: LinkFlag[]; contents: AttachmentContents } {
  const entries = zipEntries(bytes).filter((e) => !e.name.endsWith('/'));
  const flags: LinkFlag[] = [];
  const exec = entries.filter((e) => EXECUTABLE_INSIDE.test(e.name));
  const risky = entries.filter((e) => RISKY_INSIDE.test(e.name) && !EXECUTABLE_INSIDE.test(e.name));
  if (exec.length) flags.push(f('zip-executable', 'critical', `Archive contains a program: ${exec.slice(0, 3).map((e) => e.name.split('/').pop()).join(', ')}`));
  if (risky.length) flags.push(f('zip-risky', 'high', `Archive contains risky files: ${risky.slice(0, 3).map((e) => e.name.split('/').pop()).join(', ')}`));
  if (entries.some((e) => ARCHIVE_INSIDE.test(e.name))) flags.push(f('zip-nested', 'medium', 'Archive inside an archive: a trick to get past scanners'));
  const bomb = entries.some((e) => e.compressedSize > 0 && e.size / e.compressedSize > 1000 && e.size > 100_000_000);
  if (bomb) flags.push(f('zip-bomb', 'medium', 'Archive expands to an enormous size (zip bomb)'));
  return {
    flags,
    contents: { kind: 'archive', links: [], macros: false, files: entries.slice(0, 200).map((e) => ({ name: e.name, size: e.size, encrypted: e.encrypted })) },
  };
}

/** Deep inspection by file type. Returns null for types it doesn't look inside. */
export async function inspectContents(bytes: Uint8Array, ext: string, mimeType: string): Promise<{ flags: LinkFlag[]; contents: AttachmentContents } | null> {
  const head = latin1(bytes.subarray(0, 8));
  try {
    if (head.startsWith('%PDF') || ext === 'pdf') return await inspectPdf(bytes);
    if (head.startsWith('{\\rtf')) return inspectRtf(bytes);
    if (bytes[0] === 0xd0 && bytes[1] === 0xcf && bytes[2] === 0x11 && bytes[3] === 0xe0) return inspectOle(bytes);
    if (isZip(bytes)) {
      const names = zipEntries(bytes, 50).map((e) => e.name);
      if (names.includes('[Content_Types].xml')) return await inspectOoxml(bytes);
      return inspectZip(bytes);
    }
    if (/html|svg/.test(mimeType) || /^(html?|xhtml|svg|mhtml?)$/.test(ext)) {
      // DOMParser, not regexes: tag-matching regexes take quadratic time on crafted HTML.
      const doc = new DOMParser().parseFromString(new TextDecoder().decode(bytes.subarray(0, 4_000_000)), 'text/html');
      const forms = Array.from(doc.querySelectorAll('form[action]'), (el) => el.getAttribute('action') ?? '');
      const links = Array.from(doc.querySelectorAll('a[href], area[href], iframe[src], script[src], meta[http-equiv="refresh" i]'), (el) =>
        el.tagName === 'META' ? (el.getAttribute('content') ?? '').replace(/^[^;]*;\s*url\s*=\s*/i, '') : (el.getAttribute('href') ?? el.getAttribute('src') ?? ''),
      );
      return { flags: [], contents: { kind: 'html', links: uniqueUrls([...forms, ...links]), files: [], macros: false } };
    }
  } catch {
    return null;
  }
  return null;
}
