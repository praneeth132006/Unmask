import type { AttachmentInfo, Finding, LinkFlag, ParsedAttachment, Severity } from '../core/types';

const EXECUTABLE = new Set(['exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'ps1', 'psm1', 'msi', 'msp', 'jar', 'lnk', 'cpl', 'reg', 'appx', 'msix', 'apk', 'dll', 'app', 'command', 'scf', 'url', 'inf', 'xll', 'chm']);
const DISK_IMAGE = new Set(['iso', 'img', 'vhd', 'vhdx', 'dmg']);
const HTML_LIKE = new Set(['html', 'htm', 'shtml', 'xhtml', 'svg', 'mht', 'mhtml', 'xht']);
const MACRO_OFFICE = new Set(['docm', 'dotm', 'xlsm', 'xltm', 'xlsb', 'xlam', 'pptm', 'potm', 'ppam', 'one', 'onepkg']);
const ARCHIVE = new Set(['zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'ace', 'cab', 'arj', 'lzh', 'bz2', 'xz']);
const DOCUMENT = new Set(['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'rtf', 'jpg', 'jpeg', 'png', 'csv', 'odt']);

/** Extension → MIME types we'd expect, to catch "invoice.pdf" that is really HTML. */
const EXPECTED_MIME: Record<string, RegExp> = {
  pdf: /pdf|octet-stream/,
  docx: /officedocument|msword|octet-stream|zip/,
  xlsx: /officedocument|ms-excel|octet-stream|zip/,
  jpg: /image|octet-stream/,
  jpeg: /image|octet-stream/,
  png: /image|octet-stream/,
  txt: /text\/plain|octet-stream/,
};

const BIDI_CONTROL = /[‪-‮⁦-⁩‎‏]/;

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes as BufferSource);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

function extensionOf(filename: string): string {
  const clean = filename.replace(BIDI_CONTROL, '').trim().toLowerCase();
  const dot = clean.lastIndexOf('.');
  return dot >= 0 ? clean.slice(dot + 1) : '';
}

/** ZIP local file headers carry an "encrypted" bit; password-protected archives hide their contents from scanners. */
export function isEncryptedZip(bytes: Uint8Array): boolean {
  if (bytes.length < 30 || bytes[0] !== 0x50 || bytes[1] !== 0x4b || bytes[2] !== 0x03 || bytes[3] !== 0x04) return false;
  return (bytes[6]! & 0x01) === 0x01;
}

function latin1(bytes: Uint8Array, max = 2_000_000): string {
  let s = '';
  const end = Math.min(bytes.length, max);
  for (let i = 0; i < end; i += 8192) s += String.fromCharCode(...bytes.subarray(i, Math.min(i + 8192, end)));
  return s;
}

function f(id: string, severity: Severity, label: string): LinkFlag {
  return { id, severity, label };
}

export async function inspectAttachment(a: ParsedAttachment): Promise<AttachmentInfo> {
  const ext = extensionOf(a.filename);
  const flags: LinkFlag[] = [];
  const inline = a.related || (a.disposition === 'inline' && a.mimeType.startsWith('image/'));

  if (BIDI_CONTROL.test(a.filename)) {
    flags.push(f('bidi', 'critical', 'File name uses hidden right-to-left characters to fake its extension'));
  }
  if (EXECUTABLE.has(ext)) flags.push(f('executable', 'critical', `.${ext} files can run programs on your computer`));
  else if (DISK_IMAGE.has(ext)) flags.push(f('disk-image', 'high', `.${ext} disk images are used to smuggle malware past filters`));
  else if (HTML_LIKE.has(ext)) flags.push(f('html', 'high', `.${ext} attachments often open a fake login page in your browser`));
  else if (MACRO_OFFICE.has(ext)) flags.push(f('macro', 'high', `.${ext} files can contain macros or embedded scripts`));
  else if (ARCHIVE.has(ext)) flags.push(f('archive', 'low', `.${ext} archive: contents could not be checked`));

  // Double extension: "Invoice.pdf.html", "photo.jpg.exe"
  const parts = a.filename.toLowerCase().split('.');
  if (parts.length >= 3 && DOCUMENT.has(parts[parts.length - 2]!) && !DOCUMENT.has(ext)) {
    flags.push(f('double-extension', 'high', `Looks like a .${parts[parts.length - 2]} but is really a .${ext}`));
  }

  const expected = EXPECTED_MIME[ext];
  if (expected && !expected.test(a.mimeType)) {
    flags.push(f('mime-mismatch', 'medium', `Named .${ext} but its content type is ${a.mimeType}`));
  }

  if (ARCHIVE.has(ext) && isEncryptedZip(a.content)) {
    flags.push(f('encrypted-archive', 'high', 'Password-protected archive: hides its contents from virus scanners'));
  }

  if (ext === 'pdf' || a.mimeType === 'application/pdf') {
    const body = latin1(a.content);
    const active = ['/JavaScript', '/JS ', '/Launch', '/EmbeddedFile', '/OpenAction'].filter((k) => body.includes(k));
    if (active.includes('/JavaScript') || active.includes('/Launch') || active.includes('/EmbeddedFile')) {
      flags.push(f('pdf-active', 'high', `PDF contains active content (${active.join(', ')})`));
    }
  }

  if (HTML_LIKE.has(ext) || a.mimeType.includes('html') || a.mimeType.includes('svg')) {
    const body = latin1(a.content).toLowerCase();
    if (body.includes('type="password"') || body.includes("type='password'") || body.includes('type=password')) {
      flags.push(f('html-credential', 'critical', 'Attachment contains a password form'));
    }
    if (/\b(atob|unescape|eval)\s*\(|fromcharcode|document\.write\s*\(/.test(body)) {
      flags.push(f('html-obfuscated', 'high', 'Attachment contains obfuscated JavaScript'));
    }
  }

  return {
    filename: a.filename,
    mimeType: a.mimeType,
    size: a.size,
    sha256: await sha256Hex(a.content),
    extension: ext,
    inline,
    flags,
  };
}

const POINTS: Record<Severity, number> = { good: 0, info: 0, low: 4, medium: 10, high: 22, critical: 35 };

export async function analyzeAttachments(list: ParsedAttachment[]): Promise<{ attachments: AttachmentInfo[]; findings: Finding[] }> {
  const attachments = await Promise.all(list.map(inspectAttachment));
  const findings: Finding[] = [];
  for (const att of attachments) {
    if (!att.flags.length) continue;
    // The worst flag sets the weight; each extra flag adds a little.
    const order: Severity[] = ['critical', 'high', 'medium', 'low'];
    const worst = order.find((s) => att.flags.some((fl) => fl.severity === s)) ?? 'low';
    findings.push({
      id: `attachment-${att.sha256.slice(0, 12)}`,
      category: 'attachments',
      severity: worst,
      points: Math.min(POINTS[worst] + (att.flags.length - 1) * 4, 45),
      title: `Risky attachment: ${att.filename}`,
      detail: att.flags.map((fl) => fl.label).join('; '),
    });
  }
  return { attachments, findings };
}
