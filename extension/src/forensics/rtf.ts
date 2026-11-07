/**
 * Rich Text Format documents. Attackers hide exploit objects in \objdata hex
 * blocks (often padded with junk so scanners miss them) and load remote
 * templates. This reads the same things as Didier Stevens' rtfdump.py.
 */
import { extractIocs } from './ioc';
import { parseCfb } from './ole';
import { EMPTY_IOCS, type Anomaly, type ExtractedLink, type Iocs, type OfficeField, type RtfReport } from './types';
import { sniff } from './util';
import { latin1 } from '../lib/binary';

export interface RtfAnalysis {
  report: RtfReport;
  anomalies: Anomaly[];
  links: ExtractedLink[];
  iocs: Iocs;
  embeddedFiles: { name: string; bytes: Uint8Array }[];
}

/** Hex digits only; Word ignores the junk characters attackers sprinkle in. */
function hexBytes(s: string, max = 8 * 1024 * 1024): Uint8Array {
  const clean = s.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(Math.min(clean.length >> 1, max));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function analyzeRtf(bytes: Uint8Array): RtfAnalysis {
  const text = latin1(bytes, 12_000_000);
  const anomalies: Anomaly[] = [];
  const add = (a: Anomaly) => { if (!anomalies.some((x) => x.id === a.id)) anomalies.push(a); };
  const links: ExtractedLink[] = [];
  const fields: OfficeField[] = [];
  const objects: RtfReport['objects'] = [];
  const riskyClasses: string[] = [];
  const embeddedFiles: { name: string; bytes: Uint8Array }[] = [];

  for (const m of text.matchAll(/\\objclass\s+([^\\{}\s]{1,60})|\{\\\*?\\objdata\s*([^}]{16,})\}/g)) {
    if (m[1]) { riskyClasses.push(m[1]); continue; }
    const data = hexBytes(m[2]!);
    // The OLE1 wrapper: version, format id, class name, then the data.
    const cls = latin1(data.subarray(0, 120)).match(/[A-Za-z][A-Za-z0-9.]{3,40}/)?.[0] ?? '';
    const inner = data.subarray(Math.max(0, data.findIndex((_, i) => data[i] === 0xd0 && data[i + 1] === 0xcf && data[i + 2] === 0x11 && data[i + 3] === 0xe0)));
    const type = sniff(inner.length > 8 ? inner : data).label;
    objects.push({ cls, hexBytes: data.length, type });
    if (embeddedFiles.length < 4 && data.length > 32) embeddedFiles.push({ name: `objdata-${objects.length}`, bytes: data });
    const cfb = parseCfb(inner);
    if (cfb?.entries.some((e) => /Equation Native/i.test(e.path))) riskyClasses.push('Equation.3');
    if (/MZ/.test(latin1(data.subarray(0, 4096)).slice(0, 4096)) && data.length > 100) riskyClasses.push('embedded program');
  }
  if (/\\objdata\b/.test(text) && !objects.length) objects.push({ cls: '', hexBytes: 0, type: 'object data (could not be decoded)' });

  const templates = [...text.matchAll(/\{\\\*\\template\s+([^}]{1,500})\}/g)].map((m) => m[1]!.trim());
  for (const t of templates) links.push({ url: t, where: 'RTF \\template (remote template)', how: 'template' });
  for (const m of text.matchAll(/\\fldinst\s*\{?\s*([A-Za-z]+)\s+([^}]{1,500})\}/g)) {
    const type = m[1]!.toUpperCase();
    const instr = `${type} ${m[2]!.trim()}`;
    if (fields.length < 40) fields.push({ type, instr: instr.slice(0, 300), where: 'RTF' });
    const url = m[2]!.match(/"?((?:https?|ftp|file):\/\/[^\s"}]+)/i)?.[1];
    if (url) links.push({ url, where: `RTF ${type} field`, how: type === 'HYPERLINK' ? 'link' : 'resource' });
  }
  const found = extractIocs(text.replace(/\\[a-z]+-?\d* ?/g, ' ').slice(0, 4_000_000), { decode: false });
  for (const u of found.iocs.urls) if (!links.some((l) => l.url === u)) links.push({ url: u, where: 'text inside the file', how: 'text' });

  if (objects.length) {
    const exploit = riskyClasses.some((c) => /Equation/i.test(c)) || riskyClasses.includes('embedded program');
    add({ id: 'rtf-object', severity: exploit ? 'critical' : 'high', title: `RTF document with ${objects.length} embedded object${objects.length > 1 ? 's' : ''}${exploit ? ' (exploit pattern)' : ''}`, detail: objects.map((o) => `${o.cls || 'object'} (${o.type}, ${o.hexBytes} bytes)`).join('; '), plain: exploit ? 'This document carries an object of the kind used to run attacker code with no click.' : 'This document carries embedded objects, which Office exploits are delivered in.', attack: 'T1203' });
  }
  if (templates.length) add({ id: 'rtf-template', severity: 'critical', title: 'RTF loads a template from the internet', detail: templates[0], plain: 'This document fetches a file from another server when opened.', attack: 'T1221' });
  if (/\\objupdate\b/.test(text)) add({ id: 'rtf-objupdate', severity: 'high', title: 'Objects update automatically when opened', plain: 'An embedded object is set to run as soon as the document opens.', attack: 'T1203' });
  const depth = Math.max(...[...text.slice(0, 2_000_000).matchAll(/\{+/g)].map((m) => m[0].length), 0);
  if (depth > 40) add({ id: 'rtf-nesting', severity: 'medium', title: `Unusually deep nesting (${depth} levels)`, plain: 'Deeply nested braces are used to confuse scanners and trigger parser bugs.', attack: 'T1027' });
  const junkHex = [...text.matchAll(/\\objdata\s*([^}]{64,})\}/g)].some((m) => /[^0-9a-fA-F\s]/.test(m[1]!.slice(0, 4000)));
  if (junkHex) add({ id: 'rtf-hex-junk', severity: 'high', title: 'Object data padded with junk characters', plain: 'Extra characters were mixed into the hidden object so scanners fail to read it, while Word still does.', attack: 'T1027' });

  return { report: { objects, templates, fields, riskyClasses: [...new Set(riskyClasses)] }, anomalies, links, iocs: { ...EMPTY_IOCS(), ...found.iocs }, embeddedFiles };
}
