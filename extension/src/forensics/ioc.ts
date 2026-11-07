/**
 * Pulls indicators of compromise out of text: links, addresses, program
 * names and commands, plus anything hidden in base64. The same idea as
 * Didier Stevens' re-search.py and base64dump.py.
 */
import { sniff } from './util';
import { EMPTY_IOCS, type Iocs } from './types';

const URL_RE = /\b(?:(?:https?|ftp|sftp|smb|file):\/\/|hxxps?:\/\/)[^\s"'<>\\^`{}|)\]]{3,2000}/gi;
const UNC_RE = /\\\\[A-Za-z0-9_.\-]{2,}\\[A-Za-z0-9_.$\-\\]{1,200}/g;
const IPV4_RE = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])/g;
const EMAIL_RE = /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,200}\.[A-Za-z]{2,24}\b/g;
const EXEC_RE = /[A-Za-z0-9_\-./\\:%$~]{1,160}\.(?:exe|dll|scr|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|msi|jar|lnk|com|pif|cpl|sys)\b/gi;
const CMD_RE = /\b(?:powershell(?:\.exe)?|pwsh|cmd(?:\.exe)?\s*\/[ck]|mshta|certutil|bitsadmin|regsvr32|rundll32|wscript|cscript|curl|wget|schtasks|msiexec)\b[^\r\n]{0,180}/gi;
const B64_RE = /[A-Za-z0-9+/]{60,}={0,2}/g;

const PRIVATE_IP = /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|22[4-9]\.|2[3-5]\d\.)/;

export const isPrivateIp = (ip: string): boolean => PRIVATE_IP.test(ip);

const clean = (u: string) => u.replace(/^hxxp/i, 'http').replace(/[.,;:!?'")\]]+$/, '');

function add(set: Set<string>, value: string, max: number) {
  if (set.size < max && value) set.add(value);
}

function b64Bytes(s: string): Uint8Array | null {
  try {
    const bin = atob(s.replace(/=+$/, '').padEnd(Math.ceil(s.replace(/=+$/, '').length / 4) * 4, '='));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

export interface DecodedBlob {
  /** What the decoded bytes look like, e.g. "Windows program (PE)" or "text". */
  label: string;
  /** Up to 160 printable characters of it. */
  preview: string;
  length: number;
}

export interface IocResult {
  iocs: Iocs;
  decoded: DecodedBlob[];
}

/** Extracts indicators from `text`. Base64 blobs are decoded once and searched too. */
export function extractIocs(text: string, opts: { decode?: boolean; max?: number } = {}): IocResult {
  const max = opts.max ?? 200;
  const urls = new Set<string>(), ips = new Set<string>(), emails = new Set<string>(), domains = new Set<string>(), exes = new Set<string>(), cmds = new Set<string>();
  const decoded: DecodedBlob[] = [];

  const scan = (t: string) => {
    for (const m of t.matchAll(URL_RE)) add(urls, clean(m[0]), max);
    for (const m of t.matchAll(UNC_RE)) add(urls, m[0], max);
    for (const m of t.matchAll(IPV4_RE)) add(ips, m[0], max);
    for (const m of t.matchAll(EMAIL_RE)) add(emails, m[0].toLowerCase(), max);
    for (const m of t.matchAll(EXEC_RE)) add(exes, m[0], max);
    for (const m of t.matchAll(CMD_RE)) add(cmds, m[0].trim(), max);
  };
  scan(text);

  if (opts.decode !== false) {
    let n = 0;
    for (const m of text.matchAll(B64_RE)) {
      if (n++ >= 20) break;
      const bytes = b64Bytes(m[0]);
      if (!bytes || bytes.length < 24) continue;
      const magic = sniff(bytes);
      const asText = bytes.subarray(0, 4000);
      const printable = asText.filter((c) => (c >= 32 && c < 127) || c === 9 || c === 10 || c === 13).length / asText.length;
      // PowerShell -EncodedCommand is UTF-16LE: every second byte is zero.
      const utf16 = asText.length > 8 && asText.filter((c, i) => i % 2 === 1 && c === 0).length > asText.length / 2 - 2;
      if (magic.kind === 'other' && printable < 0.9 && !utf16) continue;
      const str = utf16 ? new TextDecoder('utf-16le').decode(asText) : String.fromCharCode(...asText.subarray(0, 600));
      if (magic.kind === 'other') scan(str);
      decoded.push({ label: magic.kind === 'other' ? (utf16 ? 'text (UTF-16, as PowerShell encodes commands)' : 'text') : magic.label, preview: str.replace(/[^\x20-\x7e]/g, '.').slice(0, 160), length: bytes.length });
    }
  }

  for (const u of urls) {
    const host = u.match(/^[a-z]+:\/\/(?:[^/@]*@)?([^/:?#]+)/i)?.[1]?.toLowerCase();
    if (host && !/^\d+\.\d+\.\d+\.\d+$/.test(host) && host.includes('.')) add(domains, host, max);
  }
  return { iocs: { ...EMPTY_IOCS(), urls: [...urls], ips: [...ips], emails: [...emails], domains: [...domains], executables: [...exes], commands: [...cmds] }, decoded };
}

/** Merges several IOC sets into one, without duplicates. */
export function mergeIocs(...sets: Iocs[]): Iocs {
  const out = EMPTY_IOCS();
  for (const key of Object.keys(out) as (keyof Iocs)[]) out[key] = [...new Set(sets.flatMap((s) => s[key]))].slice(0, 300);
  return out;
}
