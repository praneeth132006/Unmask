/**
 * Shapes shared by the file-forensics engine. Everything here is plain data
 * (no bytes, no functions), so a report can pass between extension contexts.
 */
import type { Severity } from '../core/types';

/** One suspicious or noteworthy thing found inside a file. */
export interface Anomaly {
  id: string;
  severity: Severity;
  title: string;
  /** Technical detail for analysts: object numbers, offsets, names. */
  detail?: string;
  /** The same thing in everyday words. */
  plain: string;
  /** Where in the file, e.g. "obj 12 0" or "word/_rels/document.xml.rels". */
  where?: string;
  /** MITRE ATT&CK technique id when one clearly applies, e.g. T1204.002. */
  attack?: string;
}

export interface ExtractedLink {
  url: string;
  /** Where in the file it sits, e.g. "link on page 1" or "word/document.xml". */
  where: string;
  /** How it is used: a clickable link, a remote template, an auto-loaded picture… */
  how: 'link' | 'template' | 'resource' | 'action' | 'form' | 'text' | 'macro' | 'decoded';
  /** The link covers most of a page, so the whole page is one big button. */
  coversPage?: boolean;
  /** The visible text people click, when the file has it. */
  label?: string;
}

export interface Iocs {
  urls: string[];
  ips: string[];
  emails: string[];
  domains: string[];
  /** File names and paths that point at programs (.exe, .ps1, cmd.exe …). */
  executables: string[];
  /** Commands seen in macros or scripts: powershell -enc, mshta, certutil … */
  commands: string[];
}

export interface FileHashes {
  sha256: string;
  sha1: string;
  md5: string;
}

export interface PdfIdRow {
  keyword: string;
  count: number;
  /** How many of them were written with #xx escapes to dodge keyword scanners. */
  obfuscated: number;
  /** Extra occurrences found only after decompressing object streams. */
  hiddenInStreams: number;
  /** Why an analyst cares. */
  note: string;
  /** Rows that normally appear in ordinary PDFs are not highlighted. */
  risk: 'normal' | 'watch' | 'danger';
}

export interface PdfEmbedded {
  name: string;
  size: number;
  type: string;
  sha256: string;
}

export interface PdfJavaScript {
  obj: string;
  trigger: string;
  length: number;
  /** The first part of the code, for the analyst. */
  preview: string;
  indicators: string[];
}

export interface PdfAction {
  obj: string;
  trigger: string;
  type: string;
  target?: string;
}

export interface PdfReport {
  header: string;
  version: string | null;
  pages: number;
  objects: number;
  encrypted: boolean;
  /** pdfid-style keyword table. */
  id: PdfIdRow[];
  eofCount: number;
  /** Bytes after the last %%EOF marker: a common place to hide a payload. */
  bytesAfterEof: number;
  entropy: { total: number; insideStreams: number; outsideStreams: number };
  metadata: Record<string, string>;
  javascript: PdfJavaScript[];
  actions: PdfAction[];
  embedded: PdfEmbedded[];
  /** Approximate text on the pages, to see what the lure says. */
  textPreview: string;
  /** Object streams were unpacked to look for hidden keywords. */
  objectStreamsUnpacked: number;
}

export interface VbaModule {
  name: string;
  kind: 'standard' | 'class' | 'document' | 'unknown';
  length: number;
  /** Beginning of the decompressed source. */
  preview: string;
  autoExec: string[];
  suspicious: string[];
  /** Source was long, so only the start was kept. */
  truncated: boolean;
}

export interface MacroReport {
  present: boolean;
  modules: VbaModule[];
  /** Excel 4.0 (XLM) macro sheets, which most scanners do not read. */
  xlmSheets: { name: string; hidden: 'visible' | 'hidden' | 'very-hidden' }[];
  autoExec: string[];
  suspicious: string[];
  /** Counts that hint at obfuscation. */
  obfuscation: { chrCalls: number; longStrings: number; base64Blobs: number };
}

export interface OleStreamInfo {
  path: string;
  size: number;
}

export interface OleReport {
  streams: OleStreamInfo[];
  metadata: Record<string, string>;
  macros: MacroReport;
  /** Embedded files inside the document (Ole10Native, Package). */
  embedded: { name: string; source: string; size: number; type: string; sha256: string }[];
  /** Equation Editor or other exploit-prone object classes. */
  riskyClasses: string[];
}

export interface OfficeField {
  type: string;
  instr: string;
  where: string;
}

export interface OoxmlReport {
  app: 'word' | 'excel' | 'powerpoint' | 'unknown';
  parts: number;
  metadata: Record<string, string>;
  /** Relationships that point outside the file. */
  externalRefs: { part: string; type: string; target: string; mode: string }[];
  fields: OfficeField[];
  macros: MacroReport;
  embedded: { part: string; size: number; type: string }[];
  activeX: number;
  hiddenSheets: string[];
  hiddenSlides: number;
  /** Starts of the visible text, to read what the lure says. */
  textPreview: string;
  /** Phrases such as "Enable Editing" that push people to switch protection off. */
  lurePhrases: string[];
}

export interface RtfReport {
  objects: { cls: string; hexBytes: number; type: string }[];
  templates: string[];
  fields: OfficeField[];
  riskyClasses: string[];
}

export interface ZipReport {
  files: { name: string; size: number; compressed: number; encrypted: boolean; type?: string }[];
}

export interface ChildFile {
  /** Path inside the parent, e.g. "invoice.pdf" or "word/embeddings/oleObject1.bin". */
  path: string;
  forensics: FileForensics;
}

export type FileKind = 'pdf' | 'ooxml' | 'ole' | 'rtf' | 'zip' | 'html' | 'script' | 'image' | 'executable' | 'shortcut' | 'text' | 'other';

export interface FileForensics {
  kind: FileKind;
  /** What the first bytes say the file is, whatever its name claims. */
  magic: { label: string; mime: string | null };
  size: number;
  /** Shannon entropy, 0 to 8 bits per byte. Near 8 means packed or encrypted. */
  entropy: number;
  hashes: FileHashes;
  anomalies: Anomaly[];
  links: ExtractedLink[];
  iocs: Iocs;
  pdf?: PdfReport;
  ooxml?: OoxmlReport;
  ole?: OleReport;
  rtf?: RtfReport;
  zip?: ZipReport;
  /** Files found inside this one and analysed the same way. */
  children: ChildFile[];
  /** The file was larger than the safe reading limit, so only part was analysed. */
  truncated: boolean;
}

export const EMPTY_IOCS = (): Iocs => ({ urls: [], ips: [], emails: [], domains: [], executables: [], commands: [] });
