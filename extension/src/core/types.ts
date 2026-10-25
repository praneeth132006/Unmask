export type Severity = 'good' | 'info' | 'low' | 'medium' | 'high' | 'critical';

export type Category = 'auth' | 'sender' | 'content' | 'links' | 'attachments' | 'privacy';

export type TabId = 'overview' | 'sender' | 'links' | 'attachments' | 'body' | 'headers' | 'privacy';

/** What part of the email a finding is about, so the UI can point at it. */
export type FindingTarget =
  | { kind: 'links'; indexes: number[] }
  | { kind: 'attachment'; sha256: string }
  | { kind: 'sender' }
  | { kind: 'header'; key: string }
  | { kind: 'hidden' }
  | { kind: 'body' }
  /** Phrases to find and mark in the email text. */
  | { kind: 'text'; phrases: string[] }
  | { kind: 'tab'; tab: TabId };

/** A single observation about the email. Points feed the risk score; reasons are shown to the user. */
export interface Finding {
  id: string;
  category: Category;
  severity: Severity;
  /** Contribution to the risk score. Negative for reassuring signals. */
  points: number;
  title: string;
  detail?: string;
  /** The same point in everyday words, for the plain-language summary. */
  plain?: string;
  target?: FindingTarget;
}

export interface Mailbox {
  name: string;
  address: string;
  /** Lowercased domain part of the address, '' if missing. */
  domain: string;
}

export interface ParsedAttachment {
  filename: string;
  mimeType: string;
  size: number;
  disposition: string | null;
  contentId?: string;
  /** Inline images referenced from the HTML body. */
  related: boolean;
  content: Uint8Array;
}

export interface ParsedEmail {
  /** key is lowercase for lookups; name keeps the original capitalisation. */
  headers: { key: string; name: string; value: string }[];
  from: Mailbox | null;
  sender: Mailbox | null;
  replyTo: Mailbox[];
  returnPath: string | null;
  to: Mailbox[];
  subject: string;
  date: string | null;
  messageId: string | null;
  html: string | null;
  text: string | null;
  attachments: ParsedAttachment[];
}

export type AuthResult = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror' | 'policy' | 'unknown';

export interface AuthSummary {
  /** authserv-id of the header used, e.g. mx.google.com. */
  server: string | null;
  spf: AuthResult;
  spfDomain: string | null;
  dkim: AuthResult;
  /** All domains (header.d / header.i) with a passing DKIM signature. */
  dkimDomains: string[];
  dmarc: AuthResult;
  dmarcDomain: string | null;
  raw: string | null;
}

export interface LinkInfo {
  /** The href exactly as it appears in the email. */
  href: string;
  /** Visible text (or alt text for image links). */
  text: string;
  /** Destination after unwrapping known redirect/safe-link wrappers locally. */
  resolved: string;
  /** Wrapper services peeled off while resolving, e.g. "Google redirect". */
  unwrappedVia: string[];
  host: string;
  /** Registrable domain (eTLD+1) of the resolved URL. */
  domain: string;
  scheme: string;
  source: LinkSource;
  /** Where a link outside the body came from, e.g. "invoice.pdf" or "QR code in scan.png". */
  origin?: string;
  flags: LinkFlag[];
}

/** html/text: the email body. attachment: inside a PDF, Office file or HTML file. qr: decoded from a QR code. */
export type LinkSource = 'html' | 'text' | 'attachment' | 'qr';

export interface LinkFlag {
  id: string;
  severity: Severity;
  label: string;
}

export interface AttachmentInfo {
  filename: string;
  mimeType: string;
  size: number;
  sha256: string;
  extension: string;
  inline: boolean;
  flags: LinkFlag[];
  /** What Unmask found inside the file, for the types it can read. */
  contents?: AttachmentContents;
}

export interface AttachmentContents {
  kind: 'pdf' | 'office' | 'archive' | 'html';
  /** Links found inside the file. */
  links: string[];
  /** Files inside an archive. */
  files: { name: string; size: number; encrypted: boolean }[];
  macros: boolean;
}

export interface HiddenSnippet {
  reason: string;
  text: string;
}

export interface TrackerPixel {
  src: string;
  host: string;
  /** Known tracking service, e.g. "Mailchimp", or null if unknown. */
  service: string | null;
  reason: string;
  /** 1-based number, also set on the element as data-unmask-pixel in the annotated HTML. */
  n: number;
  /** Where it is: the Nth image of the email (0 for a CSS background pixel). */
  imageIndex: number;
  imageCount: number;
  /** How far through the email's visible text it sits, 0-100 (hidden text is not counted). */
  positionPct: number;
  /** Visible text just before and after it, so you can find the spot. */
  before: string;
  after: string;
  /** Size from its attributes or style, e.g. "1×1", or null if not given. */
  size: string | null;
  kind: 'img' | 'background';
  /** Inside an element hidden from view (display:none and similar). */
  inHiddenBlock: boolean;
}

export interface TrackerReport {
  pixels: TrackerPixel[];
  trackedLinkCount: number;
  services: string[];
  remoteImages: number;
}

export type Verdict = 'clear' | 'suspicious' | 'high';

export interface QrCode {
  /** Where the code was found, e.g. "scan-me.png" or "image in invoice.pdf". */
  origin: string;
  text: string;
}

/** One server-to-server handoff, from a Received header. */
export interface DeliveryHop {
  /** 1 is where the email started, the highest number is your inbox. */
  n: number;
  /** Name the sending server announced (HELO), or null. */
  helo: string | null;
  /** Name the receiving server found for the sender's IP (reverse DNS), "unknown" if none. */
  rdns: string | null;
  ip: string | null;
  privateIp: boolean;
  by: string | null;
  protocol: string | null;
  /** Epoch ms of the receipt, or null when missing or unreadable. */
  time: number | null;
  /** Seconds since the previous hop; negative when the clocks run backwards. */
  delaySec: number | null;
  /**
   * Written by your own mail provider, so it can be trusted. Hops below the
   * first trusted one were written by servers you can't check, including
   * possibly the sender itself.
   */
  trusted: boolean;
}

export interface DkimSignatureInfo {
  /** Signing domain (d=). */
  domain: string;
  selector: string;
  algorithm: string;
  /** Header fields the signature covers (h=), lowercase. */
  signedHeaders: string[];
  canonicalization: string;
  /** Signed only the first N bytes of the body (l=), or null for the whole body. */
  bodyLength: number | null;
  /** Signing time (t=) and expiry (x=), epoch ms. */
  signedAt: number | null;
  expiresAt: number | null;
  /** Local body-hash check: does the body still match what was signed? */
  bodyHash: 'match' | 'mismatch' | 'unsupported';
  /** Full cryptographic check, filled in by the online DKIM check. */
  signature?: 'pass' | 'fail' | 'no-key' | 'revoked' | 'unsupported' | 'error';
  /** Key size in bits and test mode (t=y), from the DNS key record. */
  keyBits?: number;
  testing?: boolean;
  /** Short reason when the signature check didn't pass. */
  reason?: string;
}

export interface ArcSet {
  instance: number;
  /** cv= from the ARC-Seal: the chain status that server saw. */
  cv: string;
  /** Who added this set (d= of the seal). */
  domain: string;
  /** The Authentication-Results that server recorded (ARC-Authentication-Results), parsed. */
  results: Record<string, string>;
}

export interface Forensics {
  hops: DeliveryHop[];
  /** Public IP of the first server that sent the email, when known. */
  originIp: string | null;
  dkim: DkimSignatureInfo[];
  arc: ArcSet[];
  /** ARC chain problem, if any: missing instances, a broken seal status, … */
  arcProblem: string | null;
  /** Who runs the server that handed the email to your provider, from the optional online check. */
  sender?: { ip: string; ptr: string | null; confirmed: boolean; asn: string | null; network: string | null; country: string | null };
}

export interface Report {
  email: ParsedEmail;
  auth: AuthSummary;
  forensics: Forensics;
  links: LinkInfo[];
  attachments: AttachmentInfo[];
  hidden: HiddenSnippet[];
  trackers: TrackerReport;
  /** The first few hundred characters of visible text, for previews that never render the email. */
  previewText: string;
  /** QR codes decoded from the email's images and PDFs. */
  qrCodes: QrCode[];
  /** Body HTML with hidden elements tagged (data-unmask-hidden) for the "reveal" view. */
  annotatedHtml: string | null;
  findings: Finding[];
  score: number;
  verdict: Verdict;
}
