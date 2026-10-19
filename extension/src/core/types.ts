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
  headers: { key: string; value: string }[];
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
  source: 'html' | 'text';
  flags: LinkFlag[];
}

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
}

export interface TrackerReport {
  pixels: TrackerPixel[];
  trackedLinkCount: number;
  services: string[];
  remoteImages: number;
}

export type Verdict = 'clear' | 'suspicious' | 'high';

export interface Report {
  email: ParsedEmail;
  auth: AuthSummary;
  links: LinkInfo[];
  attachments: AttachmentInfo[];
  hidden: HiddenSnippet[];
  trackers: TrackerReport;
  /** Body HTML with hidden elements tagged (data-unmask-hidden) for the "reveal" view. */
  annotatedHtml: string | null;
  findings: Finding[];
  score: number;
  verdict: Verdict;
}
