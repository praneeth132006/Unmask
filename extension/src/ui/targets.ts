import type { AttachmentInfo, FindingTarget, Report, TabId } from '../core/types';
import type { HighlightTarget } from '../lib/highlight';

/** What to outline in Gmail for a finding, or null when it has no visible counterpart (headers, hidden text). */
export function toHighlight(target: FindingTarget | undefined, report: Report): HighlightTarget | null {
  if (!target) return null;
  switch (target.kind) {
    case 'links': {
      const hrefs = target.indexes.map((i) => report.links[i]?.href).filter((h): h is string => !!h);
      return hrefs.length ? { kind: 'links', hrefs } : null;
    }
    case 'attachment': {
      const att = report.attachments.find((a) => a.sha256 === target.sha256);
      return att ? attachmentTarget(report, att) : null;
    }
    case 'sender':
      return { kind: 'sender' };
    case 'text':
      return target.phrases.length ? { kind: 'text', phrases: target.phrases } : null;
    default:
      return null;
  }
}

/** Where clicking a finding takes you inside the panel. */
export interface Focus {
  tab: TabId;
  linkIndex?: number;
  sha256?: string;
  headerKey?: string;
  revealHidden?: boolean;
  /** Tracking pixel number to point at in the Body tab. */
  pixel?: number;
}

export function toFocus(target: FindingTarget | undefined): Focus | null {
  if (!target) return null;
  switch (target.kind) {
    case 'links':
      return { tab: 'links', linkIndex: target.indexes[0] };
    case 'attachment':
      return { tab: 'attachments', sha256: target.sha256 };
    case 'sender':
      return { tab: 'sender' };
    case 'header':
      return { tab: 'headers', headerKey: target.key };
    case 'hidden':
      return { tab: 'body', revealHidden: true };
    case 'body':
    case 'text':
      return { tab: 'body' };
    case 'tab':
      return { tab: target.tab };
  }
}

/** Tooltip text telling the user what hovering/clicking a finding does. */
export function targetHint(target: FindingTarget | undefined): string {
  if (!target) return '';
  switch (target.kind) {
    case 'links':
      return target.indexes.length > 1 ? `Hover to outline these ${target.indexes.length} links in the email · click for details` : 'Hover to outline this link in the email · click for details';
    case 'attachment':
      return 'Hover to outline the attachment in the email · click for details';
    case 'sender':
      return 'Hover to outline the sender in the email · click for details';
    case 'text':
      return 'Hover to mark these words in the email · click to read the body';
    case 'header':
      return `Click to see the ${target.key} header`;
    case 'hidden':
      return 'Click to reveal the hidden text';
    default:
      return 'Click for details';
  }
}

/**
 * The Gmail tile for an attachment: its name, plus its position among the
 * email's real (non-inline) attachments, which Gmail shows in the same order.
 */
export function attachmentTarget(report: Report, att: AttachmentInfo | string): HighlightTarget | null {
  const visible = report.attachments.filter((a) => !a.inline);
  const found = typeof att === 'string' ? visible.find((a) => a.filename === att) : att;
  if (!found) return typeof att === 'string' ? { kind: 'attachments', names: [att] } : null;
  const index = visible.indexOf(found);
  return { kind: 'attachments', names: [found.filename], index: index >= 0 ? index : undefined };
}
