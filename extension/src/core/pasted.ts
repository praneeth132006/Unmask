/**
 * "Paste anything": text messages, WhatsApp chats, a bare link or a whole
 * email. A full email (headers and all) is analysed as it is. Anything else
 * is wrapped in a minimal email so the same link, wording and brand checks
 * run on it, with no sender checks that would only mislead.
 */
import { analyzeRawEmail } from './analyze';
import { scoreFindings } from './score';
import type { Report } from './types';

/** True when the text starts with email headers (From:, Received:, ...). */
export function looksLikeEmail(text: string): boolean {
  const head = text.replace(/^\s+/, '').split(/\r?\n\r?\n/)[0] ?? '';
  const lines = head.split(/\r?\n/).filter((l) => /^[A-Za-z][A-Za-z0-9-]*:\s/.test(l));
  return lines.length >= 2 && lines.some((l) => /^(from|received|subject|return-path|delivered-to|message-id):/i.test(l));
}

/** A bare URL or domain gets a scheme so the link checks see it. */
function linkify(text: string): string {
  const t = text.trim();
  if (/^[a-z0-9.-]+\.[a-z]{2,}(\/\S*)?$/i.test(t) && !/\s/.test(t)) return `https://${t}`;
  return text;
}

export type PastedKind = 'email' | 'message' | 'link';

export function pastedKind(text: string): PastedKind {
  if (looksLikeEmail(text)) return 'email';
  const t = text.trim();
  return !/\s/.test(t) && /^(https?:\/\/)?[a-z0-9.-]+\.[a-z]{2,}(\/\S*)?$/i.test(t) ? 'link' : 'message';
}

/** The text as a raw email ready for `analyzeRawEmail`. */
export function pastedToRaw(text: string): string {
  if (looksLikeEmail(text)) return text;
  const body = linkify(text).replace(/\r\n/g, '\n');
  return [
    'From: "Pasted message" <unknown@pasted.invalid>',
    'Subject: Pasted message',
    'X-Unmask-Pasted: 1',
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    '',
    body,
  ].join('\n');
}

/** Sender and authentication findings mean nothing for a pasted message, which has no real sender. */
export const PASTED_SKIP_CATEGORIES = new Set(['auth', 'sender']);


/** Analyse pasted text. For anything but a full email, sender checks are dropped and the score recomputed. */
export async function analyzePasted(text: string): Promise<Report & { kind: PastedKind }> {
  const kind = pastedKind(text);
  const report = await analyzeRawEmail(pastedToRaw(text));
  if (kind === 'email') return { ...report, kind };
  const findings = report.findings.filter((f) => !PASTED_SKIP_CATEGORIES.has(f.category));
  return { ...report, findings, ...scoreFindings(findings), kind };
}
