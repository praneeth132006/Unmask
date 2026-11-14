/**
 * Family mode: for someone who wants a person they trust to look before they
 * act. On a High risk email "Open anyway" and "Reply anyway" are replaced by
 * "Ask <helper>", which opens a ready-written email to that person in the
 * user's own mail app. Nothing goes through Unmask or any server.
 * A PIN can lock Settings so the protection isn't switched off by accident.
 */
import type { Report } from '../core/types';

export interface Helper {
  name: string;
  email: string;
}

const VERDICT = { high: 'High risk', suspicious: 'Suspicious', clear: 'No red flags found' } as const;

/** Addresses and links are written so they can't be clicked by mistake: paypa1-support[.]xyz. */
const defang = (s: string) => s.replace(/\bhttps?:\/\//gi, 'hxxp://').replace(/([a-z0-9-])\.([a-z]{2,})\b/gi, '$1[.]$2');

export function validHelper(h: Partial<Helper> | undefined): h is Helper {
  return !!h?.email && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(h.email.trim());
}

/** A mailto: link to the helper, with what Unmask found, in plain words. */
export function askHelperLink(helper: Helper, report: Report): string {
  const reasons = report.findings.filter((f) => f.points > 0 && (f.plain || f.title)).slice(0, 4).map((f) => `- ${defang(f.plain ?? f.title)}`);
  const from = report.email.from;
  const body = [
    `Hi ${helper.name.trim() || 'there'},`,
    '',
    'Unmask warned me about an email. Could you look before I do anything with it?',
    '',
    `From: ${from ? `${from.name ? `${from.name} ` : ''}<${defang(from.address)}>` : 'unknown'}`,
    `Subject: ${report.email.subject.slice(0, 160)}`,
    `Unmask says: ${VERDICT[report.verdict]} (${report.score}/100)`,
    ...(reasons.length ? ['', 'Why:', ...reasons] : []),
    '',
    "I haven't clicked its links or opened its files.",
  ].join('\n');
  const q = `subject=${encodeURIComponent('Can you check this email for me?')}&body=${encodeURIComponent(body)}`;
  return `mailto:${encodeURIComponent(helper.email.trim()).replace(/%40/g, '@')}?${q}`;
}

/** Family mode stops the "anyway" buttons only on High risk emails. */
export function familyBlocks(settings: { familyMode?: boolean }, report: Report | undefined): boolean {
  return !!settings.familyMode && report?.verdict === 'high';
}

export function newSalt(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function hashPin(pin: string, salt: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${salt}:${pin}`));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function pinMatches(pin: string, salt: string, hash: string): Promise<boolean> {
  return !!hash && (await hashPin(pin, salt)) === hash;
}
