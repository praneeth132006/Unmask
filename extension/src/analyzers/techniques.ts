/**
 * Named attack techniques that analysts recognise by their shape rather than
 * by a bad link or a failed check: callback scams, abused notification
 * platforms, consent and device-code lures, "ClickFix" instructions, and
 * password-protected archives with the password in the body.
 */
import type { AttachmentInfo, AuthSummary, Finding, LinkInfo, ParsedEmail } from '../core/types';
import { registrableDomain } from '../lib/domain';
import { brandOwningDomain } from './brands';

const PHONE = /(?:\+?1[\s.-]?)?\(?\b[2-9]\d{2}\)?[\s.-]\d{3}[\s.-]\d{4}\b|\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]\d{2,4}){2,4}\b|\b1[\s-]?8(?:00|33|44|55|66|77|88)[\s.-]?\d{3}[\s.-]?\d{4}\b/g;
const CALL = /\b(call|contact|reach|dial|phone|ring)\b[^.!?\n]{0,40}\b(us|support|helpline|help ?desk|billing|team|department|immediately|toll[- ]?free|customer care|representative|agent|number)\b|\b(toll[- ]?free|helpline|customer care) (number|no\.?)\b/i;
const BILLING = /\b(subscription|renew(al|ed)?|auto[- ]?renew(al)?|order|invoice|purchase[sd]?|charged|debited|transaction|receipt|membership|billing|payment)\b/i;
const DISPUTE = /\b(cancel(lation)?|refund|dispute|not you|did ?n[o']?t (make|authori[sz]e|recogni[sz]e)|unauthori[sz]ed|if this (wasn'?t|was not) you)\b/i;
const AMOUNT = /(?:[$€£₹]\s?\d[\d,]*(?:\.\d{2})?|\b\d[\d,]*\.\d{2}\s?(?:usd|eur|gbp|inr)\b)/i;

export function phoneNumbers(text: string): string[] {
  return [...new Set([...text.matchAll(PHONE)].map((m) => m[0].trim()).filter((n) => n.replace(/\D/g, '').length >= 10))];
}

/** Signs of a callback ("TOAD") scam in the text: call this number about a charge you didn't make. */
export function callbackSigns(text: string): { phones: string[]; amount: string | null } | null {
  const phones = phoneNumbers(text);
  if (!phones.length || !CALL.test(text) || !BILLING.test(text)) return null;
  const amount = text.match(AMOUNT)?.[0] ?? null;
  if (!DISPUTE.test(text) && !amount) return null;
  return { phones, amount };
}

export function callbackFindings(email: ParsedEmail, visibleText: string, auth: AuthSummary): Finding[] {
  const text = `${email.subject}\n${visibleText}`;
  const signs = callbackSigns(text);
  if (!signs) return [];
  const fromOrg = email.from ? registrableDomain(email.from.domain) : '';
  // A verified brand putting its own support number in a receipt is normal; only note it.
  const verifiedBrand = auth.dmarc === 'pass' && brandOwningDomain(fromOrg) && !PLATFORMS.has(fromOrg);
  return [
    {
      id: 'callback-phishing',
      category: 'content',
      severity: verifiedBrand ? 'low' : 'high',
      points: verifiedBrand ? 3 : 22,
      title: verifiedBrand ? 'Asks you to phone about a charge' : 'Callback scam: tells you to phone about a charge you didn\'t make',
      detail: `It mentions ${signs.amount ? `a charge of ${signs.amount}` : 'a charge or renewal'} and asks you to call ${signs.phones.slice(0, 2).join(' or ')}. ${verifiedBrand ? 'It comes from the company\'s verified domain, but still look the number up on their official website.' : 'There is no link to click: the scam happens on the phone, where "support" talks you into a refund that installs remote-control software or takes your bank details.'}`,
      plain: verifiedBrand ? undefined : 'It wants you to call a phone number, where scammers pretend to be support.',
      target: { kind: 'text', phrases: signs.phones },
    },
  ];
}

/** Services that send genuine emails carrying text written by whoever used them: invoices, shares, invites. */
export const PLATFORMS = new Set([
  'paypal.com', 'docusign.net', 'docusign.com', 'intuit.com', 'quickbooks.com', 'squareup.com', 'square.com', 'freshbooks.com', 'xero.com', 'waveapps.com', 'zohoinvoice.com', 'stripe.com',
  'google.com', 'microsoft.com', 'sharepointonline.com', 'sharepoint.com', 'dropbox.com', 'dropboxmail.com', 'box.com', 'adobe.com', 'adobesign.com', 'zoom.us', 'calendly.com', 'eventbrite.com', 'facebookmail.com', 'canva.com', 'notion.so', 'wetransfer.com',
]);

export function platformAbuseFindings(email: ParsedEmail, visibleText: string, auth: AuthSummary, links: LinkInfo[]): Finding[] {
  const fromOrg = email.from ? registrableDomain(email.from.domain) : '';
  if (!PLATFORMS.has(fromOrg) || auth.dmarc !== 'pass') return [];
  const platform = brandOwningDomain(fromOrg)?.name ?? fromOrg;
  const reasons: string[] = [];
  const callback = callbackSigns(`${email.subject}\n${visibleText}`);
  if (callback) reasons.push(`a phone number to call about ${callback.amount ? `a ${callback.amount} charge` : 'a charge'} (${callback.phones[0]})`);
  const bad = links.filter((l) => (l.source === 'html' || l.source === 'text') && l.flags.some((f) => f.severity === 'high' || f.severity === 'critical'));
  if (bad[0]) reasons.push(`a link to ${bad[0].domain}, which has its own red flags`);
  const webmail = visibleText.match(/[\w.+-]+@(gmail|outlook|hotmail|yahoo|proton|protonmail|aol|icloud|gmx|mail|yandex)\.[a-z.]+/i)?.[0];
  if (webmail && callback) reasons.push(`a personal contact address (${webmail})`);
  if (!reasons.length) return [];
  return [
    {
      id: 'platform-abuse',
      category: 'content',
      severity: 'high',
      points: 22,
      title: `A real ${platform} email carrying a scammer's message`,
      detail: `This email genuinely comes from ${fromOrg} (it passed DMARC), but ${platform} lets anyone send invoices, shares and invites through it, with their own text. This one contains ${reasons.join(' and ')}. ${platform} itself didn't write that part.`,
      plain: `It really comes from ${platform}, but a scammer wrote the message inside it.`,
      target: { kind: 'body' },
    },
  ];
}

