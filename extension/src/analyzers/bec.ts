/**
 * Business email compromise (BEC): no malicious link or file, just a
 * convincing request to move money. These checks look for the requests
 * themselves: changed bank details, payment and gift-card asks, and the
 * secrecy / "are you available?" openers that usually come with them.
 */
import type { Finding, ParsedEmail } from '../core/types';
import { FREE_MAIL_DOMAINS } from './brands';
import { registrableDomain, sameOrg } from '../lib/domain';

const BANK_CHANGE = [
  /\b(new|updated?|changed?|different|revised) (bank(ing)?|account|payment|remittance|wire|payroll) (details|information|info|instructions|account)\b/i,
  /\b(our|my) (bank|banking|account) (details|information|account) (has|have) (changed|been (updated|changed))\b/i,
  /\b(change|update) (of |to |our |my )?(bank|banking|payment|payroll|direct deposit) (details|information|account|info)\b/i,
  /\b(update|change) (my|our) direct deposit\b/i,
  /\bwe (have )?(changed|switched|moved) (our )?bank/i,
  /\b(do not|don't) (use|pay (to|into)) the (old|previous) (account|bank)/i,
];

const PAYMENT = [
  /\b(process|make|send|initiate|arrange|release|complete|effect) (a |an |the |this )?(urgent |quick |same[- ]day )?(payment|wire( transfer)?|bank transfer|transfer|remittance)\b/i,
  /\b(outstanding|overdue|unpaid|pending) (invoice|payment|balance)s?\b/i,
  /\b(iban|swift( code)?|bic|routing number|sort code|beneficiary (account|name|bank))\b/i,
  /\bpay (this|the attached) invoice\b/i,
];

const GIFT_CARDS = [
  /\b(buy|purchase|get|pick up|grab) .{0,40}gift ?cards?\b/i,
  /\b(itunes|apple|google play|steam|amazon|ebay|visa|target|walmart|razer) (gift )?cards?\b/i,
  /\b(scratch|send me|email me|photo of) (off )?(the )?(codes?|pins?|card numbers?|back of the cards?)\b/i,
];

const PRETEXT = [
  /\bare you (available|free|around|at your desk|in the office)\b/i,
  /\b(keep|treat) (this|it) (confidential|private|between us|discreet|quiet)\b/i,
  /\b(strictly )?confidential\b.{0,40}\b(payment|transfer|acquisition|deal)\b/i,
  /\b(do not|don't) (tell|discuss|mention|call|phone)\b/i,
  /\bi('m| am) (in a meeting|in meetings|on a (flight|plane)|travel(l)?ing|tied up|in a conference)\b/i,
  /\b(quick|small|urgent) (favou?r|task|request)\b/i,
  /\bcan('t| not) (talk|take calls?) (right )?now\b/i,
];

function matches(text: string, patterns: RegExp[]): string[] {
  const found = new Set<string>();
  for (const p of patterns) {
    const m = text.match(p);
    if (m) found.add(m[0].toLowerCase());
  }
  return [...found];
}

const quote = (xs: string[]) => xs.slice(0, 3).map((x) => `"${x}"`).join(', ');

/** `visibleText` is the body without hidden blocks (from the content analyzer). */
export function analyzeBec(email: ParsedEmail, visibleText: string): Finding[] {
  const text = `${email.subject} ${visibleText}`.replace(/\s+/g, ' ');
  const findings: Finding[] = [];

  const bank = matches(text, BANK_CHANGE);
  const payment = matches(text, PAYMENT);
  const gift = matches(text, GIFT_CARDS);
  const pretext = matches(text, PRETEXT);

  if (bank.length) {
    findings.push({ id: 'bec-bank-change', category: 'content', severity: 'high', points: 25, target: { kind: 'text', phrases: bank }, title: 'Says bank or payment details have changed', detail: `Found ${quote(bank)}. Changed bank details are the most common business-fraud trick. Confirm by phone, using a number you already have, before paying.` });
  }
  if (gift.length) {
    findings.push({ id: 'bec-gift-card', category: 'content', severity: 'high', points: 22, target: { kind: 'text', phrases: gift }, title: 'Asks you to buy gift cards', detail: `Found ${quote(gift)}. No real boss, company or government agency asks to be paid in gift cards.` });
  }
  if (payment.length) {
    findings.push({ id: 'bec-payment', category: 'content', severity: 'medium', points: 10, target: { kind: 'text', phrases: payment }, title: 'Asks for a payment or transfer', detail: `Found ${quote(payment)}.` });
  }
  if (pretext.length) {
    findings.push({ id: 'bec-pretext', category: 'content', severity: payment.length || bank.length || gift.length ? 'medium' : 'low', points: payment.length || bank.length || gift.length ? 10 : 3, target: { kind: 'text', phrases: pretext }, title: 'Uses a secrecy or "are you available?" opener', detail: `Found ${quote(pretext)}. Fraudsters keep you from checking with anyone else.` });
  }

  // Money request + replies going elsewhere or a personal webmail account: the classic CEO-fraud shape.
  const from = email.from;
  const moneyAsk = bank.length + payment.length + gift.length > 0;
  const replyElsewhere = from ? email.replyTo.some((r) => r.domain && !sameOrg(r.domain, from.domain)) : false;
  const freemail = from ? FREE_MAIL_DOMAINS.has(registrableDomain(from.domain)) : false;
  if (moneyAsk && (replyElsewhere || freemail || pretext.length)) {
    const why = [replyElsewhere && 'replies go to another address', freemail && 'it comes from a personal webmail account', pretext.length && 'it asks for secrecy or speed'].filter(Boolean).join(', ');
    findings.push({ id: 'bec-pattern', category: 'content', severity: 'high', points: 15, target: { kind: 'body' }, title: 'Matches the pattern of payment fraud', detail: `A request for money where ${why}. Verify with the person in a separate call or chat before doing anything.` });
  }

  return findings;
}
