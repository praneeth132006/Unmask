/**
 * Does the email's construction match who it claims to be? Analysts compare
 * the Message-ID, the sending software and the threading headers with the
 * From address: each mail service builds them its own way, and scam tools
 * build them differently again.
 */
import type { AuthSummary, Finding, ParsedEmail } from '../core/types';
import { getHeaders } from '../core/parse';
import type { RawMessage } from '../lib/rawMessage';
import { registrableDomain, sameOrg } from '../lib/domain';
import { brandOwningDomain, brandsMentionedIn, FREE_MAIL_DOMAINS, senderClaim } from './brands';
import { INVISIBLE, mixedScriptWords, skeleton } from './lookalike';

/** How each webmail service writes its Message-IDs. A gmail.com From with any other kind wasn't written in Gmail. */
const WEBMAIL_MESSAGE_ID: { domains: string[]; name: string; id: RegExp }[] = [
  { domains: ['gmail.com', 'googlemail.com'], name: 'Gmail', id: /@(mail\.gmail\.com|gmail\.com|googlemail\.com)$/i },
  { domains: ['outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'hotmail.co.uk', 'outlook.in'], name: 'Outlook.com', id: /@([\w.-]+\.)?(outlook\.com|hotmail\.com|live\.com|phx\.gbl)$/i },
  { domains: ['yahoo.com', 'ymail.com', 'yahoo.co.in', 'yahoo.co.uk'], name: 'Yahoo Mail', id: /@([\w.-]+\.)?(yahoo\.com|yahoo\.co\.\w+|yahoodns\.net)$/i },
];

/** Bulk-sending tools that legitimate companies don't use, and tools that show a web script sent it. */
const SPAM_TOOLS = /\b(leaf ?phpmailer|atomic mail sender|gammadyne|sendblaster|turbo-?mailer|advanced mass sender|mailer ?king|super ?mailer|send-safe|dark ?mailer|ultra ?mailer|group ?mail|email marketing director)\b/i;
const SCRIPT_MAILERS = /\b(phpmailer|php\/\d|swiftmailer|microsoft cdo|python-requests|smtplib|nodemailer)\b/i;

const REPLY_PREFIX = /^\s*(re|aw|sv|antw|rif|r|vs|odp)\s*(\[\d+\])?\s*:/i;

function messageIdDomain(id: string | null): string | null {
  return id?.replace(/^<|>$/g, '').split('@')[1]?.toLowerCase().replace(/[>\s].*$/, '') || null;
}

export function identityFindings(email: ParsedEmail, raw: RawMessage, auth: AuthSummary): Finding[] {
  const findings: Finding[] = [];
  const from = email.from;
  const fromOrg = from ? registrableDomain(from.domain) : '';
  const verified = auth.dmarc === 'pass';
  const claimsBrand = from ? brandsMentionedIn(senderClaim(from.name, from.domain)).length > 0 : false;

  // 1. Two From headers: different mail apps and filters may each read a different one.
  const fromCount = raw.headers.filter((h) => h.key === 'from').length;
  if (fromCount > 1) {
    findings.push({ id: 'multiple-from', category: 'sender', severity: 'high', points: 20, title: `The email has ${fromCount} From addresses`, detail: 'A valid email has one. With several, your mail app may show one sender while spam filters checked another, a trick used to slip past authentication.', target: { kind: 'header', key: 'from' } });
  }

  // 2. Message-ID: missing, or built by a different service than the From address claims.
  const msgId = email.messageId;
  const idDomain = messageIdDomain(msgId);
  // Only when the provider says it had to add one; a missing header is usually a hand-pasted sample.
  if (msgId && /SMTPIN_ADDED/i.test(msgId)) {
    findings.push({ id: 'message-id-missing', category: 'sender', severity: 'low', points: 3, title: 'The sender didn\'t give the email a Message-ID', detail: 'Every normal mail program adds one. Its absence (your provider added it on arrival) points to a hand-made or script-sent email.', target: { kind: 'header', key: 'message-id' } });
  } else if (from && !verified && idDomain) {
    const webmail = WEBMAIL_MESSAGE_ID.find((w) => w.domains.includes(fromOrg));
    if (webmail && !webmail.id.test(`@${idDomain}`)) {
      findings.push({ id: 'webmail-forged', category: 'sender', severity: 'medium', points: 12, title: `Claims to be from ${webmail.name}, but wasn't written in ${webmail.name}`, detail: `${webmail.name} gives every email a Message-ID ending in its own domain; this one ends in @${idDomain}. Someone used ${from.address} as a fake From address.`, target: { kind: 'header', key: 'message-id' } });
    }
  }

  // 3. The software that sent it.
  const mailer = [...getHeaders(email, 'x-mailer'), ...getHeaders(email, 'user-agent')].join(' ');
  const script = getHeaders(email, 'x-php-originating-script')[0] ?? getHeaders(email, 'x-php-script')[0];
  if (SPAM_TOOLS.test(mailer)) {
    findings.push({ id: 'mailer-spam-tool', category: 'sender', severity: 'medium', points: 12, title: 'Sent with a bulk spam tool', detail: `The email says it was sent with "${mailer.trim().slice(0, 80)}", a mass-mailing program used for spam and phishing, not by real companies.`, target: { kind: 'header', key: 'x-mailer' } });
  } else if (script || SCRIPT_MAILERS.test(mailer)) {
    const brandish = claimsBrand && !verified;
    findings.push({
      id: 'mailer-script',
      category: 'sender',
      severity: brandish ? 'medium' : 'low',
      points: brandish ? 10 : 3,
      title: script ? 'Sent by a script on a website' : 'Sent by a script, not a mail program',
      detail: `${script ? `A web script (${script.slice(0, 80)}) sent it. Phishers often send from websites they have broken into.` : `Sent with ${mailer.trim().slice(0, 60)}.`}${brandish ? ' Large companies send through their own mail systems, not scripts like this.' : ''}`,
      target: { kind: 'header', key: script ? 'x-php-originating-script' : 'x-mailer' },
    });
  }

  // 4. "Re:" with nothing it replies to: a fake conversation, made to look like an ongoing thread.
  const threaded = ['in-reply-to', 'references', 'thread-index'].some((k) => getHeaders(email, k).length > 0);
  if (REPLY_PREFIX.test(email.subject) && !threaded) {
    findings.push({ id: 'fake-reply', category: 'content', severity: 'low', points: 6, title: '"Re:" in the subject, but it isn\'t a reply', detail: 'Real replies point to the message they answer (In-Reply-To or References headers). This one doesn\'t, so the "conversation" was made up to look familiar.', target: { kind: 'header', key: 'subject' } });
  }

  // 5. A genuine brand email addressed to someone else: the hallmark of a replayed (re-sent) email.
  const deliveredTo = getHeaders(email, 'delivered-to')[0]?.trim().toLowerCase();
  const brandSigned = from && !FREE_MAIL_DOMAINS.has(fromOrg) && brandOwningDomain(fromOrg) && auth.dkimDomains.some((d) => sameOrg(d, from.domain));
  // Your own forwarding (X-Forwarded-To) and mailing lists also deliver mail written for another address.
  const forwarded = ['list-id', 'x-forwarded-to', 'x-forwarded-for', 'resent-to'].some((k) => getHeaders(email, k).length > 0);
  if (deliveredTo && brandSigned && !forwarded) {
    const addressed = [...getHeaders(email, 'to'), ...getHeaders(email, 'cc')].join(' ').toLowerCase();
    if (addressed && !addressed.includes(deliveredTo) && !addressed.includes('undisclosed')) {
      findings.push({ id: 'replay-addressee', category: 'auth', severity: 'low', points: 5, title: `A genuine ${fromOrg} email, but addressed to someone else`, detail: `It is signed by ${fromOrg}, yet it was written for ${email.to[0]?.address ?? 'another address'}, not you (${deliveredTo}). If you don\'t forward mail from that address here: attackers trigger real notifications to their own account and re-send them unchanged ("DKIM replay"), so the signature still passes.`, target: { kind: 'header', key: 'to' } });
    }
  }
  // 6. Disguised words: invisible characters or letters from another alphabet in the name or subject.
  for (const [where, text, key] of [['sender name', from?.name ?? '', 'from'], ['subject', email.subject, 'subject']] as const) {
    const invisible = text.match(INVISIBLE)?.length ?? 0;
    const mixed = mixedScriptWords(text);
    if (!invisible && !mixed.length) continue;
    const disguised = brandsMentionedIn(skeleton(text.replace(INVISIBLE, ''))).filter((b) => !brandsMentionedIn(text).includes(b));
    const strong = where === 'sender name' || disguised.length > 0;
    findings.push({
      id: `disguised-${key}`,
      category: 'sender',
      severity: strong ? 'medium' : 'low',
      points: disguised.length ? 15 : strong ? 10 : 5,
      title: disguised.length ? `The ${where} spells "${disguised[0]!.name}" with disguised letters` : `The ${where} hides ${mixed.length ? 'letters from another alphabet' : 'invisible characters'}`,
      detail: `${mixed.length ? `"${mixed[0]}" mixes Latin letters with look-alikes from another alphabet. ` : ''}${invisible ? `It contains ${invisible} invisible character${invisible === 1 ? '' : 's'}. ` : ''}This is done to slip a name past filters that look for it, while it reads normally to you.`,
      target: { kind: 'header', key },
    });
  }
  return findings;
}
