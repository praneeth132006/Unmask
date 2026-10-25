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

/** Device-code and consent-page lures: the login page is real, the app you approve is the attacker's. */
const DEVICE_LOGIN = /^https?:\/\/(?:www\.)?(?:microsoft\.com\/(?:[a-z-]+\/)?devicelogin|aka\.ms\/devicelogin|login\.microsoftonline\.com\/(?:common|organizations|[\w.-]+)\/oauth2\/(?:v2\.0\/)?deviceauth|login\.microsoft\.com\/device|google\.com\/device|github\.com\/login\/device)/i;
const CONSENT = /^https?:\/\/(?:login\.microsoftonline\.com|login\.microsoft\.com|login\.live\.com|accounts\.google\.com)\/[^?]*(?:oauth2|o\/oauth2)[^?]*\/(?:v2\.0\/)?(?:authorize|auth|v2\/auth)\b/i;
const CODE = /\b(?:code|kód|código|code d'accès)\s*[:：]?\s*([A-Z0-9]{4}-?[A-Z0-9]{4,5})\b/;
const BROAD_SCOPES = /(offline_access|mail\.read|mail\.readwrite|mail\.send|files\.read(write)?\.all|full_access_as_user|https:\/\/mail\.google\.com|gmail\.(readonly|modify)|drive(\.readonly)?\b)/i;

export function consentLureFindings(visibleText: string, links: LinkInfo[]): Finding[] {
  const findings: Finding[] = [];
  const device = links.find((l) => DEVICE_LOGIN.test(l.resolved) || DEVICE_LOGIN.test(l.href));
  const code = visibleText.match(CODE)?.[1];
  if (device || (code && /devicelogin|device login|microsoft\.com\/device/i.test(visibleText))) {
    findings.push({
      id: 'device-code-lure',
      category: 'links',
      severity: 'high',
      points: 22,
      title: 'Device-code phishing: asks you to enter a code on a real login page',
      detail: `It sends you to ${device ? new URL(device.resolved).host : 'a device sign-in page'}${code ? ` with the code ${code}` : ''}. The page is genuine, but entering the code signs the attacker's device into your account, no password needed. Never enter a code you didn't request yourself.`,
      plain: 'It asks you to type a code on a real login page, which would let a stranger into your account.',
      target: device ? { kind: 'links', indexes: [links.indexOf(device)] } : { kind: 'body' },
    });
  }
  // The href, not the resolved URL: Unmask's unwrapping follows redirect_uri, which is the point here.
  const consent = links.filter((l) => CONSENT.test(l.href) || CONSENT.test(l.resolved));
  for (const l of consent.slice(0, 1)) {
    const u = new URL(CONSENT.test(l.href) ? l.href : l.resolved);
    const redirect = u.searchParams.get('redirect_uri') ?? '';
    const redirectHost = (() => {
      try {
        return new URL(redirect).host;
      } catch {
        return '';
      }
    })();
    const scope = u.searchParams.get('scope') ?? '';
    const broad = BROAD_SCOPES.test(scope);
    const foreignRedirect = redirectHost && !brandOwningDomain(registrableDomain(redirectHost));
    findings.push({
      id: 'oauth-consent-link',
      category: 'links',
      severity: broad || foreignRedirect ? 'high' : 'medium',
      points: broad || foreignRedirect ? 20 : 12,
      title: broad ? 'Asks you to give an app access to your email or files' : 'Links straight to an app-permission (consent) page',
      detail: `The link opens ${u.host}'s real sign-in page to approve an app${u.searchParams.get('client_id') ? ` (client_id ${u.searchParams.get('client_id')})` : ''}${broad ? ` that wants ${scope.split(/[\s+]/).filter((s) => BROAD_SCOPES.test(s)).slice(0, 3).join(', ')}` : ''}${foreignRedirect ? `, and then sends you on to ${redirectHost}` : ''}. Approving gives that app lasting access even if you change your password.`,
      target: { kind: 'links', indexes: [links.indexOf(l)] },
    });
  }
  return findings;
}

/** "ClickFix": instructions to paste a command into Run, PowerShell or Terminal, often as a fake CAPTCHA. */
const CLICKFIX_KEYS = /\b(win(dows)?\s*(key)?\s*\+\s*r|⊞\s*\+\s*r|press\s+(the\s+)?windows\s+(key|button)|ctrl\s*\+\s*v|cmd\s*\+\s*v|command\s*\+\s*space)\b/i;
const CLICKFIX_PLACE = /\b(run (dialog|box|window)|powershell|command prompt|cmd\.exe|terminal|win\s*\+\s*x)\b/i;
const CLICKFIX_COMMAND = /\b(powershell(\.exe)?\s+-(e|enc|encodedcommand|w|windowstyle|nop|c)\b|mshta(\.exe)?\s+https?:|iex\s*\(|invoke-expression|curl\s+-[sSkL]+\s+https?:[^|]*\|\s*(ba)?sh|certutil\s+-urlcache|bitsadmin\s+\/transfer|osascript\s+-e)/i;
const CLIPBOARD = /navigator\.clipboard\.writeText|document\.execCommand\(\s*['"]copy['"]\s*\)/;

export function clickFixFindings(visibleText: string, email: ParsedEmail, attachments: AttachmentInfo[]): Finding[] {
  const findings: Finding[] = [];
  const steps = CLICKFIX_KEYS.test(visibleText) && CLICKFIX_PLACE.test(visibleText);
  const command = visibleText.match(CLICKFIX_COMMAND)?.[0];
  if (steps || command) {
    findings.push({ id: 'clickfix', category: 'content', severity: steps && command ? 'critical' : 'high', points: steps && command ? 35 : 22, title: 'Tells you to paste a command into your computer ("ClickFix")', detail: `${command ? `It contains a command (${command.slice(0, 60)}) ` : 'It gives keyboard steps '}to run in ${visibleText.match(CLICKFIX_PLACE)?.[0] ?? 'a command window'}. No real website, CAPTCHA or support team asks you to do this: the command installs malware.`, plain: 'It tells you to run a command on your computer, which would install malware.', target: { kind: 'body' } });
  }
  for (const a of email.attachments) {
    if (!/html|svg/i.test(a.mimeType) && !/\.(s?html?|svg)$/i.test(a.filename)) continue;
    const src = new TextDecoder().decode(a.content.subarray(0, 2_000_000));
    if (CLIPBOARD.test(src) && (CLICKFIX_COMMAND.test(src) || /powershell|mshta|cmd(\.exe)?\s*\/c/i.test(src))) {
      const info = attachments.find((x) => x.filename === a.filename);
      findings.push({ id: `clickfix-attachment-${a.filename}`, category: 'attachments', severity: 'critical', points: 35, title: `${a.filename} copies a hidden command to your clipboard`, detail: 'The file contains code that silently copies a PowerShell or system command when you click, then tells you to paste it. That command installs malware.', target: info ? { kind: 'attachment', sha256: info.sha256 } : { kind: 'tab', tab: 'attachments' } });
    }
  }
  return findings;
}

const ARCHIVE_PASSWORD = /\b(?:password|passcode|pass|pwd|kennwort|mot de passe|contraseña|senha|पासवर्ड)\s*(?:is|:|=|-|：)\s*["'“]?([^\s"'”<]{3,24})/i;

export function archivePasswordFindings(visibleText: string, subject: string, attachments: AttachmentInfo[]): Finding[] {
  const locked = attachments.find((a) => a.flags.some((f) => f.id === 'encrypted-archive'));
  if (!locked) return [];
  const pw = `${subject}\n${visibleText}`.match(ARCHIVE_PASSWORD);
  if (!pw) return [];
  return [
    {
      id: 'archive-password-in-body',
      category: 'attachments',
      severity: 'critical',
      points: 30,
      title: `Locked archive with its password in the email ("${pw[1]}")`,
      detail: `${locked.filename} is password-protected so virus scanners can't look inside, and the email gives you the password. Nobody legitimate does both: this is how malware is smuggled past filters.`,
      plain: 'It has a locked file and tells you the password, a trick to sneak malware past virus scanners.',
      target: { kind: 'attachment', sha256: locked.sha256 },
    },
  ];
}
