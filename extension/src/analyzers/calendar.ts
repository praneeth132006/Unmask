/**
 * Calendar invites (.ics / text/calendar). Phishers send meeting invites
 * because Gmail and Outlook add them to your calendar on their own: the link
 * then pops up as a reminder later, even after the email is deleted, and it
 * looks like a meeting your organisation set up.
 *
 * The invite is read as text; nothing is added to any calendar.
 */
import type { AuthSummary, Finding, ParsedAttachment, ParsedEmail } from '../core/types';
import type { RawLink } from './content';
import { registrableDomain, sameOrg } from '../lib/domain';
import { callbackSigns, PLATFORMS } from './techniques';

export interface CalendarEvent {
  summary: string;
  description: string;
  location: string;
  organizer: { name: string; address: string } | null;
  /** URL, ATTACH and conference properties: links the invite points to on purpose. */
  urls: string[];
  start: string | null;
}

export interface CalendarInvite {
  /** Where it came from: an .ics file name, or "calendar invite" for the email's own invite part. */
  origin: string;
  method: string | null;
  events: CalendarEvent[];
}

/** Meeting services whose join links are expected in an invite. */
const MEETING_DOMAINS = new Set(['zoom.us', 'zoom.com', 'zoomgov.com', 'microsoft.com', 'live.com', 'office.com', 'office365.com', 'google.com', 'webex.com', 'gotomeeting.com', 'goto.com', 'gotomeet.me', 'whereby.com', 'bluejeans.com', 'chime.aws', 'ringcentral.com', 'jit.si', 'skype.com', 'slack.com', 'calendly.com', 'teams.live.com', 'cloud.microsoft']);

const LURE = /\b(password|verify|verification|confirm (?:your|account)|suspend(?:ed)?|locked|expire[sd]?|invoice|payment|wire|bank (?:details|account)|gift ?cards?|bitcoin|crypto|wallet|refund|voicemail|e-?sign|docusign|shared (?:a )?(?:document|file)|review (?:the )?(?:document|file|contract)|payroll|salary|bonus|benefits? enrol(?:l)?ment|mfa|2fa|security alert|unusual (?:activity|sign-?in))\b/i;
const URL_RE = /\bhttps?:\/\/[^\s<>"'\\]+/gi;

const isCalendar = (a: ParsedAttachment) => /text\/calendar|application\/ics/i.test(a.mimeType) || /\.(ics|ical|ifb|vcs)$/i.test(a.filename);

/** RFC 5545 text: unfold continuation lines, then split into NAME;PARAMS:VALUE. */
function contentLines(text: string): { name: string; params: string; value: string }[] {
  const unfolded = text.replace(/\r?\n[ \t]/g, '');
  const out: { name: string; params: string; value: string }[] = [];
  for (const line of unfolded.split(/\r?\n/)) {
    // The value starts at the first colon outside a quoted parameter.
    let inQuote = false;
    let at = -1;
    for (let i = 0; i < line.length; i++) {
      if (line[i] === '"') inQuote = !inQuote;
      else if (line[i] === ':' && !inQuote) { at = i; break; }
    }
    if (at < 1) continue;
    const head = line.slice(0, at);
    const semi = head.indexOf(';');
    out.push({ name: (semi < 0 ? head : head.slice(0, semi)).toUpperCase(), params: semi < 0 ? '' : head.slice(semi + 1), value: line.slice(at + 1) });
  }
  return out;
}

const unescape = (v: string) => v.replace(/\\n/gi, '\n').replace(/\\([,;\\])/g, '$1');

export function parseIcs(text: string, origin = 'calendar invite'): CalendarInvite | null {
  if (!/BEGIN:VCALENDAR/i.test(text)) return null;
  const invite: CalendarInvite = { origin, method: null, events: [] };
  let ev: CalendarEvent | null = null;
  for (const { name, params, value } of contentLines(text)) {
    if (name === 'METHOD') invite.method = value.trim().toUpperCase();
    else if (name === 'BEGIN' && /^VEVENT$/i.test(value.trim())) ev = { summary: '', description: '', location: '', organizer: null, urls: [], start: null };
    else if (name === 'END' && /^VEVENT$/i.test(value.trim()) && ev) { invite.events.push(ev); ev = null; }
    else if (!ev) continue;
    else if (name === 'SUMMARY') ev.summary = unescape(value);
    else if (name === 'DESCRIPTION') ev.description = unescape(value);
    else if (name === 'X-ALT-DESC') ev.description ||= unescape(value).replace(/<[^>]+>/g, ' ');
    else if (name === 'LOCATION') ev.location = unescape(value);
    else if (name === 'DTSTART') ev.start = value.trim();
    else if (name === 'ORGANIZER') {
      const address = value.replace(/^mailto:/i, '').trim().toLowerCase();
      const cn = params.match(/CN=("?)([^";:]*)\1/i)?.[2] ?? '';
      ev.organizer = { name: cn, address };
    } else if (['URL', 'ATTACH', 'CONFERENCE', 'X-GOOGLE-CONFERENCE', 'X-MICROSOFT-SKYPETEAMSMEETINGURL', 'X-MICROSOFT-ONLINEMEETINGCONFLINK'].includes(name) && /^https?:/i.test(value.trim())) {
      ev.urls.push(value.trim());
    }
  }
  return invite.events.length ? invite : null;
}

export function readInvites(email: ParsedEmail): CalendarInvite[] {
  const out: CalendarInvite[] = [];
  for (const a of email.attachments.filter(isCalendar)) {
    const text = new TextDecoder().decode(a.content.subarray(0, 512 * 1024));
    // The email's own invite part is not a file the sender attached; name it as what it is.
    const origin = a.disposition === 'attachment' ? a.filename : 'calendar invite';
    const invite = parseIcs(text, origin);
    if (invite) out.push(invite);
  }
  return out;
}

function eventText(e: CalendarEvent): string {
  return [e.summary, e.location, e.description].filter(Boolean).join('\n');
}

/** Every link in the invites, so they go through the same checks as links in the body. */
export function calendarLinks(invites: CalendarInvite[]): RawLink[] {
  const links: RawLink[] = [];
  for (const inv of invites) {
    for (const e of inv.events) {
      const seen = new Set<string>();
      for (const href of [...e.urls, ...(eventText(e).match(URL_RE) ?? [])]) {
        const clean = href.replace(/[).,;>\]]+$/, '');
        if (seen.has(clean)) continue;
        seen.add(clean);
        links.push({ href: clean, text: e.summary.slice(0, 80), source: 'attachment', origin: inv.origin });
      }
    }
  }
  return links;
}

/** True for a join link on Zoom, Teams, Meet, Webex and similar services. */
export function isMeetingLink(url: string): boolean {
  return MEETING_DOMAINS.has(domainOf(url));
}

function domainOf(url: string): string {
  try {
    return registrableDomain(new URL(url).hostname);
  } catch {
    return '';
  }
}

export function calendarFindings(email: ParsedEmail, auth: AuthSummary, invites: CalendarInvite[]): Finding[] {
  if (!invites.length) return [];
  const findings: Finding[] = [];
  const fromOrg = email.from ? registrableDomain(email.from.domain) : '';
  const viaPlatform = PLATFORMS.has(fromOrg) || MEETING_DOMAINS.has(fromOrg);
  const target = { kind: 'tab', tab: 'attachments' } as const;
  const autoAdd = 'Gmail and Outlook can add invites to your calendar automatically, so this link may come back as a reminder even after you delete the email.';

  for (const inv of invites) {
    for (const e of inv.events) {
      const text = eventText(e);
      const urls = [...new Set([...e.urls, ...(text.match(URL_RE) ?? [])])];
      const outside = urls.filter((u) => { const d = domainOf(u); return d && !MEETING_DOMAINS.has(d) && !sameOrg(d, fromOrg); });
      const lure = text.match(LURE)?.[0];
      const callback = callbackSigns(`${e.summary}\n${e.description}`);

      const org = e.organizer;
      const orgDomain = org?.address.split('@')[1] ?? '';
      if (org && orgDomain && fromOrg && !sameOrg(orgDomain, fromOrg) && !viaPlatform) {
        findings.push({
          id: 'calendar-organizer-mismatch',
          category: 'sender',
          severity: auth.dmarc === 'pass' ? 'low' : 'medium',
          points: auth.dmarc === 'pass' ? 4 : 12,
          title: `Invite organised by ${org.address}, but the email came from ${email.from!.address}`,
          detail: `The meeting says ${org.name ? `${org.name} (${org.address})` : org.address} set it up, while the email was sent from ${fromOrg}. Attackers forge the organiser so an invite looks internal.`,
          plain: 'The person who “organised” this meeting is not the one who sent it.',
          target,
        });
      }

      if (callback) {
        findings.push({ id: 'calendar-callback', category: 'content', severity: 'high', points: 22, title: 'Calendar invite tells you to phone about a charge', detail: `The invite mentions ${callback.amount ?? 'a charge'} and the number ${callback.phones[0]}. ${autoAdd}`, plain: 'A meeting invite that asks you to call about a payment is a callback scam.', target: { kind: 'text', phrases: callback.phones } });
      } else if (outside.length && lure) {
        findings.push({
          id: 'calendar-lure',
          category: 'content',
          severity: 'high',
          points: 22,
          title: `Calendar invite about “${lure}” links to ${domainOf(outside[0]!)}`,
          detail: `“${e.summary || 'Untitled event'}” points to ${outside.slice(0, 3).map(domainOf).join(', ')}, which is not a meeting service. ${autoAdd}`,
          plain: 'This meeting invite is really a way to get you to a website and sign in or pay.',
          target,
        });
      } else if (outside.length && /\b(join|meeting|call|webinar|interview|session|click|open|view)\b/i.test(text)) {
        findings.push({
          id: 'calendar-odd-link',
          category: 'links',
          severity: 'medium',
          points: 10,
          title: `Meeting invite whose link isn’t a meeting service (${domainOf(outside[0]!)})`,
          detail: `Real invites use Zoom, Teams, Meet, Webex and similar. This one points to ${outside.slice(0, 3).map(domainOf).join(', ')}. ${autoAdd}`,
          plain: 'The “join meeting” link doesn’t go to a meeting service.',
          target,
        });
      }
    }
  }
  return findings;
}
