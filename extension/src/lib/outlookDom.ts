/**
 * Outlook on the web (outlook.live.com, outlook.office.com, …). Outlook does
 * not expose a message's original source to the page, so Unmask rebuilds the
 * email from what Outlook displays: sender, subject and the rendered body.
 * That covers links, text, images, QR codes, logos and sender checks; header
 * checks (SPF/DKIM/DMARC, delivery path) need "View message source" pasted
 * into the panel. Outlook's markup changes often, so everything here is a
 * best effort with several fallbacks, and found messages are tagged with our
 * own attribute so later lookups don't depend on Outlook's.
 */
import type { GmailMessageRef, GmailState } from './messages';
import type { MailSite } from './gmailProtect';

export const OWA_KEY_ATTR = 'data-unmask-owa';
/** Outlook wraps every rendered email in <div class="rps_XXXX">; the aria label is the English fallback. */
export const OWA_BODY = '[class^="rps_"], [class*=" rps_"], [aria-label="Message body" i]';
export const OUTLOOK_HOSTS = ['outlook.live.com', 'outlook.office.com', 'outlook.office365.com', 'outlook.cloud.microsoft'];

const EMAIL = /[\w.+'-]+@[\w-]+(?:\.[\w-]+)+/;

export function isOutlookUrl(url: string | undefined): boolean {
  try {
    return url ? OUTLOOK_HOSTS.includes(new URL(url).hostname) : false;
  } catch {
    return false;
  }
}

function hash(s: string): string {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return (h >>> 0).toString(36);
}

/** The sender shown in a message header: an element whose title, label or text holds an address. */
function senderIn(root: Element, body: Element): { name: string; address: string } | null {
  for (const el of Array.from(root.querySelectorAll('[title], [aria-label], span, button')).slice(0, 400)) {
    if (body.contains(el)) continue;
    const parts = [el.getAttribute('title') ?? '', el.getAttribute('aria-label') ?? '', el.children.length === 0 ? (el.textContent ?? '') : ''];
    for (const p of parts) {
      const m = p.match(EMAIL);
      if (!m) continue;
      // "Name <addr>", "From: Name, addr" or just the address.
      const name = p.replace(m[0], '').replace(/^(from|sender)\s*:\s*/i, '').replace(/[<>(),;]/g, ' ').replace(/\s+/g, ' ').trim();
      return { name: name || (el.textContent ?? '').replace(m[0], '').replace(/[<>]/g, '').trim(), address: m[0] };
    }
  }
  return null;
}

/** Climbs from the body to the smallest container that also shows the sender. */
function containerOf(body: Element): { root: Element; sender: { name: string; address: string } | null } {
  let el: Element | null = body.parentElement;
  for (let i = 0; el && i < 14; i++, el = el.parentElement) {
    const sender = senderIn(el, body);
    if (sender) return { root: el, sender };
  }
  return { root: body.parentElement ?? body, sender: null };
}

function subjectOf(doc: Document, root: Element): string {
  const heading = root.querySelector('[role="heading"]') ?? doc.querySelector('[role="main"] [role="heading"], [role="main"] h1, [role="main"] h2');
  return (heading?.textContent ?? '').replace(/\s+/g, ' ').trim();
}

/** Open messages in the reading pane, each tagged with a stable key. */
export function readOutlookState(doc: Document): GmailState {
  const bodies = Array.from(doc.querySelectorAll(OWA_BODY)).filter((b) => !b.parentElement?.closest(OWA_BODY));
  const messages: GmailMessageRef[] = [];
  for (const body of bodies) {
    if (!(body.textContent ?? '').trim() && !body.querySelector('img, a')) continue;
    const { root, sender } = containerOf(body);
    const subject = subjectOf(doc, root);
    const key = root.getAttribute(OWA_KEY_ATTR) ?? `owa:${hash(`${sender?.address ?? ''}|${subject}|${(body.textContent ?? '').slice(0, 600)}`)}`;
    root.setAttribute(OWA_KEY_ATTR, key);
    if (!messages.some((m) => m.permId === key)) messages.push({ permId: key, legacyId: null, fromName: sender?.name ?? '', fromEmail: sender?.address ?? '', subject });
  }
  return { accountIndex: '0', messages };
}

function encodeHeader(v: string): string {
  // eslint-disable-next-line no-control-regex
  return /^[\x20-\x7e]*$/.test(v) ? v : `=?utf-8?B?${btoa(String.fromCharCode(...new TextEncoder().encode(v)))}?=`;
}

function base64Lines(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 8192) bin += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(bin).replace(/.{76}/g, '$&\r\n');
}

/** Rebuilds an RFC 822 message from the page, so the normal analysis can run on it. */
export function buildOutlookRaw(doc: Document, ref: GmailMessageRef): string | null {
  const root = ref.permId ? doc.querySelector(`[${OWA_KEY_ATTR}="${ref.permId.replace(/["\\]/g, '\\$&')}"]`) : null;
  const body = root?.querySelector(OWA_BODY);
  if (!root || !body) return null;
  const clone = body.cloneNode(true) as Element;
  // Outlook prefixes the email's own classes and ids with x_; keep the structure, drop our marks.
  clone.querySelectorAll('[data-unmask-hl], [data-unmask-banner]').forEach((n) => n.remove());
  const name = ref.fromName.replace(/["\\\r\n]/g, '');
  const headers = [
    `From: ${ref.fromEmail ? `"${encodeHeader(name)}" <${ref.fromEmail}>` : 'unknown'}`,
    `Subject: ${encodeHeader(ref.subject.replace(/[\r\n]/g, ' '))}`,
    `Message-ID: <${ref.permId}@outlook-web.unmask.invalid>`,
    'X-Unmask-Source: Outlook on the web, read from the page (original headers are not available here)',
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=utf-8',
    'Content-Transfer-Encoding: base64',
  ];
  return `${headers.join('\r\n')}\r\n\r\n${base64Lines(`<!doctype html><html><body>${clone.innerHTML}</body></html>`)}\r\n`;
}

export const OUTLOOK_SITE: MailSite = {
  findRoot: (doc, key) => doc.querySelector(`[${OWA_KEY_ATTR}="${key.replace(/["\\]/g, '\\$&')}"]`),
  rootOf: (el) => el.closest(`[${OWA_KEY_ATTR}]`),
  keyOfRoot: (root) => root.getAttribute(OWA_KEY_ATTR) ?? '',
  bodyOf: (root) => root.querySelector(OWA_BODY),
  bodySelector: OWA_BODY,
  threadId: (doc) => {
    const id = doc.querySelector('[data-convid]')?.getAttribute('data-convid') ?? new URL(doc.location?.href ?? 'about:blank').pathname.match(/\/id\/([^/]+)/)?.[1];
    return id ? `owa:${id}` : null;
  },
  inboxRows: (doc) =>
    Array.from(doc.querySelectorAll('[role="listbox"] [role="option"]')).flatMap((row) => {
      const sender = Array.from(row.querySelectorAll('[title]')).find((el) => EMAIL.test(el.getAttribute('title') ?? ''));
      if (!sender) return [];
      const address = sender.getAttribute('title')!.match(EMAIL)![0];
      const convid = row.getAttribute('data-convid') ?? row.querySelector('[data-convid]')?.getAttribute('data-convid') ?? '';
      return [{ row, sender, address, name: (sender.textContent ?? '').trim(), thread: convid ? `owa:${convid}` : '' }];
    }),
};
