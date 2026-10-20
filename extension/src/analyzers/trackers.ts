import type { Finding, LinkInfo, TrackerPixel, TrackerReport } from '../core/types';
import { safeUrl } from '../lib/domain';

/** Email tracking services, keyed by a host suffix they serve pixels or tracked links from. */
const SERVICES: [suffix: string, name: string][] = [
  ['list-manage.com', 'Mailchimp'], ['mailchimp.com', 'Mailchimp'], ['mcusercontent.com', 'Mailchimp'], ['mandrillapp.com', 'Mailchimp Transactional'],
  ['sendgrid.net', 'SendGrid'], ['sendgrid.com', 'SendGrid'],
  ['hubspotlinks.com', 'HubSpot'], ['hubspotemail.net', 'HubSpot'], ['hs-analytics.net', 'HubSpot'], ['hubspot.com', 'HubSpot'], ['hsms06.com', 'HubSpot'],
  ['mailtrack.io', 'Mailtrack'], ['mailtrack.com', 'Mailtrack'],
  ['mixmax.com', 'Mixmax'], ['yesware.com', 'Yesware'], ['streak.com', 'Streak'], ['mailfoogae.appspot.com', 'Streak'],
  ['superhuman.com', 'Superhuman'], ['bananatag.com', 'Bananatag'], ['contactmonkey.com', 'ContactMonkey'], ['baydin.com', 'Boomerang'],
  ['getnotify.com', 'GetNotify'], ['emltrk.com', 'Emltrk'], ['mailtrack.co', 'Mailtrack'], ['saleshandy.com', 'SaleHandy'], ['lemlist.com', 'lemlist'],
  ['mailgun.org', 'Mailgun'], ['mailgun.net', 'Mailgun'], ['sparkpostmail.com', 'SparkPost'], ['sparkpost.com', 'SparkPost'],
  ['awstrack.me', 'Amazon SES'], ['pstmrk.it', 'Postmark'], ['postmarkapp.com', 'Postmark'],
  ['exacttarget.com', 'Salesforce Marketing Cloud'], ['sfmc-content.com', 'Salesforce Marketing Cloud'], ['salesforce.com', 'Salesforce'],
  ['klaviyo.com', 'Klaviyo'], ['klclick.com', 'Klaviyo'], ['klclick1.com', 'Klaviyo'],
  ['createsend.com', 'Campaign Monitor'], ['cmail19.com', 'Campaign Monitor'], ['cmail20.com', 'Campaign Monitor'],
  ['rs6.net', 'Constant Contact'], ['constantcontact.com', 'Constant Contact'],
  ['customeriomail.com', 'Customer.io'], ['customer.io', 'Customer.io'], ['intercom-mail.com', 'Intercom'], ['intercom-clicks.com', 'Intercom'],
  ['iterable.com', 'Iterable'], ['braze.com', 'Braze'], ['braze.eu', 'Braze'], ['mailjet.com', 'Mailjet'], ['mjt.lu', 'Mailjet'],
  ['sendibt3.com', 'Brevo'], ['sendibm1.com', 'Brevo'], ['brevo.com', 'Brevo'], ['sendinblue.com', 'Brevo'],
  ['convertkit-mail.com', 'Kit (ConvertKit)'], ['convertkit-mail2.com', 'Kit (ConvertKit)'], ['ck.page', 'Kit (ConvertKit)'],
  ['substack.com', 'Substack'], ['beehiiv.com', 'beehiiv'], ['mlsend.com', 'MailerLite'], ['mailerlite.com', 'MailerLite'],
  ['getresponse.com', 'GetResponse'], ['activehosted.com', 'ActiveCampaign'], ['acemlna.com', 'ActiveCampaign'], ['acemlnb.com', 'ActiveCampaign'],
  ['mktoweb.com', 'Marketo'], ['mktdns.com', 'Marketo'], ['marketo.com', 'Marketo'], ['eloqua.com', 'Oracle Eloqua'], ['en25.com', 'Oracle Eloqua'],
  ['zcsend.net', 'Zoho Campaigns'], ['maillist-manage.com', 'Zoho Campaigns'], ['omnisend.com', 'Omnisend'], ['drip.com', 'Drip'],
  ['google-analytics.com', 'Google Analytics'], ['doubleclick.net', 'Google Ads'], ['facebook.com/tr', 'Meta Pixel'], ['px.ads.linkedin.com', 'LinkedIn Ads'],
];

/** URL paths typical of open-tracking pixels. */
const PIXEL_PATH = /(\/open(\.gif|\.png|\.aspx)?([/?]|$)|\/wf\/open|\/track\/open|\/trk\/|\/tracking\/|\/pixel|\/beacon|\/o\.gif|\/e\/o\/|\/oo\/|\/imp\b|\/t\.gif|\/1x1|spacer\.gif|\/ss\/o\/)/i;

export function serviceForUrl(url: string): string | null {
  const u = safeUrl(url);
  if (!u) return null;
  const host = u.hostname.toLowerCase();
  const hostPath = host + u.pathname.toLowerCase();
  for (const [suffix, name] of SERVICES) {
    if (suffix.includes('/') ? hostPath.startsWith(suffix) || hostPath.includes(`.${suffix}`) : host === suffix || host.endsWith(`.${suffix}`)) return name;
  }
  return null;
}

function px(value: string | null | undefined): number | null {
  if (value == null) return null;
  const m = value.trim().match(/^(\d+(?:\.\d+)?)(px)?$/i);
  return m ? parseFloat(m[1]!) : null;
}

function styleOf(el: Element): Record<string, string> {
  const out: Record<string, string> = {};
  for (const decl of (el.getAttribute('style') ?? '').split(';')) {
    const i = decl.indexOf(':');
    if (i > 0) out[decl.slice(0, i).trim().toLowerCase()] = decl.slice(i + 1).trim().toLowerCase();
  }
  return out;
}

/** Why an <img> looks like an open-tracking pixel, or null if it looks like a real image. */
function pixelReason(img: Element, src: string): string | null {
  const st = styleOf(img);
  const w = px(img.getAttribute('width')) ?? px(st['width']);
  const h = px(img.getAttribute('height')) ?? px(st['height']);
  if ((w !== null && w <= 3) && (h === null || h <= 3)) return `${w}×${h ?? w} pixel image`;
  if ((h !== null && h <= 3) && w === null) return `${h}px tall image`;
  if (st['display']?.startsWith('none') || st['visibility']?.startsWith('hidden')) return 'hidden image';
  if (st['opacity'] !== undefined && parseFloat(st['opacity']) <= 0.05) return 'invisible image';
  if (PIXEL_PATH.test(safeUrl(src)?.pathname ?? '')) return 'image at a tracking address';
  return null;
}

/**
 * Finds open-tracking pixels (tiny/hidden remote images) and click-tracked
 * links. These are about privacy, not phishing: they tell the sender when and
 * where you opened the email, so findings carry no risk points.
 */
export function analyzeTrackers(html: string | null, links: LinkInfo[]): { trackers: TrackerReport; findings: Finding[]; annotatedHtml: string | null } {
  const pixels: TrackerPixel[] = [];
  let remoteImages = 0;
  let annotatedHtml: string | null = null;

  if (html) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    const imgs = Array.from(doc.querySelectorAll('img[src]'));
    const found: { el: Element; src: string; service: string | null; reason: string; kind: 'img' | 'background' }[] = [];
    imgs.forEach((img) => {
      const src = (img.getAttribute('src') ?? '').trim();
      if (!/^https?:\/\//i.test(src)) return;
      remoteImages++;
      const service = serviceForUrl(src);
      const reason = pixelReason(img, src);
      if (reason || (service && PIXEL_PATH.test(src))) found.push({ el: img, src, service, reason: reason ?? 'image from a tracking service', kind: 'img' });
    });
    // Hidden CSS background images can track opens too.
    doc.querySelectorAll('[style*="url("]').forEach((el) => {
      const m = (el.getAttribute('style') ?? '').match(/url\(\s*['"]?(https?:\/\/[^'")\s]+)/i);
      if (!m) return;
      const src = m[1]!;
      const service = serviceForUrl(src);
      if (service || PIXEL_PATH.test(src)) found.push({ el, src, service, reason: 'background image from a tracking address', kind: 'background' });
    });

    if (found.length && doc.body) {
      // Walk the body in reading order once: text lengths before each pixel, and the text around it.
      // Text in reading order, with a space where a block starts, so "today.</p><p>Unsubscribe" reads "today. Unsubscribe".
      const order: (string | Element)[] = [];
      const walker = doc.createTreeWalker(doc.body, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
      const targets = new Set(found.map((f) => f.el));
      const BLOCK = /^(P|DIV|TD|TH|TR|LI|BR|H[1-6]|TABLE|SECTION|ARTICLE|HEADER|FOOTER|BLOCKQUOTE|UL|OL|CENTER)$/;
      for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        if (node.nodeType === 3) {
          const parent = (node as Text).parentElement;
          if (parent && !parent.closest('style, script, head, title, [data-unmask-hidden]')) order.push((node as Text).data);
        } else if (targets.has(node as Element)) order.push(node as Element);
        else if (BLOCK.test((node as Element).tagName)) order.push(' ');
      }
      const clean = (t: string) => t.replace(/\s+/g, ' ');
      const texts = order.map((n) => (typeof n === 'string' ? clean(n) : ''));
      // Measured exactly like the text before each pixel (whitespace collapsed, trimmed), so the end is 100%.
      const total = clean(texts.join('')).trim().length || 1;
      found.forEach((f, i) => {
        const at = order.indexOf(f.el);
        const beforeText = clean(texts.slice(0, Math.max(at, 0)).join('')).trim();
        const afterText = clean(texts.slice(at + 1).join('')).trim();
        const st = styleOf(f.el);
        const w = px(f.el.getAttribute('width')) ?? px(st['width']);
        const h = px(f.el.getAttribute('height')) ?? px(st['height']);
        f.el.setAttribute('data-unmask-pixel', String(i + 1));
        pixels.push({
          src: f.src,
          host: safeUrl(f.src)?.hostname ?? '',
          service: f.service,
          reason: f.reason,
          n: i + 1,
          imageIndex: f.kind === 'img' ? imgs.indexOf(f.el) + 1 : 0,
          imageCount: imgs.length,
          positionPct: Math.round((beforeText.length / total) * 100),
          before: beforeText.length > 70 ? `…${beforeText.slice(-70).replace(/^\S*\s/, '')}` : beforeText,
          after: afterText.length > 70 ? `${afterText.slice(0, 70).replace(/\s\S*$/, '')}…` : afterText,
          size: w !== null || h !== null ? `${w ?? '?'}×${h ?? '?'}` : null,
          kind: f.kind,
          inHiddenBlock: Boolean(f.el.closest('[data-unmask-hidden]')),
        });
      });
      annotatedHtml = doc.documentElement.outerHTML;
    }
  }

  const trackedLinks = links.filter((l) => serviceForUrl(l.href) !== null);
  const services = [...new Set([...pixels.map((p) => p.service), ...trackedLinks.map((l) => serviceForUrl(l.href))].filter((s): s is string => !!s))];
  const trackers: TrackerReport = { pixels, trackedLinkCount: trackedLinks.length, services, remoteImages };

  const findings: Finding[] = [];
  if (pixels.length) {
    findings.push({
      id: 'tracking-pixel',
      category: 'privacy',
      severity: 'info',
      points: 0,
      title: `${pixels.length} tracking pixel${pixels.length === 1 ? '' : 's'}${services.length ? ` (${services.slice(0, 3).join(', ')})` : ''}`,
      detail: 'Loading images tells the sender that and when you opened the email (in Gmail, through Google’s image proxy, without your IP address). Unmask’s safe view and Peek never load them.',
      target: { kind: 'tab', tab: 'privacy' },
    });
  }
  if (trackedLinks.length) {
    findings.push({
      id: 'tracked-links',
      category: 'privacy',
      severity: 'info',
      points: 0,
      title: `${trackedLinks.length} link${trackedLinks.length === 1 ? ' is' : 's are'} click-tracked`,
      detail: 'Clicking them reports the click to a mailing service before sending you on. Normal for newsletters.',
      target: { kind: 'tab', tab: 'privacy' },
    });
  }
  return { trackers, findings, annotatedHtml };
}
