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
export function analyzeTrackers(html: string | null, links: LinkInfo[]): { trackers: TrackerReport; findings: Finding[] } {
  const pixels: TrackerPixel[] = [];
  let remoteImages = 0;

  if (html) {
    const doc = new DOMParser().parseFromString(html, 'text/html');
    doc.querySelectorAll('img[src]').forEach((img) => {
      const src = (img.getAttribute('src') ?? '').trim();
      if (!/^https?:\/\//i.test(src)) return;
      remoteImages++;
      const service = serviceForUrl(src);
      const reason = pixelReason(img, src);
      if (reason || (service && PIXEL_PATH.test(src))) {
        pixels.push({ src, host: safeUrl(src)?.hostname ?? '', service, reason: reason ?? 'image from a tracking service' });
      }
    });
    // Hidden CSS background images can track opens too.
    doc.querySelectorAll('[style*="url("]').forEach((el) => {
      const m = (el.getAttribute('style') ?? '').match(/url\(\s*['"]?(https?:\/\/[^'")\s]+)/i);
      if (!m) return;
      const src = m[1]!;
      const service = serviceForUrl(src);
      if (service || PIXEL_PATH.test(src)) pixels.push({ src, host: safeUrl(src)?.hostname ?? '', service, reason: 'background image from a tracking address' });
    });
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
      detail: 'Loading images would tell the sender when you opened the email, your IP address and your device. Unmask blocks them in its safe view.',
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
  return { trackers, findings };
}
