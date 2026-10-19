import type { Finding, LinkFlag, LinkInfo, Severity } from '../core/types';
import type { RawLink } from './content';
import { hostInfo, registrableDomain, safeUrl, sameOrg } from '../lib/domain';
import { detectLookalike } from './lookalike';

const SHORTENERS = new Set([
  'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
  'rb.gy', 'tiny.cc', 't.ly', 'v.gd', 'bl.ink', 'short.io', 'lnkd.in', 'qrco.de', 's.id', 'shorturl.gg', 'urlz.fr', 'clck.ru', 'surl.li',
]);

/** Free hosting / form / file-sharing services phishing kits like to live on. */
const ABUSED_HOSTS = [
  'firebaseapp.com', 'web.app', 'pages.dev', 'workers.dev', 'netlify.app', 'vercel.app', 'github.io', 'glitch.me', 'repl.co', 'replit.app',
  'weebly.com', 'wixsite.com', 'wix.com', '000webhostapp.com', 'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'blogspot.com',
  'sites.google.com', 'docs.google.com', 'forms.gle', 'forms.office.com', 'sway.office.com', 'storage.googleapis.com', 'blob.core.windows.net',
  'r2.dev', 'ipfs.io', 'dweb.link', 'cloudflare-ipfs.com', 'dropboxusercontent.com', 'herokuapp.com', 'onrender.com', 'square.site',
  'godaddysites.com', 'webflow.io', 'framer.app', 'notion.site', 'canva.site', 'typeform.com', 'jotform.com', 'surge.sh', 'translate.goog',
];

/** Email service providers whose click-tracking hosts legitimately differ from the link text. */
const TRACKERS = [
  'sendgrid.net', 'list-manage.com', 'mailchimp.com', 'mcusercontent.com', 'mandrillapp.com', 'hubspotlinks.com', 'hs-sites.com',
  'mailgun.org', 'sparkpostmail.com', 'exacttarget.com', 'rs6.net', 'createsend.com', 'cmail19.com', 'cmail20.com', 'klaviyo.com',
  'klclick.com', 'mlsend.com', 'convertkit-mail.com', 'ck.page', 'substack.com', 'beehiiv.com', 'mailjet.com', 'sendibt3.com',
  'brevo.com', 'awstrack.me', 'pstmrk.it', 'customeriomail.com', 'intercom-clicks.com', 'salesforce.com', 'marketo.com', 'mktoweb.com',
  'eloqua.com', 'iterable.com', 'braze.com', 'links.sendinblue.com', 'emltrk.com', 'linktrack.info', 'urldefense.com',
];

const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'xyz', 'top', 'click', 'link', 'country', 'gq', 'ml', 'cf', 'tk', 'ga', 'work', 'support', 'rest', 'fit', 'cam',
  'quest', 'sbs', 'cfd', 'icu', 'buzz', 'monster', 'bond', 'lol', 'shop', 'live', 'online', 'site', 'website', 'info', 'pw', 'cc',
]);

const DOWNLOAD_EXT = /\.(exe|scr|msi|bat|cmd|js|vbs|hta|ps1|jar|apk|iso|img|zip|rar|7z|lnk|one|docm|xlsm|html?|svg)(\?|#|$)/i;

function matchesHost(host: string, list: string[]): boolean {
  return list.some((h) => host === h || host.endsWith(`.${h}`));
}

/** Peels off well-known redirect / "safe link" wrappers without making any network request. */
export function unwrapUrl(href: string): { url: string; via: string[] } {
  const via: string[] = [];
  let current = href;
  for (let i = 0; i < 6; i++) {
    const u = safeUrl(current);
    if (!u) break;
    const host = u.hostname.toLowerCase();
    const q = (k: string) => u.searchParams.get(k);
    let next: string | null = null;
    let name = '';

    if (/(^|\.)google\.[a-z.]+$/.test(host) && u.pathname === '/url') {
      next = q('q') ?? q('url');
      name = 'Google redirect';
    } else if (host.endsWith('safelinks.protection.outlook.com')) {
      next = q('url');
      name = 'Microsoft Safe Links';
    } else if (host === 'urldefense.proofpoint.com' && q('u')) {
      next = decodeURIComponent(q('u')!.replace(/-/g, '%').replace(/_/g, '/'));
      name = 'Proofpoint URL Defense';
    } else if (host === 'urldefense.com' && u.pathname.startsWith('/v3/__')) {
      next = u.href.slice(u.href.indexOf('/v3/__') + 6).split('__;')[0] ?? null;
      name = 'Proofpoint URL Defense';
    } else if ((host === 'l.facebook.com' || host === 'lm.facebook.com' || host === 'l.instagram.com') && q('u')) {
      next = q('u');
      name = 'Facebook link shim';
    } else if (host.endsWith('youtube.com') && u.pathname === '/redirect') {
      next = q('q');
      name = 'YouTube redirect';
    } else if (host.endsWith('linkedin.com') && u.pathname.startsWith('/redir')) {
      next = q('url');
      name = 'LinkedIn redirect';
    } else if (host === 'slack-redir.net') {
      next = q('url');
      name = 'Slack redirect';
    } else {
      // Generic open-redirect parameters (?url=https://…)
      for (const key of ['url', 'u', 'target', 'dest', 'destination', 'redirect', 'redirect_uri', 'redirect_url', 'redir', 'goto', 'link', 'next', 'continue', 'r']) {
        const v = q(key);
        if (v && /^https?:\/\//i.test(v) && safeUrl(v)) {
          next = v;
          name = `redirect parameter on ${registrableDomain(host)}`;
          break;
        }
      }
    }
    if (!next || next === current || !safeUrl(next)) break;
    via.push(name);
    current = next;
  }
  return { url: current, via };
}

/** Extracts a domain-looking token from visible link text ("www.paypal.com/signin" → "www.paypal.com"). */
function domainInText(text: string): string | null {
  const m = text.trim().match(/^(?:https?:\/\/)?((?:[a-z0-9¡-￿-]+\.)+[a-z¡-￿]{2,})(?:[/:?#]|\s|$)/i);
  if (!m) return null;
  const host = m[1]!.toLowerCase();
  const info = hostInfo(host);
  return info.suffix ? host : null;
}

const SEVERITY_ORDER: Severity[] = ['good', 'info', 'low', 'medium', 'high', 'critical'];

interface FlagSpec {
  severity: Severity;
  points: number;
  title: string;
}

const FLAG_SPECS: Record<string, FlagSpec> = {
  'dangerous-scheme': { severity: 'critical', points: 30, title: 'Link runs code or embeds data instead of opening a website' },
  'text-mismatch': { severity: 'high', points: 25, title: 'Link text shows one website but goes to another' },
  'lookalike': { severity: 'critical', points: 35, title: 'Link goes to a domain imitating a well-known brand' },
  'brand-in-domain': { severity: 'high', points: 18, title: 'Link domain uses a brand name it does not own' },
  'punycode': { severity: 'high', points: 20, title: 'Link uses an internationalised (punycode) domain' },
  'userinfo': { severity: 'high', points: 25, title: 'Link hides its real host behind an @ sign' },
  'ip-host': { severity: 'high', points: 20, title: 'Link points straight at an IP address' },
  'shortener': { severity: 'medium', points: 10, title: 'Link uses a URL shortener that hides the destination' },
  'abused-host': { severity: 'medium', points: 10, title: 'Link is hosted on a free hosting / forms service often used for phishing' },
  'open-redirect': { severity: 'medium', points: 8, title: 'Link bounces through a redirect on another site' },
  'download': { severity: 'medium', points: 10, title: 'Link downloads a risky file type' },
  'tracker-mismatch': { severity: 'low', points: 3, title: 'Link goes through a mail tracking service, so the final site is unknown' },
  'suspicious-tld': { severity: 'low', points: 6, title: 'Link uses a domain ending that is popular with scammers' },
  'many-subdomains': { severity: 'low', points: 5, title: 'Link has an unusually long chain of subdomains' },
  'odd-port': { severity: 'low', points: 5, title: 'Link uses a non-standard port' },
  'no-https': { severity: 'low', points: 3, title: 'Link is not encrypted (http://)' },
};

function flag(id: keyof typeof FLAG_SPECS, label: string): LinkFlag {
  return { id, severity: FLAG_SPECS[id]!.severity, label };
}

export function inspectLink(raw: RawLink): LinkInfo {
  const flags: LinkFlag[] = [];
  const scheme = (raw.href.match(/^([a-z][a-z0-9+.-]*):/i)?.[1] ?? '').toLowerCase();

  if (scheme === 'javascript' || scheme === 'data' || scheme === 'vbscript') {
    flags.push(flag('dangerous-scheme', `${scheme}: link`));
    return { href: raw.href, text: raw.text, resolved: raw.href, unwrappedVia: [], host: '', domain: '', scheme, source: raw.source, flags };
  }

  const { url: resolved, via } = unwrapUrl(raw.href);
  const u = safeUrl(resolved);
  const host = u?.hostname.toLowerCase().replace(/^\[|\]$/g, '') ?? '';
  const info = hostInfo(host);
  const domain = info.domain;

  if (via.some((v) => v.startsWith('redirect parameter'))) flags.push(flag('open-redirect', via.join(' → ')));
  if (u && (u.username || u.password)) flags.push(flag('userinfo', `real host is ${host}`));
  if (info.isIp) flags.push(flag('ip-host', host));
  if (info.isPunycode) flags.push(flag('punycode', `${host} displays as ${info.unicodeHost}`));

  const look = host ? detectLookalike(host) : null;
  if (look) {
    if (look.kind === 'homoglyph' || look.kind === 'typo') flags.push(flag('lookalike', `${host} ${look.explanation} (${look.brand.name})`));
    else flags.push(flag('brand-in-domain', `${host} ${look.explanation}`));
  }

  if (SHORTENERS.has(host) || SHORTENERS.has(domain)) flags.push(flag('shortener', host));
  if (matchesHost(host, ABUSED_HOSTS)) flags.push(flag('abused-host', host));
  if (info.suffix && SUSPICIOUS_TLDS.has(info.suffix.split('.').pop()!)) flags.push(flag('suspicious-tld', `.${info.suffix}`));
  if (info.subdomainDepth >= 4) flags.push(flag('many-subdomains', host));
  if (u?.port && !['80', '443'].includes(u.port)) flags.push(flag('odd-port', `port ${u.port}`));
  if (u && DOWNLOAD_EXT.test(u.pathname)) flags.push(flag('download', u.pathname.split('/').pop() ?? u.pathname));
  if (u?.protocol === 'http:' && !info.isIp) flags.push(flag('no-https', host));

  const shown = domainInText(raw.text);
  if (shown && host && !sameOrg(shown, host)) {
    const originalHost = safeUrl(raw.href)?.hostname.toLowerCase() ?? '';
    const viaTracker = matchesHost(originalHost, TRACKERS) || matchesHost(host, TRACKERS);
    if (viaTracker || SHORTENERS.has(domain)) flags.push(flag('tracker-mismatch', `shows ${shown}, goes via ${host}`));
    else flags.push(flag('text-mismatch', `shows ${shown}, really goes to ${host}`));
  }

  flags.sort((a, b) => SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity));
  return { href: raw.href, text: raw.text, resolved, unwrappedVia: via, host, domain, scheme, source: raw.source, flags };
}

/** Inspects every link and aggregates flags into one finding per flag type. */
export function analyzeLinks(rawLinks: RawLink[]): { links: LinkInfo[]; findings: Finding[] } {
  const unique = new Map<string, RawLink>();
  for (const l of rawLinks) {
    const key = `${l.href}\u0000${l.text}`;
    if (!unique.has(key)) unique.set(key, l);
  }
  const links = [...unique.values()].map(inspectLink);

  const byFlag = new Map<string, LinkFlag[]>();
  for (const link of links) for (const f of link.flags) byFlag.set(f.id, [...(byFlag.get(f.id) ?? []), f]);

  const findings: Finding[] = [];
  for (const [id, flags] of byFlag) {
    const spec = FLAG_SPECS[id];
    if (!spec) continue;
    const examples = [...new Set(flags.map((f) => f.label))];
    // A couple of extra points when the same problem repeats, capped so one issue can't dominate.
    const points = Math.min(spec.points + (flags.length - 1) * 2, spec.points + 8);
    findings.push({
      id: `link-${id}`,
      category: 'links',
      severity: spec.severity,
      points,
      title: flags.length > 1 ? `${spec.title} (${flags.length} links)` : spec.title,
      detail: examples.slice(0, 3).join('; ') + (examples.length > 3 ? `; +${examples.length - 3} more` : ''),
    });
  }
  return { links, findings };
}
