/**
 * Active content inside SVG images and HTML attachments: the code an image or
 * page runs when it is opened. In 2026 SVG files became a favourite way to
 * smuggle phishing pages past filters (Microsoft saw a single three-day SVG
 * campaign of 1.2 million messages), because mail filters treat them as
 * pictures while browsers run them like web pages.
 *
 * Nothing here runs the file: the text is read and matched only.
 */
import type { Anomaly, ExtractedLink } from './types';

export interface MarkupResult {
  anomalies: Anomaly[];
  links: ExtractedLink[];
}

const URL_IN_QUOTES = /["'`](https?:\/\/[^"'`\s<>]{4,500})["'`]/g;
const BASE64_CALL = /\batob\s*\(\s*["'`]([A-Za-z0-9+/=_-]{16,})["'`]\s*\)/g;
const BASE64_DATA = /data:(?:text\/html|image\/svg\+xml|application\/(?:x-)?javascript|text\/javascript)[^,]{0,40};base64,([A-Za-z0-9+/=]{24,})/gi;
const REDIRECT = /\b(?:(?:window|top|self|document|parent)\s*\.\s*)?location(?:\s*\.\s*(?:href|replace|assign))?\s*(?:=(?!=)|\()|\bwindow\s*\.\s*open\s*\(|<meta[^>]+http-equiv\s*=\s*["']?refresh/i;
const HANDLER = /<[a-z][^>]*\s(on(?:load|error|begin|end|click|mouseover|mouseenter|focus|focusin|animationstart|animationend|repeat|activate))\s*=/i;
const SCRIPT = /<script[\s>]/i;
const SCRIPT_HREF = /(?:href|xlink:href|src|action)\s*=\s*["']?\s*(?:javascript:|data:text\/html|vbscript:)/i;
const FOREIGN_FORM = /<foreignObject[\s\S]{0,20000}?<(?:form|input|iframe|textarea)\b/i;
const PASSWORD = /type\s*=\s*["']?password/i;
const SMUGGLE = /\b(?:URL|webkitURL)\s*\.\s*createObjectURL\s*\(|new\s+Blob\s*\(|msSaveOrOpenBlob|\.download\s*=/;
const CAPTCHA = /\b(?:turnstile|hcaptcha|h-captcha|recaptcha|g-recaptcha|cf-chl|verify (?:you are|you're) (?:a )?human|i'?m not a robot|human verification)\b/i;
const EMAIL = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}/g;
/** Emails that appear in ordinary SVG and HTML files and say nothing about the reader. */
const BENIGN_EMAIL = /@(?:w3\.org|example\.(?:com|org|net)|sentry\.io|adobe\.com|inkscape\.org|sodipodi\.sourceforge\.net)$/i;

function decodeBase64(s: string): string | null {
  try {
    const clean = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(clean + '='.repeat((4 - (clean.length % 4)) % 4));
    // Keep only text-looking results; binary blobs are handled by the IOC extractor.
    const printable = [...bin.slice(0, 400)].filter((c) => /[\x09\x0a\x0d\x20-\x7e]/.test(c)).length;
    return printable >= Math.min(bin.length, 400) * 0.9 ? bin : null;
  } catch {
    return null;
  }
}

/** Script-ish text inside the file, where a redirect or recipient address means something. */
function scriptText(text: string): string {
  const parts: string[] = [];
  for (const m of text.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)) parts.push(m[1] ?? '');
  for (const m of text.matchAll(/\son[a-z]+\s*=\s*(["'])([\s\S]*?)\1/gi)) parts.push(m[2] ?? '');
  for (const m of text.matchAll(/<!\[CDATA\[([\s\S]*?)\]\]>/g)) parts.push(m[1] ?? '');
  return parts.join('\n');
}

/**
 * Reads an SVG image or HTML file and reports what would happen if it were
 * opened: scripts, redirects, embedded login pages, hidden (base64) pages,
 * file smuggling and CAPTCHA gates.
 */
export function analyzeMarkup(text: string, isSvg: boolean): MarkupResult {
  const anomalies: Anomaly[] = [];
  const links: ExtractedLink[] = [];
  const add = (a: Anomaly) => { if (!anomalies.some((x) => x.id === a.id)) anomalies.push(a); };
  const what = isSvg ? 'This image' : 'This page';
  const smuggling = isSvg ? 'T1027.017' : 'T1027.006';

  // What the file decodes to counts as much as what it says in the open.
  const hidden: string[] = [];
  for (const m of text.matchAll(BASE64_CALL)) { const d = decodeBase64(m[1]!); if (d) hidden.push(d); }
  for (const m of text.matchAll(BASE64_DATA)) { const d = decodeBase64(m[1]!); if (d) hidden.push(d); }
  const all = hidden.length ? `${text}\n${hidden.join('\n')}` : text;
  const code = `${scriptText(text)}\n${hidden.join('\n')}`;

  const hasScript = SCRIPT.test(all);
  const handler = all.match(HANDLER)?.[1];
  if (isSvg && hasScript) add({ id: 'svg-script', severity: 'high', title: 'SVG image contains JavaScript', plain: 'Pictures don’t need code. This image runs a program in your browser when you open it, which is how fake login pages are smuggled in as “images”.', attack: smuggling });
  if (handler) add({ id: 'markup-event-handler', severity: isSvg ? 'high' : 'medium', title: `Runs code as soon as it is shown (${handler})`, detail: `An ${handler} attribute starts code without a click.`, plain: `${what} starts running code the moment it is displayed.`, attack: smuggling });
  if (SCRIPT_HREF.test(all)) add({ id: 'markup-script-link', severity: 'high', title: 'Links that run code (javascript: or data: addresses)', plain: `Clicking inside ${what.toLowerCase()} runs code instead of opening a website.`, attack: 'T1204.001' });
  if (isSvg && FOREIGN_FORM.test(all)) add({ id: 'svg-embedded-page', severity: PASSWORD.test(all) ? 'critical' : 'high', title: PASSWORD.test(all) ? 'SVG image hides a login form' : 'SVG image hides a web page with a form', plain: 'There is a whole web page with a form tucked inside this “image”. Real pictures never ask you to type anything.', attack: 'T1566.001' });

  const redirect = REDIRECT.test(code) || /<meta[^>]+http-equiv\s*=\s*["']?refresh/i.test(all);
  const targets = new Set<string>();
  for (const m of code.matchAll(URL_IN_QUOTES)) targets.add(m[1]!);
  for (const m of all.matchAll(/<meta[^>]+content\s*=\s*["'][^"']*url\s*=\s*([^"'\s>]+)/gi)) targets.add(m[1]!);
  for (const d of hidden) for (const m of d.matchAll(/https?:\/\/[^\s"'`<>]{4,500}/g)) targets.add(m[0]);
  if (redirect) {
    const first = [...targets][0];
    add({ id: 'markup-redirect', severity: 'high', title: first ? `Sends your browser to ${hostOf(first)}` : 'Sends your browser to another website when opened', detail: first ? `Redirect target: ${first}` : undefined, plain: `Opening ${what.toLowerCase()} takes you straight to a website, usually a fake login page, without you clicking anything.`, attack: 'T1204.001' });
  }
  if (hidden.length && (redirect || hasScript || /<(?:html|form|script|svg)\b/i.test(hidden.join('\n')))) add({ id: 'markup-hidden-payload', severity: 'high', title: 'Hides code or a web page in encoded (base64) text', detail: `${hidden.length} encoded block${hidden.length === 1 ? '' : 's'} decoded.`, plain: 'Part of the file is scrambled so filters can’t read it. Unmask unscrambled it: it is code or a web page.', attack: 'T1027' });
  if (SMUGGLE.test(code)) add({ id: 'markup-smuggling', severity: 'high', title: 'Builds and downloads a file from inside itself (smuggling)', plain: `${what} assembles a file in your browser and saves it, which slips malware past email filters.`, attack: smuggling });
  if (CAPTCHA.test(all) && (redirect || hasScript || PASSWORD.test(all))) add({ id: 'markup-captcha', severity: 'medium', title: 'Shows a CAPTCHA before the real content', plain: 'Phishing kits put a “prove you’re human” check in front of fake login pages so security scanners can’t see them.', attack: 'T1564' });

  const recipients = [...new Set([...code.matchAll(EMAIL)].map((m) => m[0]).filter((e) => !BENIGN_EMAIL.test(e)))];
  if (recipients.length && (redirect || hasScript)) add({ id: 'markup-personalised', severity: 'medium', title: `Carries an email address (${recipients[0]}) for a pre-filled login`, plain: 'The file has an email address built in, so the fake login page can greet you by name and look real.' });

  for (const url of targets) links.push({ url, where: isSvg ? 'script in SVG image' : 'script in page', how: hidden.some((h) => h.includes(url)) ? 'decoded' : 'action' });
  return { anomalies, links };
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url.slice(0, 60);
  }
}
