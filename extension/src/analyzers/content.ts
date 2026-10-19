import type { Finding, HiddenSnippet, ParsedEmail } from '../core/types';

export interface RawLink {
  href: string;
  text: string;
  source: 'html' | 'text';
}

export interface ContentResult {
  findings: Finding[];
  hidden: HiddenSnippet[];
  annotatedHtml: string | null;
  links: RawLink[];
  visibleText: string;
}

const URGENCY = [
  /within \d+ (hours?|hrs?|days?)/i,
  /\b(immediately|urgent(ly)?|act now|right away|as soon as possible)\b/i,
  /\b(final|last) (notice|warning|reminder)\b/i,
  /account (has been|will be|is|was) (temporarily )?(suspended|locked|limited|restricted|closed|disabled|deactivated|terminated|on hold)/i,
  /\bunusual (activity|sign[- ]?in|login)\b/i,
  /\bsuspicious (activity|sign[- ]?in|login|transaction)\b/i,
  /\b(expires?|expiring|expired) (today|soon|in \d+)/i,
  /\bpermanently (closed|deleted|suspended|disabled)\b/i,
  /\bfailure to (comply|verify|respond|update)\b/i,
];

const CREDENTIALS = [
  /verify your (account|identity|information|details|email|login)/i,
  /confirm your (password|account|identity|details|information|credentials)/i,
  /update your (payment|billing|account|card|bank) (information|details|method)/i,
  /re-?enter your (password|credentials|details)/i,
  /(log ?in|sign ?in) (now )?to (restore|unlock|verify|reactivate|avoid)/i,
  /\bvalidate your (account|mailbox|email|password)\b/i,
  /\bunlock your account\b/i,
  /\bmailbox (is )?(full|quota|storage)\b/i,
  /\b(password|passcode) (expires?|expired|expiring)\b/i,
];

const MONEY = [
  /\bgift ?cards?\b/i,
  /\bwire transfer\b/i,
  /\b(bitcoin|btc|usdt|crypto(currency)? wallet)\b/i,
  /\b(payment|invoice) (is )?(overdue|past due|pending)\b/i,
  /\b(you have|you've) (won|been selected)\b/i,
  /\b(unclaimed|claim your) (refund|prize|reward|funds)\b/i,
  /\btax refund\b/i,
];

function matches(text: string, patterns: RegExp[]): string[] {
  const found = new Set<string>();
  for (const p of patterns) {
    const m = text.match(p);
    if (m) found.add(m[0].toLowerCase());
  }
  return [...found];
}

/** Very rough colour normalisation for "white text on white background" checks. */
function normColor(c: string | undefined): string | null {
  if (!c) return null;
  const v = c.trim().toLowerCase().replace(/\s+/g, '').replace(/!important$/, '');
  const named: Record<string, string> = { white: '#ffffff', '#fff': '#ffffff', 'rgb(255,255,255)': '#ffffff', black: '#000000', '#000': '#000000', 'rgb(0,0,0)': '#000000', transparent: 'transparent' };
  return named[v] ?? v;
}

function parseStyle(style: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const decl of style.split(';')) {
    const i = decl.indexOf(':');
    if (i > 0) out[decl.slice(0, i).trim().toLowerCase()] = decl.slice(i + 1).trim().toLowerCase();
  }
  return out;
}

function hiddenReason(el: Element, inheritedBg: string | null): string | null {
  const style = parseStyle(el.getAttribute('style') ?? '');
  if (el.hasAttribute('hidden')) return 'hidden attribute';
  if (style['display']?.startsWith('none')) return 'display:none';
  if (style['visibility']?.startsWith('hidden')) return 'visibility:hidden';
  if (style['opacity'] !== undefined && parseFloat(style['opacity']) <= 0.05) return 'fully transparent';
  const fs = style['font-size'];
  if (fs !== undefined && /^0(\.\d+)?(px|pt|em|rem|%)?/.test(fs) && parseFloat(fs) < 1) return 'zero-size font';
  if ((style['max-height'] === '0' || style['max-height'] === '0px' || style['height'] === '0px' || style['height'] === '0') && style['overflow']?.startsWith('hidden')) return 'collapsed to zero height';
  const color = normColor(style['color'] ?? el.getAttribute('color') ?? undefined);
  const bg = normColor(style['background-color'] ?? style['background'] ?? el.getAttribute('bgcolor') ?? undefined) ?? inheritedBg ?? '#ffffff';
  if (color && color === bg) return 'text colour matches the background';
  return null;
}

/**
 * Inspects the body: hidden text, forms, pressure language, tracking pixels,
 * and collects every link for the link analyzer.
 */
export function analyzeContent(email: ParsedEmail): ContentResult {
  const findings: Finding[] = [];
  const hidden: HiddenSnippet[] = [];
  const links: RawLink[] = [];
  let annotatedHtml: string | null = null;
  let visibleText = email.text ?? '';

  if (email.html) {
    const doc = new DOMParser().parseFromString(email.html, 'text/html');

    // Hidden text. Walk top-down so a hidden parent is reported once, not per child.
    const walk = (el: Element, bg: string | null) => {
      const reason = hiddenReason(el, bg);
      if (reason) {
        const text = (el.textContent ?? '').replace(/\s+/g, ' ').trim();
        if (text.length >= 3) {
          hidden.push({ reason, text: text.length > 300 ? `${text.slice(0, 300)}…` : text });
          el.setAttribute('data-unmask-hidden', reason);
        }
        return;
      }
      const style = parseStyle(el.getAttribute('style') ?? '');
      const ownBg = normColor(style['background-color'] ?? style['background'] ?? el.getAttribute('bgcolor') ?? undefined);
      for (const child of Array.from(el.children)) walk(child, ownBg ?? bg);
    };
    if (doc.body) walk(doc.body, null);
    annotatedHtml = doc.documentElement.outerHTML;

    // Visible text (with hidden nodes removed) for phrase matching.
    const clone = doc.body?.cloneNode(true) as HTMLElement | undefined;
    clone?.querySelectorAll('[data-unmask-hidden], style, script, head, title').forEach((n) => n.remove());
    visibleText = `${(clone?.textContent ?? '').replace(/\s+/g, ' ')} ${email.text ?? ''}`;

    // Links
    doc.querySelectorAll('a[href], area[href]').forEach((a) => {
      const href = (a.getAttribute('href') ?? '').trim();
      if (!href || href.startsWith('#') || /^mailto:|^tel:|^cid:/i.test(href)) return;
      const img = a.querySelector('img[alt]');
      const text = ((a.textContent ?? '').replace(/\s+/g, ' ').trim() || img?.getAttribute('alt') || '').slice(0, 200);
      links.push({ href, text, source: 'html' });
    });

    // Forms inside an email are almost never legitimate.
    const forms = doc.querySelectorAll('form');
    if (forms.length) {
      const password = doc.querySelector('input[type="password" i]');
      findings.push({
        id: 'html-form',
        category: 'content',
        severity: password ? 'critical' : 'high',
        points: password ? 35 : 20,
        title: password ? 'The email contains a password field' : 'The email contains a form',
        detail: `Form submits to ${forms[0]!.getAttribute('action') || 'an unknown address'}. Legitimate services never ask you to type credentials into an email.`,
      });
    }

    if (doc.querySelector('script')) {
      findings.push({ id: 'html-script', category: 'content', severity: 'medium', points: 10, title: 'The email contains JavaScript', detail: 'Email clients block it, but its presence suggests a hand-crafted malicious message.' });
    }

    const pixels = Array.from(doc.querySelectorAll('img[src^="http"]')).filter((img) => {
      const w = img.getAttribute('width');
      const h = img.getAttribute('height');
      return (w === '1' || w === '0') && (h === '1' || h === '0');
    });
    if (pixels.length) {
      findings.push({ id: 'tracking-pixel', category: 'content', severity: 'info', points: 0, title: 'Contains a tracking pixel', detail: 'Opening the email with images on tells the sender you read it. Unmask blocks remote images in its safe view.' });
    }

    if (hidden.length) {
      const total = hidden.reduce((n, h) => n + h.text.length, 0);
      const big = total > 150;
      findings.push({
        id: 'hidden-text',
        category: 'content',
        severity: big ? 'medium' : 'info',
        points: big ? 10 : 2,
        title: `${hidden.length} hidden text block${hidden.length > 1 ? 's' : ''} (${total} characters)`,
        detail: big
          ? 'Large amounts of invisible text are used to trick spam filters. Newsletters sometimes hide a short preview line, which is harmless.'
          : 'Short hidden text is often just an inbox preview line.',
      });
    }
  }

  // Plain-text URLs (and URLs only present in the text part).
  const seen = new Set(links.map((l) => l.href));
  for (const m of (email.text ?? '').matchAll(/\bhttps?:\/\/[^\s<>"')\]]+/gi)) {
    const href = m[0].replace(/[.,;:!?]+$/, '');
    if (!seen.has(href)) {
      seen.add(href);
      links.push({ href, text: href, source: 'text' });
    }
  }

  const haystack = `${email.subject} ${visibleText}`;
  const urgency = matches(haystack, URGENCY);
  if (urgency.length) {
    findings.push({ id: 'urgency', category: 'content', severity: 'medium', points: urgency.length > 1 ? 15 : 10, title: 'Uses pressure and urgency', detail: `Phrases like ${urgency.slice(0, 3).map((u) => `"${u}"`).join(', ')} are designed to make you act before thinking.` });
  }
  const creds = matches(haystack, CREDENTIALS);
  if (creds.length) {
    findings.push({ id: 'credential-request', category: 'content', severity: 'medium', points: 15, title: 'Asks you to verify or re-enter account details', detail: `Found ${creds.slice(0, 3).map((u) => `"${u}"`).join(', ')}.` });
  }
  const money = matches(haystack, MONEY);
  if (money.length) {
    findings.push({ id: 'money-lure', category: 'content', severity: 'low', points: 8, title: 'Mentions money, prizes or payments', detail: `Found ${money.slice(0, 3).map((u) => `"${u}"`).join(', ')}.` });
  }

  return { findings, hidden, annotatedHtml, links, visibleText };
}
