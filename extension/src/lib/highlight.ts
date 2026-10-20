/**
 * Outlines the part of an open Gmail message that a finding refers to.
 * Uses only DOM APIs that are allowed under Gmail's Trusted Types policy
 * (no HTML strings), and every change is reversible with clearHighlights().
 */
import type { GmailMessageRef } from './messages';

export type HighlightTarget =
  | { kind: 'links'; hrefs: string[] }
  | { kind: 'sender' }
  /** `index`: position among the email's real (non-inline) attachments, used when names don't settle it. */
  | { kind: 'attachments'; names: string[]; index?: number }
  | { kind: 'text'; phrases: string[] }
  /** A tracking pixel, by the address it loads from; marked with a visible label because it is 1×1. */
  | { kind: 'pixel'; src: string; n: number };

const ATTR = 'data-unmask-hl';
const MARK = 'data-unmask-mark';
const STYLE_ID = 'unmask-highlight-style';
const PIXEL_MARK = 'data-unmask-pixel-mark';

const CSS = `
[${ATTR}] { outline: 3px solid #f59e0b !important; outline-offset: 2px !important; border-radius: 4px !important;
  background-color: rgba(250, 204, 21, 0.28) !important; box-shadow: 0 0 0 6px rgba(245, 158, 11, 0.18) !important; }
[${PIXEL_MARK}] { display: inline-block !important; margin: 2px 4px !important; padding: 1px 8px !important; border-radius: 9px !important;
  font: 600 12px/1.6 Roboto, Arial, sans-serif !important; color: #fff !important; background: #d93025 !important; box-shadow: 0 0 0 3px #fbbc04 !important; }
mark[${MARK}] { background: #fde047 !important; color: #111 !important; border-radius: 3px; padding: 0 2px;
  box-shadow: 0 0 0 2px #f59e0b; }
`;

export function ensureStyle(doc: Document): void {
  if (doc.getElementById(STYLE_ID)) return;
  const style = doc.createElement('style');
  style.id = STYLE_ID;
  style.textContent = CSS;
  (doc.head ?? doc.documentElement).appendChild(style);
}

/** The container of one open message, found by Gmail's data attributes. */
export function findMessageRoot(doc: Document, ref: GmailMessageRef): Element | null {
  const byPerm = ref.permId ? doc.querySelector(`[data-message-id="#${CSS_escape(ref.permId)}"], [data-message-id="${CSS_escape(ref.permId)}"]`) : null;
  if (byPerm) return byPerm;
  return ref.legacyId ? doc.querySelector(`[data-legacy-message-id="${CSS_escape(ref.legacyId)}"]`) : null;
}

function CSS_escape(v: string): string {
  return v.replace(/["\\]/g, '\\$&');
}

function bodyOf(root: Element): Element {
  return root.querySelector('.a3s, [data-message-body]') ?? root;
}

function normalise(url: string): string {
  try {
    const u = new URL(url);
    return u.href.replace(/\/$/, '');
  } catch {
    return url.trim();
  }
}

function linkElements(root: Element, hrefs: string[]): Element[] {
  const wanted = new Set(hrefs.map(normalise));
  const exact = linkElementsByHref(root, wanted);
  if (exact.length) return exact;
  // Plain-text parts often print the URL as the link's visible text.
  return Array.from(bodyOf(root).querySelectorAll('a')).filter((a) => wanted.has(normalise((a.textContent ?? '').trim())));
}

function linkElementsByHref(root: Element, wanted: Set<string>): Element[] {
  return Array.from(bodyOf(root).querySelectorAll('a[href], area[href]')).filter((a) => {
    const raw = a.getAttribute('href') ?? '';
    if (wanted.has(normalise(raw))) return true;
    // Gmail sometimes keeps the original only in its safe-redirect attribute.
    const safe = a.getAttribute('data-saferedirecturl');
    if (safe) {
      try {
        const q = new URL(safe).searchParams.get('q');
        if (q && wanted.has(normalise(q))) return true;
      } catch {
        // ignore
      }
    }
    return false;
  });
}

function senderElements(root: Element): Element[] {
  const el = root.querySelector('[email]');
  return el ? [el] : [];
}

/** Gmail's attachment tiles in a message, in display order. */
export function attachmentChips(root: Element): Element[] {
  const byUrl = Array.from(root.querySelectorAll('[download_url]'));
  if (byUrl.length) return byUrl;
  // Newer layouts: one tile per attachment inside the attachment strip.
  const strip = root.querySelector('.aQH');
  if (strip) return Array.from(strip.children).filter((c) => !c.matches('.aZK, .aZJ'));
  return Array.from(root.querySelectorAll('.aZo, .aQy'));
}

/** The file name a tile shows: from download_url ("mime:name:url"), its name label, or its aria-label/title. */
export function chipName(chip: Element): string {
  const url = chip.getAttribute('download_url');
  if (url) {
    const first = url.indexOf(':');
    const last = url.indexOf(':http');
    if (first >= 0 && last > first) return url.slice(first + 1, last);
  }
  const label = chip.querySelector('.aV3')?.textContent ?? chip.getAttribute('aria-label') ?? chip.getAttribute('title') ?? chip.querySelector('[aria-label], [title]')?.getAttribute('aria-label') ?? chip.textContent ?? '';
  return label.replace(/^(attachment|preview attachment|download attachment)\s*:?\s*/i, '').trim();
}

const normName = (s: string) => s.toLowerCase().replace(/\s+/g, ' ').trim();

function attachmentElements(root: Element, names: string[], index?: number): Element[] {
  const chips = attachmentChips(root);
  if (!chips.length) return [];
  const wanted = names.map(normName);
  const labels = chips.map((c) => normName(chipName(c)));
  // 1. The tile's name is exactly the file name.
  let hits = chips.filter((_, i) => wanted.includes(labels[i]!));
  // 2. Gmail shortens long names with an ellipsis: "GST-CHALLAN - K Mallik….pdf".
  if (!hits.length) {
    hits = chips.filter((_, i) => {
      const parts = labels[i]!.split(/…|\.\.\./);
      return parts.length === 2 && wanted.some((w) => w.startsWith(parts[0]!) && w.endsWith(parts[1]!));
    });
  }
  // 3. The tile mentions the name (aria-labels add words around it).
  if (!hits.length) hits = chips.filter((_, i) => wanted.some((w) => labels[i]!.includes(w)));
  // Several matches (two files with the same name) or none: the position decides.
  if (hits.length !== 1 && index !== undefined && chips[index]) {
    const byIndex = chips[index]!;
    if (!hits.length || hits.includes(byIndex)) return [byIndex];
  }
  return hits.slice(0, 1);
}

/** Wraps each occurrence of the phrases in <mark>, splitting text nodes. Returns the marks. */
function markPhrases(root: Element, phrases: string[]): Element[] {
  const doc = root.ownerDocument;
  const needles = phrases.map((p) => p.toLowerCase()).filter((p) => p.length >= 3);
  if (!needles.length) return [];
  const marks: Element[] = [];
  const walker = doc.createTreeWalker(bodyOf(root), NodeFilter.SHOW_TEXT);
  const nodes: Text[] = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) nodes.push(n as Text);

  for (const node of nodes) {
    let current: Text | null = node;
    while (current) {
      const lower: string = current.data.toLowerCase();
      let best = -1;
      let len = 0;
      for (const needle of needles) {
        const i = lower.indexOf(needle);
        if (i >= 0 && (best < 0 || i < best)) {
          best = i;
          len = needle.length;
        }
      }
      if (best < 0) break;
      const match: Text = current.splitText(best);
      const rest: Text = match.splitText(len);
      const mark = doc.createElement('mark');
      mark.setAttribute(MARK, '');
      match.parentNode!.replaceChild(mark, match);
      mark.appendChild(match);
      marks.push(mark);
      current = rest;
    }
  }
  return marks;
}

/**
 * For phrases that cross tags (e.g. "verify <b>your account</b>") text-node marking
 * finds nothing; outline the smallest element whose text contains the phrase instead.
 */
function elementsContaining(root: Element, phrases: string[]): Element[] {
  const body = bodyOf(root);
  const norm = (t: string) => t.replace(/\s+/g, ' ').toLowerCase();
  const out: Element[] = [];
  for (const phrase of phrases.map(norm).filter((p) => p.length >= 3)) {
    if (!norm(body.textContent ?? '').includes(phrase)) continue;
    let best: Element = body;
    let descended = true;
    while (descended) {
      descended = false;
      for (const child of Array.from(best.children)) {
        if (norm(child.textContent ?? '').includes(phrase)) {
          best = child;
          descended = true;
          break;
        }
      }
    }
    if (best !== body && !out.includes(best)) out.push(best);
  }
  return out;
}

/**
 * Gmail shows remote images through its proxy, whose URL ends with "#<original address>",
 * so a pixel is found by its original address in either form.
 */
export function pixelElements(root: Element, src: string): Element[] {
  const want = src.trim();
  return Array.from(bodyOf(root).querySelectorAll('img')).filter((img) => {
    const s = img.getAttribute('src') ?? '';
    if (s === want || s.endsWith(`#${want}`)) return true;
    try {
      return decodeURIComponent(s.split('#').slice(1).join('#')) === want;
    } catch {
      return false;
    }
  });
}

export function clearHighlights(doc: Document): void {
  doc.querySelectorAll(`[${PIXEL_MARK}]`).forEach((el) => el.remove());
  doc.querySelectorAll(`[${ATTR}]`).forEach((el) => el.removeAttribute(ATTR));
  doc.querySelectorAll(`mark[${MARK}]`).forEach((mark) => {
    const parent = mark.parentNode;
    if (!parent) return;
    while (mark.firstChild) parent.insertBefore(mark.firstChild, mark);
    parent.removeChild(mark);
    parent.normalize();
  });
}

/** Highlights the target inside the message and scrolls the first match into view. Returns how many were found. */
export function applyHighlight(doc: Document, ref: GmailMessageRef, target: HighlightTarget | null, scroll = true): number {
  clearHighlights(doc);
  if (!target) return 0;
  const root = findMessageRoot(doc, ref);
  if (!root) return 0;
  ensureStyle(doc);

  let els: Element[] = [];
  if (target.kind === 'links') els = linkElements(root, target.hrefs);
  else if (target.kind === 'sender') els = senderElements(root);
  else if (target.kind === 'attachments') els = attachmentElements(root, target.names, target.index);
  else if (target.kind === 'pixel') {
    // A 1×1 image can't be seen even when outlined: put a label right before it.
    els = pixelElements(root, target.src).map((img) => {
      const label = doc.createElement('span');
      label.setAttribute(PIXEL_MARK, '');
      label.textContent = `● Tracking pixel ${target.n} is here`;
      img.parentNode?.insertBefore(label, img);
      return label;
    });
  }
  else if (target.kind === 'text') {
    els = markPhrases(root, target.phrases);
    if (!els.length) {
      els = elementsContaining(root, target.phrases);
      els.forEach((el) => el.setAttribute(ATTR, ''));
    }
  }

  if (target.kind !== 'text' && target.kind !== 'pixel') els.forEach((el) => el.setAttribute(ATTR, ''));
  const first = els[0] as HTMLElement | undefined;
  if (scroll && first && typeof first.scrollIntoView === 'function') {
    const r = first.getBoundingClientRect();
    const view = doc.defaultView;
    const visible = view ? r.top >= 0 && r.bottom <= view.innerHeight : true;
    if (!visible) first.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }
  return els.length;
}
