/**
 * Outlines the part of an open Gmail message that a finding refers to.
 * Uses only DOM APIs that are allowed under Gmail's Trusted Types policy
 * (no HTML strings), and every change is reversible with clearHighlights().
 */
import type { GmailMessageRef } from './messages';

export type HighlightTarget =
  | { kind: 'links'; hrefs: string[] }
  | { kind: 'sender' }
  | { kind: 'attachments'; names: string[] }
  | { kind: 'text'; phrases: string[] };

const ATTR = 'data-unmask-hl';
const MARK = 'data-unmask-mark';
const STYLE_ID = 'unmask-highlight-style';

const CSS = `
[${ATTR}] { outline: 3px solid #f59e0b !important; outline-offset: 2px !important; border-radius: 4px !important;
  background-color: rgba(250, 204, 21, 0.28) !important; box-shadow: 0 0 0 6px rgba(245, 158, 11, 0.18) !important; }
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

function attachmentElements(root: Element, names: string[]): Element[] {
  const lower = names.map((n) => n.toLowerCase());
  const out = new Set<Element>();
  // Gmail's attachment chips carry download_url="mime:filename:url".
  root.querySelectorAll('[download_url]').forEach((el) => {
    const v = (el.getAttribute('download_url') ?? '').toLowerCase();
    if (lower.some((n) => v.includes(`:${n}:`))) out.add(el);
  });
  if (!out.size) {
    root.querySelectorAll('[aria-label], [title]').forEach((el) => {
      const label = `${el.getAttribute('aria-label') ?? ''} ${el.getAttribute('title') ?? ''}`.toLowerCase();
      if (lower.some((n) => label.includes(n))) out.add(el);
    });
  }
  return [...out];
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

export function clearHighlights(doc: Document): void {
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
  else if (target.kind === 'attachments') els = attachmentElements(root, target.names);
  else if (target.kind === 'text') {
    els = markPhrases(root, target.phrases);
    if (!els.length) {
      els = elementsContaining(root, target.phrases);
      els.forEach((el) => el.setAttribute(ATTR, ''));
    }
  }

  if (target.kind !== 'text') els.forEach((el) => el.setAttribute(ATTR, ''));
  const first = els[0] as HTMLElement | undefined;
  if (scroll && first && typeof first.scrollIntoView === 'function') {
    const r = first.getBoundingClientRect();
    const view = doc.defaultView;
    const visible = view ? r.top >= 0 && r.bottom <= view.innerHeight : true;
    if (!visible) first.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }
  return els.length;
}
