/**
 * Warnings drawn inside Gmail: the banner above a risky email, the badge in
 * the inbox list, and the "Wait…" dialog before a risky link or reply.
 * Each lives in a shadow root so Gmail's CSS can't break it and ours can't
 * leak into Gmail. Built with createElement/textContent only: Gmail enforces
 * Trusted Types, and email-derived text must never become HTML.
 */
import type { Finding, Verdict } from '../core/types';

export const BANNER_ATTR = 'data-unmask-banner';
export const BADGE_ATTR = 'data-unmask-badge';
const DIALOG_ID = 'unmask-dialog-host';

const PALETTE = {
  high: { bg: '#fdecea', border: '#d93025', text: '#a50e0e', label: 'High risk' },
  suspicious: { bg: '#fef7e0', border: '#e8a200', text: '#8a5300', label: 'Suspicious' },
  clear: { bg: '#e6f4ea', border: '#1e8e3e', text: '#0d652d', label: 'No red flags' },
} as const;

const BASE_CSS = `
:host { all: initial; }
* { box-sizing: border-box; font-family: 'Google Sans', Roboto, system-ui, sans-serif; }
button { cursor: pointer; font-family: 'Google Sans', Roboto, system-ui, sans-serif; }
`;

function el<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, props: { className?: string; text?: string; title?: string } = {}, ...children: Node[]): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  if (props.className) node.className = props.className;
  if (props.text !== undefined) node.textContent = props.text;
  if (props.title) node.title = props.title;
  node.append(...children);
  return node;
}

function host(doc: Document, attr: string, css: string): { host: HTMLElement; root: ShadowRoot } {
  const h = doc.createElement('div');
  h.setAttribute(attr, '');
  const root = h.attachShadow({ mode: 'open' });
  root.append(el(doc, 'style', { text: BASE_CSS + css }));
  return { host: h, root };
}

/** The top reasons, worded for the banner. */
export function topReasons(findings: Finding[], max = 3): string[] {
  return findings.filter((f) => f.points > 0 && f.severity !== 'info').slice(0, max).map((f) => f.title);
}

export interface BannerOptions {
  verdict: Verdict;
  /** Plain-language one-liner, e.g. "This email looks like a scam." */
  headline?: string;
  score: number;
  reasons: string[];
  onOpenPanel?: () => void;
  onDismiss?: () => void;
}

export function createBanner(doc: Document, opts: BannerOptions): HTMLElement {
  const p = PALETTE[opts.verdict];
  const { host: h, root } = host(
    doc,
    BANNER_ATTR,
    `.b { margin: 8px 0 12px; padding: 10px 12px; border-radius: 8px; background: ${p.bg}; border: 1px solid ${p.border}; border-left-width: 4px; color: #202124; font-size: 13px; line-height: 1.4; }
     .t { display: flex; align-items: center; gap: 8px; font-weight: 600; color: ${p.text}; font-size: 14px; }
     .s { margin-left: auto; font-weight: 500; font-size: 12px; opacity: .8; }
     .h { margin-top: 4px; font-weight: 500; }
     ul { margin: 6px 0 0; padding-left: 18px; }
     li { margin: 2px 0; }
     .a { margin-top: 8px; display: flex; gap: 8px; }
     .a button { border: 1px solid ${p.border}; background: #fff; color: ${p.text}; border-radius: 6px; padding: 4px 10px; font-size: 12px; font-weight: 500; }
     .a button.x { border-color: transparent; background: transparent; color: #5f6368; }`,
  );
  const icon = opts.verdict === 'clear' ? '✓' : '⚠';
  const title = el(doc, 'div', { className: 't' }, el(doc, 'span', { text: `${icon} Unmask: ${p.label}` }), el(doc, 'span', { className: 's', text: `risk ${opts.score}/100` }));
  const headline = opts.headline ? [el(doc, 'div', { className: 'h', text: opts.headline })] : [];
  const list = el(doc, 'ul', {}, ...opts.reasons.map((r) => el(doc, 'li', { text: r })));
  const actions = el(doc, 'div', { className: 'a' });
  if (opts.onOpenPanel) {
    const b = el(doc, 'button', { text: 'See why' });
    b.addEventListener('click', opts.onOpenPanel);
    actions.append(b);
  }
  if (opts.onDismiss) {
    const b = el(doc, 'button', { className: 'x', text: 'Dismiss' });
    b.addEventListener('click', () => {
      h.remove();
      opts.onDismiss?.();
    });
    actions.append(b);
  }
  root.append(el(doc, 'div', { className: 'b' }, title, ...headline, ...(opts.reasons.length ? [list] : []), ...(actions.childElementCount ? [actions] : [])));
  return h;
}

export function createBadge(doc: Document, verdict: Exclude<Verdict, 'clear'>, reasons: string[]): HTMLElement {
  const p = PALETTE[verdict];
  const { host: h, root } = host(
    doc,
    BADGE_ATTR,
    `.g { display: inline-block; margin: 0 6px 0 4px; padding: 0 6px; border-radius: 9px; font-size: 11px; line-height: 17px; font-weight: 600; white-space: nowrap; vertical-align: middle;
          background: ${p.bg}; color: ${p.text}; border: 1px solid ${p.border}; }`,
  );
  h.style.display = 'inline';
  root.append(el(doc, 'span', { className: 'g', text: verdict === 'high' ? '⚠ Risky' : 'Check', title: `Unmask: ${p.label}\n${reasons.map((r) => `• ${r}`).join('\n')}` }));
  return h;
}

export interface DialogOptions {
  title: string;
  /** Shown large and monospaced, e.g. the real destination host. */
  target?: string;
  reasons: string[];
  proceedLabel: string;
  cancelLabel?: string;
}

/** A modal over Gmail. Resolves true when the user chooses to continue. Escape and the backdrop cancel. */
export function confirmDialog(doc: Document, opts: DialogOptions): Promise<boolean> {
  doc.getElementById(DIALOG_ID)?.remove();
  const { host: h, root } = host(
    doc,
    'data-unmask-dialog',
    `.bg { position: fixed; inset: 0; z-index: 2147483646; background: rgba(32,33,36,.55); display: flex; align-items: center; justify-content: center; }
     .d { width: min(460px, calc(100vw - 32px)); background: #fff; color: #202124; border-radius: 12px; padding: 20px 22px; box-shadow: 0 12px 40px rgba(0,0,0,.35); border-top: 5px solid #d93025; }
     h2 { margin: 0 0 6px; font-size: 18px; font-weight: 600; }
     .tg { margin: 8px 0 10px; padding: 8px 10px; background: #fdecea; border-radius: 6px; font: 600 14px ui-monospace, Menlo, monospace; color: #a50e0e; word-break: break-all; }
     ul { margin: 8px 0 0; padding-left: 18px; font-size: 13px; line-height: 1.45; color: #3c4043; }
     .a { margin-top: 18px; display: flex; gap: 8px; justify-content: flex-end; }
     .a button { border-radius: 6px; padding: 7px 14px; font-size: 13px; font-weight: 600; border: 1px solid #dadce0; background: #fff; color: #3c4043; }
     .a .safe { background: #1a73e8; border-color: #1a73e8; color: #fff; }
     .f { margin-top: 10px; font-size: 11px; color: #80868b; }`,
  );
  h.id = DIALOG_ID;
  return new Promise((resolve) => {
    const done = (v: boolean) => {
      h.remove();
      doc.removeEventListener('keydown', onKey, true);
      resolve(v);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        done(false);
      }
    };
    const cancel = el(doc, 'button', { className: 'safe', text: opts.cancelLabel ?? 'Go back' });
    const go = el(doc, 'button', { text: opts.proceedLabel });
    cancel.addEventListener('click', () => done(false));
    go.addEventListener('click', () => done(true));
    const dialog = el(
      doc,
      'div',
      { className: 'd' },
      el(doc, 'h2', { text: opts.title }),
      ...(opts.target ? [el(doc, 'div', { className: 'tg', text: opts.target })] : []),
      ...(opts.reasons.length ? [el(doc, 'ul', {}, ...opts.reasons.map((r) => el(doc, 'li', { text: r })))] : []),
      el(doc, 'div', { className: 'a' }, go, cancel),
      el(doc, 'div', { className: 'f', text: 'Unmask · checked on your device' }),
    );
    dialog.setAttribute('role', 'alertdialog');
    dialog.setAttribute('aria-modal', 'true');
    const bg = el(doc, 'div', { className: 'bg' }, dialog);
    bg.addEventListener('click', (e) => {
      if (e.target === bg) done(false);
    });
    root.append(bg);
    doc.addEventListener('keydown', onKey, true);
    (doc.body ?? doc.documentElement).append(h);
    cancel.focus();
  });
}

export const PEEK_ATTR = 'data-unmask-peek';
const PEEK_CARD_ID = 'unmask-peek-card';

/** The small "Peek" pill on an inbox row. Swallows its own clicks so Gmail doesn't open the email. */
export function createPeekButton(doc: Document, onPeek: () => void): HTMLElement {
  const { host: h, root } = host(
    doc,
    PEEK_ATTR,
    `.p { display: inline-block; margin: 0 4px; padding: 0 7px; border-radius: 9px; font-size: 11px; line-height: 17px; font-weight: 500; white-space: nowrap; vertical-align: middle;
          background: #f1f3f4; color: #3c4043; border: 1px solid #dadce0; cursor: pointer; }
     .p:hover { background: #e8f0fe; border-color: #1a73e8; color: #1a73e8; }`,
  );
  h.style.display = 'inline';
  const b = el(doc, 'button', { className: 'p', text: '👁 Peek', title: 'Check this email without opening it (Unmask). Images and trackers stay blocked.' });
  b.setAttribute('aria-label', 'Peek: check this email without opening it');
  root.append(b);
  // Stop every pointer event at our element: the row underneath opens the email on click.
  for (const type of ['mousedown', 'mouseup', 'click', 'dblclick', 'pointerdown', 'pointerup']) {
    h.addEventListener(type, (e) => {
      e.stopPropagation();
      if (type === 'click') {
        e.preventDefault();
        onPeek();
      }
    });
  }
  return h;
}

export interface PeekCardData {
  state: 'loading' | 'done' | 'error';
  subject?: string;
  from?: string;
  verdict?: Verdict;
  score?: number;
  headline?: string;
  reasons?: string[];
  preview?: string;
  error?: string;
  onReadSafely?: () => void;
}

/** The floating Peek result. Calling it again updates the same card; Escape or Close removes it. */
export function showPeekCard(doc: Document, data: PeekCardData): () => void {
  doc.getElementById(PEEK_CARD_ID)?.remove();
  const p = data.verdict ? PALETTE[data.verdict] : { bg: '#f8f9fa', border: '#dadce0', text: '#3c4043', label: 'Checking…' };
  const { host: h, root } = host(
    doc,
    'data-unmask-peek-card',
    `.c { position: fixed; top: 76px; right: 24px; z-index: 2147483645; width: min(400px, calc(100vw - 48px)); max-height: calc(100vh - 110px); overflow: auto;
          background: #fff; color: #202124; border-radius: 12px; box-shadow: 0 12px 40px rgba(0,0,0,.28); border-top: 5px solid ${p.border}; padding: 14px 16px; font-size: 13px; line-height: 1.45; }
     .t { display: flex; align-items: center; gap: 8px; font-weight: 600; color: ${p.text}; font-size: 14px; }
     .s { margin-left: auto; font-size: 12px; font-weight: 500; opacity: .8; }
     .x { border: 0; background: transparent; font-size: 18px; line-height: 1; color: #5f6368; padding: 0 2px; }
     .m { margin-top: 8px; color: #5f6368; font-size: 12px; word-break: break-word; }
     .m b { color: #202124; font-weight: 600; }
     .h { margin-top: 10px; font-weight: 600; font-size: 14px; color: ${p.text}; }
     ul { margin: 6px 0 0; padding-left: 18px; }
     .pv { margin-top: 10px; padding: 8px 10px; background: #f8f9fa; border-radius: 8px; max-height: 150px; overflow: auto; white-space: pre-wrap; color: #3c4043; font-size: 12px; }
     .pl { margin-top: 10px; font-size: 10.5px; font-weight: 600; text-transform: uppercase; letter-spacing: .06em; color: #80868b; }
     .a { margin-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; }
     .a button { border-radius: 6px; padding: 6px 12px; font-size: 12.5px; font-weight: 600; border: 1px solid #dadce0; background: #fff; color: #3c4043; }
     .a .go { background: #1a73e8; border-color: #1a73e8; color: #fff; }
     .f { margin-top: 10px; font-size: 11px; color: #188038; }
     .spin { width: 14px; height: 14px; border: 2px solid #dadce0; border-top-color: #1a73e8; border-radius: 50%; animation: r .8s linear infinite; }
     @keyframes r { to { transform: rotate(360deg); } }`,
  );
  h.id = PEEK_CARD_ID;
  const close = () => {
    h.remove();
    doc.removeEventListener('keydown', onKey, true);
  };
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'Escape') close();
  };
  const x = el(doc, 'button', { className: 'x', text: '×', title: 'Close' });
  x.addEventListener('click', close);
  const title =
    data.state === 'loading'
      ? el(doc, 'div', { className: 't' }, el(doc, 'span', { className: 'spin' }), el(doc, 'span', { text: 'Unmask is checking this email…' }), el(doc, 'span', { className: 's' }), x)
      : data.state === 'error'
        ? el(doc, 'div', { className: 't' }, el(doc, 'span', { text: 'Unmask could not check this email' }), el(doc, 'span', { className: 's' }), x)
        : el(doc, 'div', { className: 't' }, el(doc, 'span', { text: `${data.verdict === 'clear' ? '✓' : '⚠'} ${p.label}` }), el(doc, 'span', { className: 's', text: `risk ${data.score}/100` }), x);
  const body: Node[] = [title];
  if (data.from || data.subject) {
    body.push(el(doc, 'div', { className: 'm' }, el(doc, 'b', { text: data.subject || '(no subject)' }), doc.createElement('br'), doc.createTextNode(data.from ?? '')));
  }
  if (data.state === 'error') body.push(el(doc, 'div', { className: 'm', text: data.error ?? '' }));
  if (data.state === 'done') {
    if (data.headline) body.push(el(doc, 'div', { className: 'h', text: data.headline }));
    if (data.reasons?.length) body.push(el(doc, 'ul', {}, ...data.reasons.map((r) => el(doc, 'li', { text: r }))));
    body.push(el(doc, 'div', { className: 'pl', text: 'Text preview (no images, no trackers)' }), el(doc, 'div', { className: 'pv', text: data.preview || '(no text)' }));
    const actions = el(doc, 'div', { className: 'a' });
    if (data.onReadSafely) {
      const go = el(doc, 'button', { className: 'go', text: 'Read it safely in Unmask' });
      go.addEventListener('click', () => {
        data.onReadSafely?.();
        close();
      });
      actions.append(go);
    }
    const done = el(doc, 'button', { text: 'Close' });
    done.addEventListener('click', close);
    actions.append(done);
    body.push(actions, el(doc, 'div', { className: 'f', text: '✓ Not opened in Gmail. Nothing in this email was loaded, so the sender can’t tell you looked.' }));
  }
  const card = el(doc, 'div', { className: 'c' }, ...body);
  card.setAttribute('role', 'dialog');
  card.setAttribute('aria-label', 'Unmask peek');
  root.append(card);
  doc.addEventListener('keydown', onKey, true);
  (doc.body ?? doc.documentElement).append(h);
  return close;
}
