import type { ParsedAttachment } from '../core/types';

export interface SafeHtmlOptions {
  /** Show elements the analyzer marked as hidden, outlined in red. */
  reveal: boolean;
  /** Allow remote images (tells the sender you opened the email). */
  remoteImages: boolean;
  attachments: ParsedAttachment[];
  /** Put a visible tag where each tracking pixel (data-unmask-pixel) sits; labels by pixel number. */
  pixelLabels?: Record<number, string>;
  /** The pixel to emphasise. */
  focusPixel?: number;
}

function toDataUrl(att: ParsedAttachment): string {
  let bin = '';
  for (let i = 0; i < att.content.length; i += 8192) bin += String.fromCharCode(...att.content.subarray(i, i + 8192));
  return `data:${att.mimeType};base64,${btoa(bin)}`;
}

/**
 * Produces a srcdoc for a sandboxed iframe (no scripts, no same-origin):
 * - a CSP that blocks every network request unless remote images are allowed
 * - links are disarmed (href removed, real destination shown on hover) so a
 *   click can't navigate the frame to a phishing page
 * - inline cid: images are swapped for data: URLs from the attachments
 */
export function buildSafeSrcDoc(html: string, opts: SafeHtmlOptions): string {
  const doc = new DOMParser().parseFromString(html, 'text/html');

  // <link> covers dns-prefetch/preconnect/prefetch, which CSP doesn't fully stop and which would tell
  // the sender's servers you opened the email. <meta> covers refresh and any CSP the email brings.
  doc.querySelectorAll('script, noscript, iframe, frame, frameset, object, embed, applet, base, link, meta, portal').forEach((n) => n.remove());

  doc.querySelectorAll('*').forEach((el) => {
    for (const attr of Array.from(el.attributes)) {
      if (attr.name.startsWith('on') || attr.name === 'ping' || /^\s*(javascript|vbscript):/i.test(attr.value)) el.removeAttribute(attr.name);
    }
  });

  doc.querySelectorAll('a[href], area[href]').forEach((a) => {
    const href = a.getAttribute('href')!;
    a.removeAttribute('href');
    a.setAttribute('title', `Real destination: ${href}`);
    a.setAttribute('data-unmask-link', '');
  });
  doc.querySelectorAll('form').forEach((form) => {
    form.removeAttribute('action');
    form.setAttribute('data-unmask-form', '');
  });

  // Tracking pixels never load, even when remote images are allowed: loading one tells the sender you opened it.
  doc.querySelectorAll('[data-unmask-pixel]').forEach((el) => {
    const n = Number(el.getAttribute('data-unmask-pixel'));
    if (el.tagName === 'IMG') el.removeAttribute('src');
    el.removeAttribute('srcset');
    const style = el.getAttribute('style');
    if (style) el.setAttribute('style', style.replace(/url\([^)]*\)/gi, 'none'));
    if (opts.pixelLabels) {
      const tag = doc.createElement('span');
      tag.setAttribute('data-unmask-pixel-tag', String(n));
      if (n === opts.focusPixel) tag.setAttribute('data-unmask-focus', '');
      tag.textContent = `● Tracking pixel ${n}${opts.pixelLabels[n] ? ` (${opts.pixelLabels[n]})` : ''}: blocked`;
      if (el.tagName === 'IMG') el.parentNode?.insertBefore(tag, el);
      else el.prepend(tag);
    }
  });

  const byCid = new Map(opts.attachments.filter((a) => a.contentId).map((a) => [a.contentId!.replace(/^<|>$/g, ''), a]));
  doc.querySelectorAll('img[src^="cid:" i]').forEach((img) => {
    const att = byCid.get(img.getAttribute('src')!.slice(4));
    // Only real images: a cid: part claiming text/html must not become a data: document.
    if (att && att.size < 5_000_000 && /^image\/(png|jpe?g|gif|webp|bmp|x-icon|vnd\.microsoft\.icon)$/i.test(att.mimeType)) img.setAttribute('src', toDataUrl(att));
  });

  const imgSrc = opts.remoteImages ? 'data: https: http:' : 'data:';
  const csp = `default-src 'none'; img-src ${imgSrc}; style-src 'unsafe-inline'; font-src data:; form-action 'none'; base-uri 'none'`;

  const style = `
    html { color-scheme: light; }
    body { margin: 12px; font-family: system-ui, sans-serif; font-size: 14px; line-height: 1.45; word-wrap: break-word; background: #fff; color: #111; }
    img { max-width: 100%; height: auto; }
    [data-unmask-link] { color: #1d4ed8; text-decoration: underline; cursor: help; }
    [data-unmask-form] { outline: 3px solid #dc2626; outline-offset: 2px; }
    [data-unmask-pixel-tag] { display: inline-block !important; margin: 2px 4px !important; padding: 1px 7px !important; border-radius: 9px !important;
      font: 600 11px/1.6 system-ui, sans-serif !important; color: #fff !important; background: #d93025 !important; white-space: nowrap !important;
      visibility: visible !important; opacity: 1 !important; position: static !important; }
    [data-unmask-pixel-tag][data-unmask-focus] { outline: 3px solid #fbbc04 !important; outline-offset: 2px !important; font-size: 13px !important; }
    ${
      opts.reveal
        ? `[data-unmask-hidden] { display: block !important; visibility: visible !important; opacity: 1 !important;
             font-size: 13px !important; max-height: none !important; height: auto !important; overflow: visible !important;
             color: #b91c1c !important; background: #fef2f2 !important; outline: 2px dashed #dc2626 !important; padding: 4px !important; margin: 4px 0 !important; }
           [data-unmask-hidden]::before { content: "HIDDEN (" attr(data-unmask-hidden) "): "; font-weight: 700; }`
        : ''
    }`;

  const head = doc.head ?? doc.documentElement.insertBefore(doc.createElement('head'), doc.body);
  const meta = doc.createElement('meta');
  meta.setAttribute('http-equiv', 'Content-Security-Policy');
  meta.setAttribute('content', csp);
  const noPrefetch = doc.createElement('meta');
  noPrefetch.setAttribute('http-equiv', 'x-dns-prefetch-control');
  noPrefetch.setAttribute('content', 'off');
  head.prepend(meta, noPrefetch);
  const styleEl = doc.createElement('style');
  styleEl.textContent = style;
  head.append(styleEl);

  return `<!doctype html>${doc.documentElement.outerHTML}`;
}

/**
 * Count of remote images, so the UI can say what "load images" would fetch.
 * Uses the DOM: a regex like /<img[^>]+src/ takes quadratic time on crafted HTML (ReDoS).
 */
export function countRemoteImages(html: string): number {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  return Array.from(doc.querySelectorAll('img[src]')).filter((img) => /^\s*https?:/i.test(img.getAttribute('src') ?? '')).length;
}
