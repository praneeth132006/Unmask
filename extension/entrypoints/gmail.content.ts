import { defineContentScript } from 'wxt/utils/define-content-script';
import { browser } from 'wxt/browser';
import type {
  BackgroundFetchRequest,
  BackgroundFetchResponse,
  FetchRawResponse,
  GmailMessageRef,
  GmailState,
  PanelRequest,
  StateChanged,
} from '../src/lib/messages';
import { applyHighlight } from '../src/lib/highlight';
import { candidateUrls, describeResponse, findIkInHtml, looksLikeRawEmail, parseOriginalPage, type Attempt } from '../src/lib/gmailRaw';

/**
 * Runs inside Gmail. Its only jobs are to notice which emails are open and to
 * download their raw source from Gmail's own "Show original" endpoints, so no
 * OAuth or Gmail API access is needed. All analysis happens in the side panel.
 */
export default defineContentScript({
  matches: ['https://mail.google.com/*'],
  runAt: 'document_idle',
  main() {
    let lastSignature = '';

    let observer: MutationObserver | undefined;
    const notify = () => {
      // After the extension is reloaded or updated, this old copy of the script is orphaned: stop quietly.
      if (!browser.runtime?.id) {
        observer?.disconnect();
        window.removeEventListener('hashchange', notify);
        return;
      }
      const state = readState();
      const signature = JSON.stringify(state);
      if (signature === lastSignature) return;
      lastSignature = signature;
      const msg: StateChanged = { type: 'unmask:state-changed', state };
      // The side panel may not be open; that's fine.
      try {
        browser.runtime.sendMessage(msg).catch(() => {});
      } catch {
        observer?.disconnect();
      }
    };

    let timer: ReturnType<typeof setTimeout> | undefined;
    observer = new MutationObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(notify, 400);
    });
    observer.observe(document.body, { childList: true, subtree: true });
    window.addEventListener('hashchange', notify);
    notify();

    browser.runtime.onMessage.addListener((req: PanelRequest, _sender, sendResponse) => {
      if (req?.type === 'unmask:get-state') {
        sendResponse(readState());
        return;
      }
      if (req?.type === 'unmask:highlight') {
        sendResponse({ found: applyHighlight(document, req.message, req.target) });
        return;
      }
      if (req?.type === 'unmask:fetch-raw') {
        fetchRaw(req.message).then(sendResponse, (err: unknown) =>
          sendResponse({ ok: false, error: err instanceof Error ? err.message : String(err) } satisfies FetchRawResponse),
        );
        return true; // async response
      }
    });
  },
});

function accountIndex(): string {
  return location.pathname.match(/\/mail\/u\/(\d+)/)?.[1] ?? '0';
}

/** Expanded messages in the open thread. Gmail's class names change, so lean on data attributes. */
function readState(): GmailState {
  const subject = document.querySelector('h2[data-thread-perm-id], h2.hP')?.textContent?.trim() ?? '';
  const nodes = document.querySelectorAll<HTMLElement>('[data-message-id], [data-legacy-message-id]');
  const seen = new Set<string>();
  const messages: GmailMessageRef[] = [];

  nodes.forEach((node) => {
    const permRaw = node.getAttribute('data-message-id');
    const permId = permRaw ? permRaw.replace(/^#/, '') : null;
    const legacyId = node.getAttribute('data-legacy-message-id');
    const key = permId ?? legacyId;
    if (!key || seen.has(key)) return;
    // Only messages whose body is rendered (expanded), not collapsed thread rows.
    if (!node.querySelector('.a3s, [data-message-body], .ii')) return;
    seen.add(key);
    const sender = node.querySelector<HTMLElement>('[email]');
    messages.push({
      permId: permId && permId.startsWith('msg-') ? permId : null,
      legacyId: legacyId && /^[0-9a-f]+$/i.test(legacyId) ? legacyId : null,
      fromName: sender?.getAttribute('name') ?? sender?.textContent?.trim() ?? '',
      fromEmail: sender?.getAttribute('email') ?? '',
      subject,
    });
  });

  return { accountIndex: accountIndex(), messages };
}

/** Gmail's per-session token, published by the MAIN-world script, with an HTML scan as fallback. */
let cachedIk: string | null = null;
function getIk(): string | null {
  const fromAttr = document.documentElement.getAttribute('data-unmask-ik');
  if (fromAttr) return (cachedIk = fromAttr);
  if (cachedIk) return cachedIk;
  for (const s of Array.from(document.scripts)) {
    const ik = findIkInHtml(s.textContent ?? '');
    if (ik) return (cachedIk = ik);
  }
  return (cachedIk = findIkInHtml(document.documentElement.innerHTML.slice(0, 3_000_000)));
}

interface Fetched {
  status: number;
  finalUrl: string;
  contentType: string;
  body: string;
  via: 'page' | 'background';
}

/**
 * Fetch from the page first (same origin, Gmail cookies). If that throws —
 * usually a redirect to another Google domain that CORS blocks — retry from
 * the extension's background worker, which has host permissions.
 */
async function fetchText(url: string): Promise<Fetched> {
  try {
    const res = await fetch(url, { credentials: 'include', redirect: 'follow' });
    return { status: res.status, finalUrl: res.url || url, contentType: res.headers.get('content-type') ?? '', body: await res.text(), via: 'page' };
  } catch (pageErr) {
    const res = (await browser.runtime.sendMessage({ type: 'unmask:bg-fetch', url } satisfies BackgroundFetchRequest)) as BackgroundFetchResponse | undefined;
    if (!res) throw new Error(`page fetch failed (${(pageErr as Error).message}) and the background worker did not answer`);
    if (!res.ok) throw new Error(`page fetch failed (${(pageErr as Error).message}); background fetch failed (${res.error})`);
    return { ...res, via: 'background' };
  }
}

async function fetchRaw(message: GmailMessageRef): Promise<FetchRawResponse> {
  const ik = getIk();
  const attempts: Attempt[] = [{ label: 'session token', outcome: ik ? 'found' : 'not found (trying without it)' }];
  const tried = new Set<string>();

  const tryUrl = async (label: string, url: string): Promise<string | null> => {
    if (tried.has(url)) return null;
    tried.add(url);
    try {
      const r = await fetchText(url);
      if (r.status === 200 && looksLikeRawEmail(r.body)) {
        attempts.push({ label, outcome: `OK via ${r.via} fetch` });
        return r.body;
      }
      if (r.status === 200 && /html/i.test(r.contentType)) {
        const page = parseOriginalPage(r.body, r.finalUrl);
        // Prefer the download link (never truncated) over the on-page <pre>.
        if (page.downloadUrl && !tried.has(page.downloadUrl)) {
          const fromLink = await tryUrl(`${label} → download link`, page.downloadUrl);
          if (fromLink) return fromLink;
        }
        if (page.raw) {
          attempts.push({ label, outcome: `OK from page text via ${r.via} fetch` });
          return page.raw;
        }
      }
      attempts.push({ label, outcome: describeResponse(r.status, r.finalUrl, r.contentType, r.body) });
    } catch (e) {
      attempts.push({ label, outcome: e instanceof Error ? e.message : String(e) });
    }
    return null;
  };

  for (const c of candidateUrls(location.origin, accountIndex(), message, ik)) {
    const raw = await tryUrl(c.label, c.url);
    if (raw) return { ok: true, raw, via: c.label };
  }

  return {
    ok: false,
    error: 'Gmail did not return the original message. You can still analyze it: in Gmail open ⋮ → "Download message", then drop the .eml file on this panel.',
    attempts,
  };
}
