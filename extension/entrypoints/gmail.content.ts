import { defineContentScript } from 'wxt/utils/define-content-script';
import { browser } from 'wxt/browser';
import type { FetchRawResponse, GmailMessageRef, GmailState, PanelRequest, StateChanged } from '../src/lib/messages';

/**
 * Runs inside Gmail. Its only jobs are to notice which emails are open and to
 * download their raw source from Gmail's own "Show original" view, so no
 * OAuth or Gmail API access is needed. All analysis happens in the side panel.
 */
export default defineContentScript({
  matches: ['https://mail.google.com/*'],
  runAt: 'document_idle',
  main() {
    let lastSignature = '';

    const notify = () => {
      const state = readState();
      const signature = JSON.stringify(state);
      if (signature === lastSignature) return;
      lastSignature = signature;
      const msg: StateChanged = { type: 'unmask:state-changed', state };
      // The side panel may not be open; that's fine.
      browser.runtime.sendMessage(msg).catch(() => {});
    };

    let timer: ReturnType<typeof setTimeout> | undefined;
    new MutationObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(notify, 400);
    }).observe(document.body, { childList: true, subtree: true });
    window.addEventListener('hashchange', notify);
    notify();

    browser.runtime.onMessage.addListener((req: PanelRequest, _sender, sendResponse) => {
      if (req?.type === 'unmask:get-state') {
        sendResponse(readState());
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
      legacyId,
      fromName: sender?.getAttribute('name') ?? sender?.textContent?.trim() ?? '',
      fromEmail: sender?.getAttribute('email') ?? '',
      subject,
    });
  });

  return { accountIndex: accountIndex(), messages };
}

function looksLikeRawEmail(text: string): boolean {
  const head = text.slice(0, 4000);
  return /^[\w-]+:\s/m.test(head) && /^(received|from|message-id|date|delivered-to|mime-version):/im.test(head);
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { credentials: 'include' });
  if (!res.ok) throw new Error(`Gmail returned HTTP ${res.status}`);
  return res.text();
}

async function fromOriginalPage(url: string): Promise<string | null> {
  const html = await fetchText(url);
  const doc = new DOMParser().parseFromString(html, 'text/html');

  // Prefer the "Download original" link: it is never truncated for large emails.
  const download = Array.from(doc.querySelectorAll<HTMLAnchorElement>('a[href]')).find((a) =>
    /disp=comp|view=att/.test(a.getAttribute('href') ?? ''),
  );
  if (download) {
    try {
      const raw = await fetchText(new URL(download.getAttribute('href')!, url).href);
      if (looksLikeRawEmail(raw)) return raw;
    } catch {
      // fall back to the <pre> below
    }
  }

  const pre = doc.getElementById('raw_message_text');
  const text = pre?.textContent ?? null;
  return text && looksLikeRawEmail(text) ? text : null;
}

async function fetchRaw(message: GmailMessageRef): Promise<FetchRawResponse> {
  const base = `${location.origin}/mail/u/${accountIndex()}/`;
  const candidates: string[] = [];
  if (message.permId) candidates.push(`${base}?view=om&permmsgid=${encodeURIComponent(message.permId)}`);
  if (message.legacyId) candidates.push(`${base}?ui=2&view=om&th=${encodeURIComponent(message.legacyId)}`);

  for (const url of candidates) {
    try {
      const raw = await fromOriginalPage(url);
      if (raw) return { ok: true, raw };
    } catch {
      // try the next URL shape
    }
  }
  return {
    ok: false,
    error: 'Could not read the original message from Gmail. Open the email, then use ⋮ → "Show original" → "Download original" and drop the .eml file into Unmask.',
  };
}
