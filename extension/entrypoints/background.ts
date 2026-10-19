import { defineBackground } from 'wxt/utils/define-background';
import { browser } from 'wxt/browser';
import type { BackgroundFetchRequest, BackgroundFetchResponse, TraceRequest, TraceResponse } from '../src/lib/messages';
import { traceQueued } from '../src/lib/builtinTrace';

/** Only Gmail and Google's own content hosts may be fetched on the content script's behalf. */
function isAllowedGmailUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && (u.hostname === 'mail.google.com' || u.hostname.endsWith('.googleusercontent.com'));
  } catch {
    return false;
  }
}

export default defineBackground(() => {
  // Clicking the toolbar icon opens the side panel instead of a popup.
  browser.sidePanel
    ?.setPanelBehavior({ openPanelOnActionClick: true })
    .catch((err: unknown) => console.error('[unmask] sidePanel behavior', err));

  // Built-in redirect tracing, requested by the side panel.
  browser.runtime.onMessage.addListener((req: TraceRequest, sender, sendResponse) => {
    if (req?.type !== 'unmask:trace') return;
    const panelOrigin = new URL(browser.runtime.getURL('/')).origin;
    if (sender.id !== browser.runtime.id || !sender.url?.startsWith(panelOrigin)) {
      sendResponse({ ok: false, error: 'request not allowed' } satisfies TraceResponse);
      return;
    }
    const wr = (browser as unknown as { webRequest?: { onBeforeRequest: never; onBeforeRedirect: never } }).webRequest;
    if (!wr) {
      sendResponse({ ok: false, error: 'Chrome did not give Unmask permission to trace links.' } satisfies TraceResponse);
      return;
    }
    traceQueued({ fetch: (...a) => fetch(...a), onBeforeRequest: wr.onBeforeRequest, onBeforeRedirect: wr.onBeforeRedirect, origin: panelOrigin }, req.url).then(
      (result) => sendResponse({ ok: true, result } satisfies TraceResponse),
      (err: unknown) => sendResponse({ ok: false, error: err instanceof Error ? err.message : String(err) } satisfies TraceResponse),
    );
    return true; // async response
  });

  browser.runtime.onMessage.addListener((req: BackgroundFetchRequest, sender, sendResponse) => {
    if (req?.type !== 'unmask:bg-fetch') return;
    // Only our own Gmail content script may ask, and only for Gmail URLs.
    if (sender.id !== browser.runtime.id || !sender.tab?.url?.startsWith('https://mail.google.com/') || !isAllowedGmailUrl(req.url)) {
      sendResponse({ ok: false, error: 'request not allowed' } satisfies BackgroundFetchResponse);
      return;
    }
    fetch(req.url, { credentials: 'include', redirect: 'follow' })
      .then(async (res) => {
        const body = await res.text();
        sendResponse({ ok: true, status: res.status, finalUrl: res.url || req.url, contentType: res.headers.get('content-type') ?? '', body } satisfies BackgroundFetchResponse);
      })
      .catch((err: unknown) => sendResponse({ ok: false, error: err instanceof Error ? err.message : String(err) } satisfies BackgroundFetchResponse));
    return true; // async response
  });
});
