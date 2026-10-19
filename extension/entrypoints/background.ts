import { defineBackground } from 'wxt/utils/define-background';
import { browser } from 'wxt/browser';
import type { AnalyzeRequest, AnalyzeResponse, BackgroundFetchRequest, BackgroundFetchResponse, OpenPanelRequest, TraceRequest, TraceResponse } from '../src/lib/messages';
import { isOutlookUrl } from '../src/lib/outlookDom';
import { traceQueued, webRequestHub } from '../src/lib/builtinTrace';

/** Only Gmail and Google's own content hosts may be fetched on the content script's behalf. */
function isAllowedGmailUrl(url: string): boolean {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' && (u.hostname === 'mail.google.com' || u.hostname.endsWith('.googleusercontent.com'));
  } catch {
    return false;
  }
}

type OffscreenApi = {
  createDocument(o: { url: string; reasons: string[]; justification: string }): Promise<void>;
};
type ContextsApi = { getContexts?(f: { contextTypes: string[] }): Promise<unknown[]> };

let creating: Promise<void> | null = null;
/** Chrome's service worker has no DOMParser; an offscreen document does. */
async function ensureOffscreen(): Promise<void> {
  const offscreen = (browser as unknown as { offscreen?: OffscreenApi }).offscreen;
  if (!offscreen) throw new Error('This browser cannot analyze emails in the background.');
  const existing = await (browser.runtime as unknown as ContextsApi).getContexts?.({ contextTypes: ['OFFSCREEN_DOCUMENT'] });
  if (existing?.length) return;
  creating ??= offscreen
    .createDocument({ url: 'offscreen.html', reasons: ['DOM_PARSER'], justification: 'Parse the HTML of the email the user opened, when the mail page blocks parsing in the content script.' })
    .finally(() => (creating = null));
  await creating;
}

async function analyzeElsewhere(req: AnalyzeRequest): Promise<AnalyzeResponse> {
  // Firefox's background is a page with a DOM; Chrome's is a worker without one.
  if (import.meta.env.FIREFOX && typeof DOMParser !== 'undefined') {
    const [{ analyzeRawEmail }, { slimReport }] = await Promise.all([import('../src/core/analyze'), import('../src/lib/slimReport')]);
    return { ok: true, report: slimReport(await analyzeRawEmail(req.raw, { history: req.history, protection: req.protection })) };
  }
  await ensureOffscreen();
  return ((await browser.runtime.sendMessage({ ...req, target: 'offscreen' })) as AnalyzeResponse | undefined) ?? { ok: false, error: 'The analysis page did not answer.' };
}

export default defineBackground(() => {
  // Registered at startup so no trace starts before its listeners are live.
  const wrApi = (browser as unknown as { webRequest?: { onBeforeRequest: never; onBeforeRedirect: never } }).webRequest;
  const hub = wrApi ? webRequestHub(wrApi.onBeforeRequest, wrApi.onBeforeRedirect) : null;

  // Clicking the toolbar icon opens the side panel instead of a popup.
  browser.sidePanel
    ?.setPanelBehavior({ openPanelOnActionClick: true })
    .catch((err: unknown) => console.error('[unmask] sidePanel behavior', err));
  // Firefox has a sidebar instead of a side panel; the toolbar icon toggles it.
  const sidebar = (browser as unknown as { sidebarAction?: { toggle(): Promise<void> } }).sidebarAction;
  if (!browser.sidePanel && sidebar) browser.action.onClicked.addListener(() => void sidebar.toggle());

  // A mail page blocked HTML parsing in the content script: analyze the email here instead.
  browser.runtime.onMessage.addListener((req: AnalyzeRequest & { target?: string }, sender, sendResponse) => {
    if (req?.type !== 'unmask:analyze' || req.target) return;
    const url = sender.tab?.url ?? '';
    if (sender.id !== browser.runtime.id || !(url.startsWith('https://mail.google.com/') || isOutlookUrl(url))) {
      sendResponse({ ok: false, error: 'request not allowed' } satisfies AnalyzeResponse);
      return;
    }
    analyzeElsewhere(req).then(sendResponse, (err: unknown) => sendResponse({ ok: false, error: err instanceof Error ? err.message : String(err) } satisfies AnalyzeResponse));
    return true;
  });

  // "See why" on a Gmail banner. Allowed because it comes from a user click in the page.
  browser.runtime.onMessage.addListener((req: OpenPanelRequest, sender) => {
    if (req?.type !== 'unmask:open-panel' || sender.id !== browser.runtime.id || !sender.tab?.id) return;
    const b = browser as unknown as { sidePanel?: { open(o: { tabId: number }): Promise<void> }; sidebarAction?: { open(): Promise<void> } };
    const opening = b.sidePanel ? b.sidePanel.open({ tabId: sender.tab.id }) : b.sidebarAction?.open();
    opening?.catch((err: unknown) => console.warn('[unmask] could not open the panel', err));
  });

  // Built-in redirect tracing, requested by the side panel.
  browser.runtime.onMessage.addListener((req: TraceRequest, sender, sendResponse) => {
    if (req?.type !== 'unmask:trace') return;
    const panelOrigin = new URL(browser.runtime.getURL('/')).origin;
    if (sender.id !== browser.runtime.id || !sender.url?.startsWith(panelOrigin)) {
      sendResponse({ ok: false, error: 'request not allowed' } satisfies TraceResponse);
      return;
    }
    if (!hub) {
      sendResponse({ ok: false, error: 'Chrome did not give Unmask permission to trace links.' } satisfies TraceResponse);
      return;
    }
    traceQueued({ fetch: (...a) => fetch(...a), ...hub, origin: panelOrigin }, req.url).then(
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
