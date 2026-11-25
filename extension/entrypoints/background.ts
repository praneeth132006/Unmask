import { defineBackground } from 'wxt/utils/define-background';
import { browser } from 'wxt/browser';
import { PEEK_KEY, type PendingPeek } from '../src/lib/messages';
import type { AnalyzeRequest, AnalyzeResponse, BackgroundFetchRequest, BackgroundFetchResponse, OpenPanelRequest, PreviewLinkRequest, PreviewLinkResponse, TraceRequest, TraceResponse } from '../src/lib/messages';
import { loadSettings, SETTINGS_KEY } from '../src/lib/settings';
import { syncLoginGuard } from '../src/lib/loginGuardSetup';
import { fetchScreenshot, scanUrl, UrlscanPending } from '../src/integrations/urlscan';
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
  if ((import.meta.env.FIREFOX || import.meta.env.SAFARI) && typeof DOMParser !== 'undefined') {
    const [{ analyzeRawEmail }, { slimReport }] = await Promise.all([import('../src/core/analyze'), import('../src/lib/slimReport')]);
    return { ok: true, report: slimReport(await analyzeRawEmail(req.raw, { history: req.history, protection: req.protection })) };
  }
  await ensureOffscreen();
  return ((await browser.runtime.sendMessage({ ...req, target: 'offscreen' })) as AnalyzeResponse | undefined) ?? { ok: false, error: 'The analysis page did not answer.' };
}

export default defineBackground(() => {
  // Once, on a fresh install: a welcome tab showing a real warning on a made-up phishing email.
  browser.runtime.onInstalled.addListener((details) => {
    if (details.reason !== 'install') return;
    void (async () => {
      const managed = await browser.storage.managed?.get('skipWelcome').catch(() => ({} as Record<string, unknown>));
      if (managed?.skipWelcome === true) return;
      await browser.tabs.create({ url: browser.runtime.getURL('/welcome.html') });
    })();
  });

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
    if (req.peek) {
      const session = (browser.storage as unknown as { session?: { set(v: Record<string, unknown>): Promise<void> } }).session;
      void session?.set({ [PEEK_KEY]: { tabId: sender.tab.id, ref: req.peek, at: Date.now() } satisfies PendingPeek });
    }
    const b = browser as unknown as { sidePanel?: { open(o: { tabId: number }): Promise<void> }; sidebarAction?: { open(): Promise<void> } };
    const opening = b.sidePanel ? b.sidePanel.open({ tabId: sender.tab.id }) : b.sidebarAction?.open();
    opening?.catch((err: unknown) => console.warn('[unmask] could not open the panel', err));
  });

  // "Warn on fake sign-in pages anywhere": the content script is registered only while it's on.
  const syncGuard = () => void loadSettings().then((st) => syncLoginGuard(st.loginGuard));
  syncGuard();
  browser.storage.onChanged.addListener((changes, area) => { if (area === 'local' && changes[SETTINGS_KEY]) syncGuard(); });
  browser.permissions.onRemoved?.addListener(syncGuard);

  // "Preview safely" in the click warning: a private urlscan.io scan, run here so the key never reaches the mail page.
  browser.runtime.onMessage.addListener((req: PreviewLinkRequest, sender, sendResponse) => {
    if (req?.type !== 'unmask:preview-link') return;
    if (sender.id !== browser.runtime.id || !sender.tab || !/^https?:/.test(req.url)) {
      sendResponse({ ok: false, error: 'request not allowed' } satisfies PreviewLinkResponse);
      return;
    }
    void (async (): Promise<PreviewLinkResponse> => {
      const { urlscanApiKey } = await loadSettings();
      if (!urlscanApiKey) return { ok: false, error: 'Add a free urlscan.io key in Unmask Settings to preview links.' };
      try {
        const r = await scanUrl(urlscanApiKey, req.url);
        const blob = await fetchScreenshot(urlscanApiKey, r.uuid);
        const bytes = new Uint8Array(await blob.arrayBuffer());
        let bin = '';
        for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
        return { ok: true, image: `data:image/png;base64,${btoa(bin)}`, finalUrl: r.finalUrl, malicious: r.malicious, reportUrl: r.reportUrl };
      } catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e), reportUrl: e instanceof UrlscanPending ? e.reportUrl : undefined };
      }
    })().then(sendResponse);
    return true;
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
