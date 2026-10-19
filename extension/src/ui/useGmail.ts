import { useCallback, useEffect, useRef, useState } from 'react';
import { browser } from 'wxt/browser';
import type { HighlightTarget } from '../lib/highlight';
import { isOutlookUrl } from '../lib/outlookDom';
import type { FetchRawResponse, GmailMessageRef, GmailState, PanelRequest, ReportPhishingResponse, StateChanged } from '../lib/messages';

export type GmailStatus = 'not-gmail' | 'no-script' | 'ready';
/** Which web mail app the active tab is. */
export type MailApp = 'gmail' | 'outlook';

/** Error carrying Gmail's per-URL diagnostics so the panel can show them. */
export class GmailFetchError extends Error {
  constructor(
    message: string,
    readonly details: string[],
  ) {
    super(message);
  }
}

export function messageKey(m: GmailMessageRef): string {
  return m.permId ?? m.legacyId ?? '';
}

/** Tracks the active tab and, when it is Gmail, which emails are open. */
export function useGmail() {
  const [tabId, setTabId] = useState<number | null>(null);
  const [status, setStatus] = useState<GmailStatus>('not-gmail');
  const [state, setState] = useState<GmailState | null>(null);
  const [app, setApp] = useState<MailApp>('gmail');
  const tabIdRef = useRef<number | null>(null);
  tabIdRef.current = tabId;

  const refresh = useCallback(async () => {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    const outlook = isOutlookUrl(tab?.url);
    if (!tab?.id || (!tab.url?.startsWith('https://mail.google.com/') && !outlook)) {
      setTabId(tab?.id ?? null);
      setStatus('not-gmail');
      setState(null);
      return;
    }
    setTabId(tab.id);
    setApp(outlook ? 'outlook' : 'gmail');
    try {
      const s = (await browser.tabs.sendMessage(tab.id, { type: 'unmask:get-state' } satisfies PanelRequest)) as GmailState | undefined;
      setState(s ?? null);
      setStatus('ready');
    } catch {
      // Gmail was open before the extension was installed/updated: the content script isn't there yet.
      setState(null);
      setStatus('no-script');
    }
  }, []);

  useEffect(() => {
    void refresh();
    const onActivated = () => void refresh();
    const onUpdated = (_id: number, info: { status?: string; url?: string }) => {
      if (info.status === 'complete' || info.url) void refresh();
    };
    const onMessage = (msg: StateChanged, sender: { tab?: { id?: number } }) => {
      if (msg?.type !== 'unmask:state-changed') return;
      if (sender.tab?.id !== tabIdRef.current) return;
      setState(msg.state);
      setStatus('ready');
    };
    browser.tabs.onActivated.addListener(onActivated);
    browser.tabs.onUpdated.addListener(onUpdated);
    browser.windows.onFocusChanged.addListener(onActivated);
    browser.runtime.onMessage.addListener(onMessage);
    return () => {
      browser.tabs.onActivated.removeListener(onActivated);
      browser.tabs.onUpdated.removeListener(onUpdated);
      browser.windows.onFocusChanged.removeListener(onActivated);
      browser.runtime.onMessage.removeListener(onMessage);
    };
  }, [refresh]);

  const fetchRaw = useCallback(
    async (message: GmailMessageRef): Promise<string> => {
      if (tabId === null) throw new Error('No Gmail tab is active.');
      const res = (await browser.tabs.sendMessage(tabId, { type: 'unmask:fetch-raw', message } satisfies PanelRequest)) as FetchRawResponse | undefined;
      if (!res) throw new Error('Gmail did not answer. Reload the Gmail tab and try again.');
      if (!res.ok) throw new GmailFetchError(res.error, (res.attempts ?? []).map((a) => `${a.label}: ${a.outcome}`));
      return res.raw;
    },
    [tabId],
  );

  /** Best effort: outline something in the open Gmail message. Silently ignored if Gmail isn't there. */
  const highlight = useCallback(
    (message: GmailMessageRef, target: HighlightTarget | null) => {
      if (tabId === null) return;
      browser.tabs.sendMessage(tabId, { type: 'unmask:highlight', message, target } satisfies PanelRequest).catch(() => {});
    },
    [tabId],
  );

  const reportPhishing = useCallback(
    async (message: GmailMessageRef): Promise<ReportPhishingResponse> => {
      if (tabId === null) return { ok: false, error: 'No Gmail tab is active.' };
      try {
        await browser.tabs.update(tabId, { active: true });
        return ((await browser.tabs.sendMessage(tabId, { type: 'unmask:report-phishing', message } satisfies PanelRequest)) as ReportPhishingResponse | undefined) ?? { ok: false, error: 'Gmail did not answer.' };
      } catch (e) {
        return { ok: false, error: e instanceof Error ? e.message : String(e) };
      }
    },
    [tabId],
  );

  const reloadTab = useCallback(async () => {
    if (tabId !== null) await browser.tabs.reload(tabId);
  }, [tabId]);

  return { status, state, app, tabId, fetchRaw, refresh, reloadTab, highlight, reportPhishing };
}
