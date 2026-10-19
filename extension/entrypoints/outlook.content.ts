import { defineContentScript } from 'wxt/utils/define-content-script';
import { browser } from 'wxt/browser';
import type { FetchRawResponse, OpenPanelRequest } from '../src/lib/messages';
import { startBridge, type BridgeRuntime } from '../src/lib/gmailBridge';
import { analyzeInPage } from '../src/lib/remoteAnalyze';
import { loadHistory, rememberSender } from '../src/lib/historyStore';
import { loadProtection } from '../src/lib/protectionStore';
import { DEFAULT_SETTINGS, loadSettings, SETTINGS_KEY, type Settings } from '../src/lib/settings';
import { startProtection } from '../src/lib/gmailProtect';
import { buildOutlookRaw, OUTLOOK_SITE, readOutlookState } from '../src/lib/outlookDom';
import type { StoredVerdict } from '../src/lib/protect';

const VERDICTS_KEY = 'unmask:verdicts';

/**
 * Runs inside Outlook on the web. Same job as the Gmail script, but Outlook
 * doesn't expose the original message source, so the email is rebuilt from
 * the page (see outlookDom.ts). Nothing leaves the browser.
 */
export default defineContentScript({
  matches: ['https://outlook.live.com/*', 'https://outlook.office.com/*', 'https://outlook.office365.com/*', 'https://outlook.cloud.microsoft/*'],
  runAt: 'document_idle',
  main(ctx) {
    const fetchRaw = async (ref: Parameters<typeof buildOutlookRaw>[1]): Promise<FetchRawResponse> => {
      const raw = buildOutlookRaw(document, ref);
      return raw
        ? { ok: true, raw, via: 'Outlook page' }
        : { ok: false, error: 'Outlook closed or changed the message. Open it again, or use … → View → View message source and paste it into Unmask.' };
    };
    const readState = () => readOutlookState(document);

    startBridge({ runtime: () => browser.runtime as unknown as BridgeRuntime, doc: document, win: window, readState, fetchRaw, onInvalidated: (cb) => ctx.onInvalidated(cb) });

    let settings: Settings = DEFAULT_SETTINGS;
    const protection = startProtection({
      site: OUTLOOK_SITE,
      doc: document,
      win: window,
      readState,
      fetchRaw,
      analyze: analyzeInPage,
      settings: () => settings,
      loadHistory,
      loadProtection,
      rememberSender,
      loadVerdicts: async () => ((await browser.storage.local.get(VERDICTS_KEY))[VERDICTS_KEY] as Record<string, StoredVerdict> | undefined) ?? {},
      saveVerdicts: (v) => browser.storage.local.set({ [VERDICTS_KEY]: v }),
      openPanel: () => void browser.runtime.sendMessage({ type: 'unmask:open-panel' } satisfies OpenPanelRequest).catch(() => {}),
    });
    const onStorage = (changes: Record<string, { newValue?: unknown }>, area: string) => {
      if (area === 'local' && changes[SETTINGS_KEY]) {
        settings = { ...DEFAULT_SETTINGS, ...(changes[SETTINGS_KEY].newValue as Partial<Settings>) };
        void protection.scan();
      }
    };
    void loadSettings().then((s) => {
      settings = s;
      void protection.scan();
    });
    browser.storage.onChanged.addListener(onStorage);
    ctx.onInvalidated(() => {
      protection.stop();
      try {
        browser.storage.onChanged.removeListener(onStorage);
      } catch {
        // the extension context is already gone
      }
    });
  },
});
