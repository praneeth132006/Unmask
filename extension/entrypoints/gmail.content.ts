import { defineContentScript } from 'wxt/utils/define-content-script';
import { browser } from 'wxt/browser';
import type { BackgroundFetchRequest, BackgroundFetchResponse, FetchRawResponse, GmailMessageRef, GmailState, OpenPanelRequest } from '../src/lib/messages';
import { analyzeInPage } from '../src/lib/remoteAnalyze';
import { loadHistory, rememberSender } from '../src/lib/historyStore';
import { loadProtection } from '../src/lib/protectionStore';
import { DEFAULT_SETTINGS, loadSettings, SETTINGS_KEY, type Settings } from '../src/lib/settings';
import { startProtection, messageKey } from '../src/lib/gmailProtect';
import type { StoredVerdict } from '../src/lib/protect';
import { alive, startBridge, type BridgeRuntime } from '../src/lib/gmailBridge';
import { reportPhishingInGmail } from '../src/lib/gmailActions';
import { candidateUrls, describeResponse, findIkInHtml, looksLikeRawEmail, parseOriginalPage, type Attempt } from '../src/lib/gmailRaw';

const VERDICTS_KEY = 'unmask:verdicts';

/**
 * Runs inside Gmail. It notices which emails are open and downloads their raw
 * source from Gmail's own "Show original" endpoints, so no OAuth or Gmail API
 * access is needed. It also runs the same local analysis as the side panel to
 * warn inside Gmail: a banner on risky emails, inbox badges, and a check
 * before risky links and replies. Nothing leaves the browser.
 */
export default defineContentScript({
  matches: ['https://mail.google.com/*'],
  runAt: 'document_idle',
  main(ctx) {
    startBridge({
      runtime: () => browser.runtime as unknown as BridgeRuntime,
      doc: document,
      win: window,
      readState,
      fetchRaw: cachedFetchRaw,
      reportPhishing: (ref) => reportPhishingInGmail(document, ref),
      inboxStatus: () => protectionRef?.inboxStatus() ?? { rows: 0, peekButtons: 0, peekEnabled: false },
      onInvalidated: (cb) => ctx.onInvalidated(cb),
    });

    let settings: Settings = DEFAULT_SETTINGS;
    let protectionRef: ReturnType<typeof startProtection> | undefined;
    const onStorage = (changes: Record<string, { newValue?: unknown }>, area: string) => {
      if (area === 'local' && changes[SETTINGS_KEY]) {
        settings = { ...DEFAULT_SETTINGS, ...(changes[SETTINGS_KEY].newValue as Partial<Settings>) };
        void protection.scan();
      }
    };
    const protection = startProtection({
      doc: document,
      win: window,
      readState,
      fetchRaw: cachedFetchRaw,
      analyze: analyzeInPage,
      settings: () => settings,
      loadHistory,
      loadProtection,
      rememberSender,
      loadVerdicts: async () => ((await browser.storage.local.get(VERDICTS_KEY))[VERDICTS_KEY] as Record<string, StoredVerdict> | undefined) ?? {},
      saveVerdicts: (v) => browser.storage.local.set({ [VERDICTS_KEY]: v }),
      openPanel: () => void browser.runtime.sendMessage({ type: 'unmask:open-panel' } satisfies OpenPanelRequest).catch(() => {}),
      openPeekInPanel: (peek) => void browser.runtime.sendMessage({ type: 'unmask:open-panel', peek } satisfies OpenPanelRequest).catch(() => {}),
    });
    protectionRef = protection;
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

/** Raw sources already downloaded, so the in-Gmail check and the side panel share one fetch. */
const rawCache = new Map<string, Promise<FetchRawResponse>>();
function cachedFetchRaw(message: GmailMessageRef): Promise<FetchRawResponse> {
  const key = messageKey(message);
  const hit = key ? rawCache.get(key) : undefined;
  if (hit) return hit;
  const p = fetchRaw(message).then((r) => {
    if (!r.ok) rawCache.delete(key); // let the panel's "Try again" really retry
    return r;
  });
  if (key) {
    rawCache.set(key, p);
    if (rawCache.size > 40) rawCache.delete(rawCache.keys().next().value!);
  }
  return p;
}

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
    if (!alive(() => browser.runtime as unknown as BridgeRuntime)) throw new Error('Unmask was reloaded. Reload this Gmail tab.');
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
