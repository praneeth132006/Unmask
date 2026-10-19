/**
 * The Gmail side of the panel ↔ Gmail bridge: notices open messages, answers
 * the panel's requests, and shuts itself down cleanly when the extension is
 * reloaded or updated.
 *
 * Why the care: after the extension reloads, Chrome leaves the old copy of this
 * script running in already-open Gmail tabs. Any extension API call from that
 * orphaned copy throws "Extension context invalidated" synchronously, which
 * shows up as an uncaught error on chrome://extensions. Every API access here
 * goes through `alive()` / `safely()`, and invalidation removes all listeners.
 */
import type { FetchRawResponse, GmailState, PanelRequest, ReportPhishingResponse, StateChanged } from './messages';
import { applyHighlight, clearHighlights } from './highlight';

/** The subset of the extension runtime the bridge uses, injectable for tests. */
export interface BridgeRuntime {
  readonly id?: string;
  sendMessage(message: unknown): Promise<unknown> | void;
  onMessage: {
    addListener(cb: (req: PanelRequest, sender: unknown, sendResponse: (r: unknown) => void) => boolean | void): void;
    removeListener(cb: (req: PanelRequest, sender: unknown, sendResponse: (r: unknown) => void) => boolean | void): void;
  };
}

export interface BridgeDeps {
  runtime: () => BridgeRuntime | undefined;
  doc: Document;
  win: Window;
  readState: () => GmailState;
  fetchRaw: (message: GmailState['messages'][number]) => Promise<FetchRawResponse>;
  /** Opens the mail app's own "report phishing" flow for a message. */
  reportPhishing?: (message: GmailState['messages'][number]) => Promise<ReportPhishingResponse>;
  /** Called by WXT when it detects invalidation; the bridge also detects it itself. */
  onInvalidated?: (cb: () => void) => void;
  debounceMs?: number;
}

/** True while the extension that injected this script is still loaded. Never throws. */
export function alive(runtime: () => BridgeRuntime | undefined): boolean {
  try {
    return Boolean(runtime()?.id);
  } catch {
    return false;
  }
}

export function startBridge(deps: BridgeDeps): { stop: () => void; notify: () => void } {
  const { doc, win, readState, fetchRaw, runtime } = deps;
  let stopped = false;
  let lastSignature = '';
  let timer: ReturnType<typeof setTimeout> | undefined;

  const stop = () => {
    if (stopped) return;
    stopped = true;
    clearTimeout(timer);
    observer.disconnect();
    win.removeEventListener('hashchange', notify);
    try {
      runtime()?.onMessage.removeListener(onMessage);
    } catch {
      // the runtime is already gone
    }
    try {
      clearHighlights(doc);
    } catch {
      // nothing to clean up
    }
  };

  /** Runs an extension API call; on any failure the context is gone, so shut down. */
  const safely = (fn: (rt: BridgeRuntime) => unknown) => {
    if (stopped) return;
    if (!alive(runtime)) return stop();
    try {
      const r = fn(runtime()!);
      if (r && typeof (r as Promise<unknown>).catch === 'function') (r as Promise<unknown>).catch(() => {});
    } catch {
      stop();
    }
  };

  function notify() {
    if (stopped) return;
    if (!alive(runtime)) return stop();
    let state: GmailState;
    try {
      state = readState();
    } catch {
      return;
    }
    const signature = JSON.stringify(state);
    if (signature === lastSignature) return;
    lastSignature = signature;
    // The side panel may not be open; a rejected promise is fine.
    safely((rt) => rt.sendMessage({ type: 'unmask:state-changed', state } satisfies StateChanged));
  }

  const respond = (sendResponse: (r: unknown) => void, value: unknown) => {
    // The panel or the extension may have gone away while we worked.
    try {
      sendResponse(value);
    } catch {
      stop();
    }
  };

  function onMessage(req: PanelRequest, _sender: unknown, sendResponse: (r: unknown) => void): boolean | void {
    if (stopped) return;
    if (req?.type === 'unmask:get-state') {
      respond(sendResponse, readState());
      return;
    }
    if (req?.type === 'unmask:highlight') {
      respond(sendResponse, { found: applyHighlight(doc, req.message, req.target) });
      return;
    }
    if (req?.type === 'unmask:report-phishing') {
      if (!deps.reportPhishing) {
        respond(sendResponse, { ok: false, error: 'Not supported here.' } satisfies ReportPhishingResponse);
        return;
      }
      deps.reportPhishing(req.message).then(
        (r) => respond(sendResponse, r),
        (err: unknown) => respond(sendResponse, { ok: false, error: err instanceof Error ? err.message : String(err) } satisfies ReportPhishingResponse),
      );
      return true; // async response
    }
    if (req?.type === 'unmask:fetch-raw') {
      fetchRaw(req.message).then(
        (r) => respond(sendResponse, r),
        (err: unknown) => respond(sendResponse, { ok: false, error: err instanceof Error ? err.message : String(err) } satisfies FetchRawResponse),
      );
      return true; // async response
    }
  }

  const observer = new (win as unknown as { MutationObserver: typeof MutationObserver }).MutationObserver(() => {
    if (stopped) return;
    clearTimeout(timer);
    timer = setTimeout(notify, deps.debounceMs ?? 400);
  });

  if (!alive(runtime)) {
    stopped = true;
    return { stop: () => {}, notify };
  }
  observer.observe(doc.body, { childList: true, subtree: true });
  win.addEventListener('hashchange', notify);
  safely((rt) => rt.onMessage.addListener(onMessage));
  deps.onInvalidated?.(stop);
  notify();

  return { stop, notify };
}
