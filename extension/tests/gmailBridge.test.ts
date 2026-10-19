import { startBridge, alive, type BridgeRuntime } from '../src/lib/gmailBridge';

/** A runtime that behaves like Chrome's: once invalidated, id is gone and every call throws synchronously. */
function fakeRuntime() {
  const listeners: Function[] = [];
  let valid = true;
  const sent: unknown[] = [];
  const rt: BridgeRuntime = {
    get id() {
      return valid ? 'ext-id' : undefined;
    },
    sendMessage(m) {
      if (!valid) throw new Error('Extension context invalidated.');
      sent.push(m);
      return Promise.resolve();
    },
    onMessage: {
      addListener: (cb) => {
        if (!valid) throw new Error('Extension context invalidated.');
        listeners.push(cb);
      },
      removeListener: (cb) => {
        if (!valid) throw new Error('Extension context invalidated.');
        listeners.splice(listeners.indexOf(cb), 1);
      },
    },
  };
  return { rt, sent, listeners, invalidate: () => (valid = false) };
}

const state = (n: number) => ({ accountIndex: '0', messages: Array.from({ length: n }, (_, i) => ({ permId: `msg-f:${i}`, legacyId: null, fromName: '', fromEmail: '', subject: '' })) });

describe('gmail bridge', () => {
  it('reports state changes and answers the panel', async () => {
    const f = fakeRuntime();
    let n = 1;
    startBridge({ runtime: () => f.rt, doc: document, win: window, readState: () => state(n), fetchRaw: async () => ({ ok: true, raw: 'x', via: 't' }), debounceMs: 0 });
    expect(f.sent).toHaveLength(1);
    n = 2;
    window.dispatchEvent(new HashChangeEvent('hashchange'));
    expect(f.sent).toHaveLength(2);
    const reply = await new Promise((resolve) => f.listeners[0]!({ type: 'unmask:get-state' }, {}, resolve));
    expect(reply).toEqual(state(2));
  });

  it('never throws after the extension is reloaded, and stops listening', async () => {
    const f = fakeRuntime();
    let n = 1;
    const errors: unknown[] = [];
    const onError = (e: ErrorEvent) => errors.push(e.error);
    window.addEventListener('error', onError);
    startBridge({ runtime: () => f.rt, doc: document, win: window, readState: () => state(n), fetchRaw: async () => ({ ok: true, raw: 'x', via: 't' }), debounceMs: 0 });
    f.invalidate();
    n = 3;
    expect(() => window.dispatchEvent(new HashChangeEvent('hashchange'))).not.toThrow();
    document.body.append(document.createElement('div'));
    await new Promise((r) => setTimeout(r, 20));
    window.removeEventListener('error', onError);
    expect(errors).toEqual([]);
    expect(f.sent).toHaveLength(1); // nothing sent after invalidation
  });

  it('treats a runtime whose getter throws as dead', () => {
    expect(alive(() => { throw new Error('Extension context invalidated.'); })).toBe(false);
    expect(alive(() => undefined)).toBe(false);
  });

  it('stops when WXT reports invalidation', () => {
    const f = fakeRuntime();
    let invalidate: () => void = () => {};
    startBridge({ runtime: () => f.rt, doc: document, win: window, readState: () => state(1), fetchRaw: async () => ({ ok: true, raw: 'x', via: 't' }), onInvalidated: (cb) => (invalidate = cb) });
    expect(f.listeners).toHaveLength(1);
    invalidate();
    expect(f.listeners).toHaveLength(0);
  });
});
