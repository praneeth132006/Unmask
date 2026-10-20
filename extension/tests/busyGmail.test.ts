import { debounceMax } from '../src/lib/schedule';
import { DEFAULT_SETTINGS, migrateSettings } from '../src/lib/settings';
import { startProtection, GMAIL_SITE } from '../src/lib/gmailProtect';
import { PEEK_ATTR } from '../src/lib/inpage';
import { analyzeRawEmail } from '../src/core/analyze';
import { EMPTY_HISTORY } from '../src/analyzers/history';
import { fixture } from './helpers';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('scheduling on a page that never stops changing', () => {
  it('still runs within the max wait', async () => {
    let runs = 0;
    const d = debounceMax(() => runs++, 100, 300);
    const t0 = Date.now();
    while (Date.now() - t0 < 700) {
      d.schedule();
      await sleep(30);
    }
    d.cancel();
    expect(runs).toBeGreaterThanOrEqual(2);
  });
});

describe('settings upgrade', () => {
  it('turns every in-Gmail protection on for settings saved by older versions', () => {
    const { settings, changed } = migrateSettings({ theme: 'dark', scanInbox: false, peekButtons: false, gmailBanner: false });
    expect(changed).toBe(true);
    expect(settings).toMatchObject({ theme: 'dark', gmailBanner: true, inboxBadges: true, clickProtection: true, peekButtons: true, scanInbox: true, settingsVersion: 2 });
  });
  it('respects choices made after the upgrade, and new installs get everything on', () => {
    expect(migrateSettings({ settingsVersion: 2, scanInbox: false }).settings.scanInbox).toBe(false);
    expect(migrateSettings(undefined)).toEqual({ settings: DEFAULT_SETTINGS, changed: false });
    expect(DEFAULT_SETTINGS).toMatchObject({ gmailBanner: true, inboxBadges: true, clickProtection: true, peekButtons: true, scanInbox: true });
  });
});

describe('Peek buttons on a busy, redrawing Gmail inbox', () => {
  let stop: (() => void) | undefined;
  afterEach(() => {
    stop?.();
    document.body.innerHTML = '';
  });

  it('adds them even while the page keeps changing, and puts back ones Gmail wiped', async () => {
    document.body.innerHTML = `<div id="clock"></div><table>
      <tr class="zA yO"><td><span email="ann@acme.com" name="Ann">Ann</span><span class="bog"><span data-thread-id="#thread-f:42" data-legacy-thread-id="2a" data-legacy-last-message-id="2f">Lunch</span></span></td></tr></table>`;
    const fetched: unknown[] = [];
    const p = startProtection({
      doc: document,
      win: window,
      readState: () => ({ accountIndex: '0', messages: [] }),
      fetchRaw: async (ref) => (fetched.push(ref), { ok: true, raw: fixture('legit-newsletter.eml'), via: 't' }),
      analyze: (raw) => analyzeRawEmail(raw),
      settings: () => ({ ...DEFAULT_SETTINGS, scanInbox: false, senderHistory: false }),
      loadHistory: async () => EMPTY_HISTORY,
      rememberSender: async () => {},
      loadVerdicts: async () => ({}),
      saveVerdicts: async () => {},
      debounceMs: 200,
    });
    stop = p.stop;
    // Gmail-like churn every 50 ms, faster than the 200 ms quiet period.
    const churn = setInterval(() => (document.getElementById('clock')!.textContent = String(Date.now())), 50);
    try {
      for (let t = 0; t < 3000 && !document.querySelector(`[${PEEK_ATTR}]`); t += 50) await sleep(50);
      expect(document.querySelector(`[${PEEK_ATTR}]`)).not.toBeNull();
      // Gmail redraws the row's contents but keeps the <tr> and our marker attribute.
      document.querySelector(`[${PEEK_ATTR}]`)!.remove();
      for (let t = 0; t < 3000 && !document.querySelector(`[${PEEK_ATTR}]`); t += 50) await sleep(50);
      expect(document.querySelector(`[${PEEK_ATTR}]`)).not.toBeNull();
      expect(p.inboxStatus()).toEqual({ rows: 1, peekButtons: 1, peekEnabled: true });
    } finally {
      clearInterval(churn);
    }
  });

  it('peeks at the latest message of a conversation when Gmail exposes it', () => {
    document.body.innerHTML = `<table><tr class="zA"><td><span email="a@b.com">A</span><span data-thread-id="#thread-f:42" data-legacy-thread-id="2a" data-legacy-last-message-id="2f">S</span></td></tr></table>`;
    const row = document.querySelector('tr')!;
    expect(GMAIL_SITE.refForRow!(row, 'thread-f:42')).toMatchObject({ permId: null, legacyId: '2f' });
    row.querySelector('[data-legacy-last-message-id]')!.removeAttribute('data-legacy-last-message-id');
    expect(GMAIL_SITE.refForRow!(row, 'thread-f:42')).toMatchObject({ permId: 'msg-f:42', legacyId: '2a' });
  });
});
