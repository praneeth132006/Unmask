import { analyzeRawEmail } from '../src/core/analyze';
import { linkWarning, pruneVerdicts, quickVerdict, replyWarning } from '../src/lib/protect';
import { startProtection, type ProtectSettings } from '../src/lib/gmailProtect';
import { BADGE_ATTR, BANNER_ATTR } from '../src/lib/inpage';
import { EMPTY_HISTORY } from '../src/analyzers/history';
import type { StoredVerdict } from '../src/lib/protect';
import { fixture } from './helpers';

const PHISH_LINK = 'http://www.google.com/url?q=https://paypa1-secure.top/login?id=88&sa=D';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(check: () => boolean, ms = 3000) {
  for (let t = 0; t < ms && !check(); t += 20) await sleep(20);
  expect(check()).toBe(true);
}

describe('protection decisions', () => {
  it('warns before a risky link and names the real host', async () => {
    const r = await analyzeRawEmail(fixture('phishing-paypal.eml'));
    expect(linkWarning(r, PHISH_LINK)).toMatchObject({ host: 'paypa1-secure.top' });
    // Gmail sometimes rewrites href and keeps the original in data-saferedirecturl.
    expect(linkWarning(r, 'https://example.invalid/x', `https://www.google.com/url?q=${encodeURIComponent('https://bit.ly/3xYzAbc')}`)?.host).toBe('bit.ly');
  });

  it('lets ordinary links through', async () => {
    const r = await analyzeRawEmail(fixture('legit-newsletter.eml'));
    expect(linkWarning(r, 'https://github.com/settings/keys')).toBeNull();
  });

  it('warns when replies go elsewhere', async () => {
    expect(replyWarning(await analyzeRawEmail(fixture('phishing-paypal.eml')))).toEqual({ replyTo: 'secure-team@protonmail.com', from: 'billing@paypa1-support.xyz' });
    expect(replyWarning(await analyzeRawEmail(fixture('legit-newsletter.eml')))).toBeNull();
  });

  it('rates inbox senders from the From line alone', () => {
    expect(quickVerdict('PayPal', 'service@paypa1-support.xyz').verdict).not.toBe('clear');
    expect(quickVerdict('Ann Lee', 'ann@acme.com', EMPTY_HISTORY).verdict).toBe('clear');
  });

  it('caps the verdict cache', () => {
    const many: Record<string, StoredVerdict> = Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`t${i}`, { verdict: 'clear', score: 0, reasons: [], at: i }]));
    expect(Object.keys(pruneVerdicts(many, 2))).toEqual(['t4', 't3']);
  });
});

describe('protection inside a Gmail page', () => {
  const settings: ProtectSettings = { gmailBanner: true, inboxBadges: true, clickProtection: true, senderHistory: false };
  let stop: (() => void) | undefined;
  afterEach(() => {
    stop?.();
    document.body.innerHTML = '';
  });

  function page() {
    document.body.innerHTML = `
      <table><tr class="zA"><td><span email="billing@paypa1-support.xyz" name="PayPal Service">PayPal Service</span><span data-thread-id="#thread-f:9"></span></td></tr>
      <tr class="zA"><td><span email="ann@acme.com" name="Ann">Ann</span></td></tr></table>
      <h2 data-thread-perm-id="thread-f:1">Your account</h2>
      <div data-message-id="#msg-f:1">
        <div role="button" aria-label="Reply">Reply</div>
        <div><div class="a3s"><a id="bad" href="${PHISH_LINK.replace(/&/g, '&amp;')}">https://www.paypal.com/signin</a></div></div>
      </div>`;
  }

  async function start(saved: Record<string, StoredVerdict> = {}) {
    page();
    const opened: string[] = [];
    let store = saved;
    const p = startProtection({
      doc: document,
      win: Object.assign(window, { open: (u: string) => (opened.push(u), null) }) as unknown as Window,
      readState: () => ({ accountIndex: '0', messages: [{ permId: 'msg-f:1', legacyId: null, fromName: '', fromEmail: '', subject: '' }] }),
      fetchRaw: async () => ({ ok: true, raw: fixture('phishing-paypal.eml'), via: 'test' }),
      analyze: (raw) => analyzeRawEmail(raw),
      settings: () => settings,
      loadHistory: async () => EMPTY_HISTORY,
      rememberSender: async () => {},
      loadVerdicts: async () => store,
      saveVerdicts: async (v) => void (store = v),
      debounceMs: 10,
    });
    stop = p.stop;
    await until(() => p.reports.size === 1);
    return { p, opened, store: () => store };
  }

  it('shows a banner above the risky email and remembers the thread verdict', async () => {
    const { store } = await start();
    await until(() => Boolean(document.querySelector(`[${BANNER_ATTR}]`)));
    const banner = document.querySelector(`[${BANNER_ATTR}]`)!;
    expect(banner.nextElementSibling?.classList.contains('a3s')).toBe(true);
    expect(banner.shadowRoot?.textContent).toContain('High risk');
    await until(() => store()['thread-f:1']?.verdict === 'high');
  });

  it('badges risky senders in the inbox list only', async () => {
    await start({ 'thread-f:9': { verdict: 'high', score: 80, reasons: ['Lookalike domain'], at: Date.now() } });
    await until(() => document.querySelectorAll(`[${BADGE_ATTR}]`).length === 1);
    const rows = document.querySelectorAll('tr.zA');
    expect(rows[0]!.querySelector(`[${BADGE_ATTR}]`)?.shadowRoot?.textContent).toContain('Risky');
    expect(rows[1]!.querySelector(`[${BADGE_ATTR}]`)).toBeNull();
  });

  it('holds a risky link behind "Wait, this goes to"', async () => {
    const { opened } = await start();
    const click = new MouseEvent('click', { bubbles: true, cancelable: true, button: 0 });
    document.getElementById('bad')!.dispatchEvent(click);
    expect(click.defaultPrevented).toBe(true);
    const dialog = () => document.querySelector('[data-unmask-dialog]')?.shadowRoot;
    await until(() => Boolean(dialog()));
    expect(dialog()!.textContent).toContain('paypa1-secure.top');
    const [openAnyway] = Array.from(dialog()!.querySelectorAll('button'));
    openAnyway!.click();
    await until(() => opened.length === 1);
    expect(opened[0]).toBe(PHISH_LINK);
  });

  it('warns before replying to a different address', async () => {
    await start();
    const click = new MouseEvent('click', { bubbles: true, cancelable: true, button: 0 });
    document.querySelector('[aria-label="Reply"]')!.dispatchEvent(click);
    expect(click.defaultPrevented).toBe(true);
    const dialog = document.querySelector('[data-unmask-dialog]')!.shadowRoot!;
    expect(dialog.textContent).toContain('secure-team@protonmail.com');
    Array.from(dialog.querySelectorAll('button')).find((b) => b.textContent === 'Go back')!.click();
    await until(() => !document.querySelector('[data-unmask-dialog]'));
  });
});
