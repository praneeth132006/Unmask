import { analyzeRawEmail } from '../src/core/analyze';
import { startProtection, type ProtectSettings } from '../src/lib/gmailProtect';
import { PEEK_ATTR } from '../src/lib/inpage';
import { EMPTY_HISTORY } from '../src/analyzers/history';
import type { GmailMessageRef } from '../src/lib/messages';
import { fixture } from './helpers';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(check: () => boolean, ms = 4000) {
  for (let t = 0; t < ms && !check(); t += 20) await sleep(20);
  expect(check()).toBe(true);
}

const INBOX = `<table>
  <tr class="zA zE" id="r1"><td><span email="billing@paypa1-support.xyz" name="PayPal Service">PayPal Service</span><span class="bog">Your account has been limited</span><span data-thread-id="#thread-f:1780954093844218223" data-legacy-thread-id="18b7c4a2e5f1d06f"></span></td></tr>
  <tr class="zA" id="r2"><td><span email="ann@acme.com" name="Ann">Ann</span><span class="bog">Lunch</span><span data-thread-id="#thread-f:42"></span></td></tr>
</table>`;

function start(settings: Partial<ProtectSettings>) {
  document.body.innerHTML = INBOX;
  const fetched: GmailMessageRef[] = [];
  const opened: string[] = [];
  document.querySelectorAll('tr.zA').forEach((tr) => tr.addEventListener('click', () => opened.push(tr.id)));
  const peeked: GmailMessageRef[] = [];
  const p = startProtection({
    doc: document,
    win: window,
    readState: () => ({ accountIndex: '0', messages: [] }),
    fetchRaw: async (ref) => {
      fetched.push(ref);
      return ref.permId === 'msg-f:1780954093844218223' ? { ok: true, raw: fixture('phishing-paypal.eml'), via: 'test' } : { ok: true, raw: fixture('legit-newsletter.eml'), via: 'test' };
    },
    analyze: (raw) => analyzeRawEmail(raw),
    settings: () => ({ gmailBanner: true, inboxBadges: true, clickProtection: true, senderHistory: false, peekButtons: true, scanInbox: false, ...settings }),
    loadHistory: async () => EMPTY_HISTORY,
    rememberSender: async () => {},
    loadVerdicts: async () => ({}),
    saveVerdicts: async () => {},
    openPeekInPanel: (ref) => peeked.push(ref),
    debounceMs: 10,
  });
  return { p, fetched, opened, peeked };
}

describe('Peek: check an inbox email without opening it', () => {
  let stop: (() => void) | undefined;
  afterEach(() => {
    stop?.();
    document.body.innerHTML = '';
  });

  it('puts a Peek button on each row', async () => {
    const { p } = start({});
    stop = p.stop;
    await until(() => document.querySelectorAll(`[${PEEK_ATTR}]`).length === 2);
  });

  it('checks the email from the row, without opening it, and shows a text-only preview', async () => {
    const { p, fetched, opened, peeked } = start({});
    stop = p.stop;
    await until(() => document.querySelectorAll(`[${PEEK_ATTR}]`).length === 2);
    const button = document.querySelector(`#r1 [${PEEK_ATTR}]`)!.shadowRoot!.querySelector('button')!;
    button.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, composed: true }));
    button.dispatchEvent(new MouseEvent('click', { bubbles: true, composed: true, cancelable: true }));
    expect(opened).toEqual([]); // the row never saw the click
    const card = () => document.querySelector('[data-unmask-peek-card]')?.shadowRoot;
    await until(() => /High risk/.test(card()?.textContent ?? ''));
    expect(fetched[0]).toMatchObject({ permId: 'msg-f:1780954093844218223', legacyId: '18b7c4a2e5f1d06f' });
    const text = card()!.textContent!;
    expect(text).toContain('This email looks like a scam.');
    expect(text).toContain('Text preview (no images, no trackers)');
    expect(text).toContain('Not opened in Gmail');
    Array.from(card()!.querySelectorAll('button')).find((b) => b.textContent === 'Read it safely in Unmask')!.click();
    expect(peeked).toHaveLength(1);
    // The full verdict now drives the row's badge.
    await until(() => /Risky/.test(document.querySelector('#r1 [data-unmask-badge]')?.shadowRoot?.textContent ?? ''));
  });

  it('checks unread rows by itself when asked to, and leaves read ones alone', async () => {
    const { p, fetched } = start({ scanInbox: true });
    stop = p.stop;
    await until(() => fetched.length === 1);
    await sleep(600);
    expect(fetched.map((r) => r.permId)).toEqual(['msg-f:1780954093844218223']);
  });

  it('adds no Peek buttons when switched off', async () => {
    const { p } = start({ peekButtons: false });
    stop = p.stop;
    await sleep(200);
    expect(document.querySelectorAll(`[${PEEK_ATTR}]`)).toHaveLength(0);
  });
});
