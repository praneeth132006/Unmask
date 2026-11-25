import { analyzeRawEmail } from '../src/core/analyze';
import { askHelperLink, familyBlocks, hashPin, newSalt, pinMatches, validHelper } from '../src/lib/family';
import { addEvent, EMPTY_STATS, thisAndLastWeek, weekOf, weekSentence } from '../src/lib/stats';
import { startProtection, type ProtectSettings } from '../src/lib/gmailProtect';
import { EMPTY_HISTORY } from '../src/analyzers/history';
import type { StatEvent } from '../src/lib/stats';
import { fixture } from './helpers';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(check: () => boolean, ms = 3000) {
  for (let t = 0; t < ms && !check(); t += 20) await sleep(20);
  expect(check()).toBe(true);
}

describe('family mode', () => {
  it('writes the helper a plain email with nothing clickable in it', async () => {
    const r = await analyzeRawEmail(fixture('phishing-paypal.eml'));
    const link = askHelperLink({ name: 'Sam', email: 'sam@example.org' }, r);
    expect(link.startsWith('mailto:sam@example.org?subject=')).toBe(true);
    const body = decodeURIComponent(link.split('&body=')[1]!);
    expect(body).toContain('Hi Sam,');
    expect(body).toContain('Unmask says: High risk');
    expect(body).toContain('paypa1-support[.]xyz');
    expect(body).not.toMatch(/https?:\/\//);
  });

  it('checks the helper address and only blocks High risk emails', async () => {
    expect(validHelper({ name: 'Sam', email: 'sam@example.org' })).toBe(true);
    expect(validHelper({ name: 'Sam', email: 'sam' })).toBe(false);
    const high = await analyzeRawEmail(fixture('phishing-paypal.eml'));
    const clear = await analyzeRawEmail(fixture('legit-newsletter.eml'));
    expect(familyBlocks({ familyMode: true }, high)).toBe(true);
    expect(familyBlocks({ familyMode: true }, clear)).toBe(false);
    expect(familyBlocks({ familyMode: false }, high)).toBe(false);
  });

  it('stores the PIN only as a salted fingerprint', async () => {
    const salt = newSalt();
    const hash = await hashPin('2580', salt);
    expect(hash).not.toContain('2580');
    expect(await pinMatches('2580', salt, hash)).toBe(true);
    expect(await pinMatches('0000', salt, hash)).toBe(false);
    expect(await pinMatches('2580', newSalt(), hash)).toBe(false);
    expect(await pinMatches('2580', salt, '')).toBe(false);
  });
});

describe('weekly summary', () => {
  const mon = new Date(2026, 10, 9, 10); // Monday 9 November 2026
  it('starts weeks on Monday and counts each email once', () => {
    expect(weekOf(new Date(2026, 10, 15, 23))).toBe('2026-11-09');
    expect(weekOf(new Date(2026, 10, 16, 1))).toBe('2026-11-16');
    let s = addEvent(EMPTY_STATS, { type: 'checked', key: 'msg-1', verdict: 'high' }, mon);
    s = addEvent(s, { type: 'checked', key: 'msg-1', verdict: 'high' }, mon);
    s = addEvent(s, { type: 'checked', key: 'msg-2', verdict: 'clear' }, mon);
    s = addEvent(s, { type: 'stopped', what: 'link' }, mon);
    const w = thisAndLastWeek(s, mon).thisWeek;
    expect(w).toMatchObject({ checked: 2, warned: 1, high: 1, clicksStopped: 1, repliesStopped: 0 });
    expect(weekSentence(w)).toBe('checked 2 emails, warned you about 1 (1 high risk) and stopped 1 risky click');
    expect(JSON.stringify(s)).not.toContain('msg-1');
  });

  it('keeps two years of weeks and reads last week', () => {
    let s = EMPTY_STATS;
    for (let i = 0; i < 110; i++) s = addEvent(s, { type: 'checked', key: `k${i}`, verdict: 'clear' }, new Date(2024, 9, 7 + i * 7, 12));
    expect(Object.keys(s.weeks)).toHaveLength(104);
    const last = new Date(2024, 9, 7 + 109 * 7, 12);
    const now = new Date(last.getFullYear(), last.getMonth(), last.getDate() + 7, 12);
    expect(thisAndLastWeek(s, now).lastWeek?.checked).toBe(1);
  });
});

describe('family mode inside Gmail', () => {
  const PHISH_LINK = 'http://www.google.com/url?q=https://paypa1-secure.top/login?id=88&sa=D';
  let stop: (() => void) | undefined;
  afterEach(() => { stop?.(); document.body.innerHTML = ''; });

  async function start(settings: ProtectSettings) {
    document.body.innerHTML = `<h2 data-thread-perm-id="thread-f:1">x</h2><div data-message-id="#msg-f:1"><div role="button" aria-label="Reply">Reply</div><div class="a3s"><a id="bad" href="${PHISH_LINK.replace(/&/g, '&amp;')}">https://www.paypal.com/signin</a></div></div>`;
    const events: StatEvent[] = [];
    const opened: string[] = [];
    const p = startProtection({
      doc: document,
      win: Object.assign(window, { open: (u: string) => (opened.push(u), null) }) as unknown as Window,
      readState: () => ({ accountIndex: '0', messages: [{ permId: 'msg-f:1', legacyId: null, fromName: '', fromEmail: '', subject: '' }] }),
      fetchRaw: async () => ({ ok: true, raw: fixture('phishing-paypal.eml'), via: 'test' }),
      analyze: (raw) => analyzeRawEmail(raw),
      settings: () => settings,
      loadHistory: async () => EMPTY_HISTORY,
      rememberSender: async () => {},
      loadVerdicts: async () => ({}),
      saveVerdicts: async () => {},
      onEvent: (e) => void events.push(e),
      debounceMs: 10,
    });
    stop = p.stop;
    await until(() => p.reports.size === 1);
    return { events, opened };
  }
  const dialog = () => document.querySelector('[data-unmask-dialog]')?.shadowRoot;

  it('offers "Ask Sam" instead of "Open anyway" on a High risk email', async () => {
    const { events, opened } = await start({ gmailBanner: true, inboxBadges: true, clickProtection: true, senderHistory: false, familyMode: true, helperName: 'Sam', helperEmail: 'sam@example.org' });
    expect(events).toContainEqual({ type: 'checked', key: expect.any(String), verdict: 'high' });
    document.getElementById('bad')!.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, button: 0 }));
    await until(() => Boolean(dialog()));
    const labels = [...dialog()!.querySelectorAll('button, a')].map((b) => b.textContent);
    expect(labels).toEqual(['Ask Sam', 'Go back']);
    expect(dialog()!.querySelector('a')!.getAttribute('href')).toMatch(/^mailto:sam@example\.org\?/);
    expect(dialog()!.textContent).toContain('Family mode is on');
    [...dialog()!.querySelectorAll('button')].find((b) => b.textContent === 'Go back')!.click();
    await until(() => events.some((e) => e.type === 'stopped' && e.what === 'link'));
    expect(opened).toEqual([]);
  });

  it('still lets people choose when family mode is off', async () => {
    await start({ gmailBanner: true, inboxBadges: true, clickProtection: true, senderHistory: false });
    document.querySelector('[aria-label="Reply"]')!.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, button: 0 }));
    await until(() => Boolean(dialog()));
    expect([...dialog()!.querySelectorAll('button')].map((b) => b.textContent)).toEqual(['Reply anyway', 'Go back']);
  });
});
