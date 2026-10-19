// End-to-end test of the built extension in real Chromium (Playwright).
// mail.google.com is routed to a local test double, so no Google account is involved.
//
//   node e2e/run.mjs            (after `pnpm build`)
//   PLAYWRIGHT_MODULE=/path/to/playwright node e2e/run.mjs
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const extPath = process.env.EXT_PATH ?? join(here, '..', '..', 'build', 'unmask-chrome');
const fixture = readFileSync(join(here, '..', 'tests', 'fixtures', 'phishing-paypal.eml'), 'utf8');
const page = readFileSync(join(here, 'fake-gmail.html'), 'utf8');

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright');

let failures = 0;
const check = (ok, label) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) failures++;
};

const ctx = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), 'unmask-e2e-')), {
  channel: 'chromium',
  headless: true,
  args: [`--disable-extensions-except=${extPath}`, `--load-extension=${extPath}`],
});

const requests = [];
await ctx.route('https://mail.google.com/**', (route) => {
  const url = route.request().url();
  requests.push(url);
  if (url.includes('view=att') && url.includes('disp=comp')) {
    return route.fulfill({ status: 200, contentType: 'application/force-download', body: fixture });
  }
  return route.fulfill({ status: 200, contentType: 'text/html', body: page });
});

let sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent('serviceworker'));
const extId = new URL(sw.url()).host;

const tab = await ctx.newPage();
// Collect uncaught exceptions from every JS world, including content scripts.
const cdp = await ctx.newCDPSession(tab);
const errors = [];
cdp.on('Runtime.exceptionThrown', (e) => errors.push(e.exceptionDetails.exception?.description ?? e.exceptionDetails.text));
cdp.on('Runtime.consoleAPICalled', (e) => {
  if (e.type === 'error') errors.push(e.args.map((a) => a.value ?? a.description).join(' '));
});
await cdp.send('Runtime.enable');

await tab.goto('https://mail.google.com/mail/u/0/#inbox/abc');
await tab.waitForTimeout(1500);

check((await tab.getAttribute('html', 'data-unmask-ik')) === 'a1b2c3d4e5', 'MAIN-world script publishes the session token');

// Ask the content script for state and the raw message, like the side panel does.
const panel = await ctx.newPage();
await panel.goto(`chrome-extension://${extId}/sidepanel.html`);
const result = await panel.evaluate(async () => {
  const [gmail] = await chrome.tabs.query({ url: 'https://mail.google.com/*' });
  const state = await chrome.tabs.sendMessage(gmail.id, { type: 'unmask:get-state' });
  const raw = await chrome.tabs.sendMessage(gmail.id, { type: 'unmask:fetch-raw', message: state.messages[0] });
  const hl = await chrome.tabs.sendMessage(gmail.id, { type: 'unmask:highlight', message: state.messages[0], target: { kind: 'sender' } });
  return { count: state.messages.length, sender: state.messages[0]?.fromEmail, ok: raw.ok, via: raw.via, rawStart: raw.ok ? raw.raw.slice(0, 13) : raw.error, found: hl?.found };
});
check(result.count === 1 && result.sender === 'billing@paypa1-support.xyz', `content script sees the open message (${result.sender})`);
check(result.ok && result.rawStart === 'Delivered-To:', `raw message downloaded via "${result.via}"`);
check(requests.some((u) => u.includes('ik=a1b2c3d4e5') && u.includes('view=att')), 'download URL carries the session token');
check(result.found === 1, 'highlight outlines the sender in the page');
check((await tab.locator('[data-unmask-hl]').count()) === 1, 'outline attribute present in the DOM');
await panel.close();

// Reload the extension, as when you press ↻ in chrome://extensions. The old content script is now orphaned.
errors.length = 0;
await sw.evaluate(() => chrome.runtime.reload());
await tab.waitForTimeout(1500);
// Make Gmail's DOM change and the URL hash change, which wakes the orphaned script's observers.
for (let i = 0; i < 5; i++) {
  await tab.evaluate((n) => {
    document.getElementById('churn').append(document.createElement('div'));
    location.hash = `#inbox/next${n}`;
  }, i);
  await tab.waitForTimeout(600);
}
await tab.waitForTimeout(1000);
const invalidated = errors.filter((e) => /context invalidated/i.test(e));
check(invalidated.length === 0, `no "Extension context invalidated" errors after reload (${invalidated.length} seen)`);
const other = errors.filter((e) => !/context invalidated/i.test(e));
check(other.length === 0, `no other uncaught errors (${other.length} seen)${other.length ? `: ${other[0]}` : ''}`);

await ctx.close();
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
