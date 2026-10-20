// End-to-end test of the built extension in real Chromium (Playwright).
// mail.google.com is routed to a local test double, so no Google account is involved.
//
//   node e2e/run.mjs            (after `pnpm build`)
//   PLAYWRIGHT_MODULE=/path/to/playwright node e2e/run.mjs
import { readFileSync, mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// The e2e build (UNMASK_E2E=1) adds host permission for *.unmask-e2e.test only, so the built-in tracer can be tested.
const extPath = process.env.EXT_PATH ?? join(here, '..', '..', 'build', 'unmask-e2e');

// A tiny site with a redirect chain, reached as http://*.unmask-e2e.test (mapped to this server).
const site = createServer((req, res) => {
  const host = req.headers.host ?? '';
  const route = `${host.split('.')[0]}${req.url}`;
  if (route === 'short/go') return res.writeHead(301, { location: 'http://track.unmask-e2e.test/click' }).end();
  if (route === 'track/click') return res.writeHead(302, { location: 'http://land.unmask-e2e.test/hop' }).end();
  if (route === 'land/hop') return res.writeHead(200, { 'content-type': 'text/html' }).end('<meta http-equiv="refresh" content="0;url=http://evil.unmask-e2e.test/login">');
  if (route === 'evil/login') return res.writeHead(200, { 'content-type': 'text/html' }).end('<h1>Sign in</h1>');
  if (route === 'bad/router') return res.writeHead(302, { location: 'http://192.168.1.1/admin' }).end();
  if (route === 'cookie/check') return res.writeHead(200, { 'content-type': 'text/html' }).end(req.headers.cookie ? 'HAS-COOKIE' : 'no-cookie');
  res.writeHead(404).end();
});
await new Promise((r) => site.listen(0, '127.0.0.1', r));
const sitePort = site.address().port;
const fixture = readFileSync(join(here, '..', 'tests', 'fixtures', 'phishing-paypal.eml'), 'utf8');
const page = readFileSync(join(here, 'fake-gmail.html'), 'utf8');
// An inbox list built like Gmail's: fixed-width sender column that clips overflow,
// a flex subject line, and a page that never stops changing.
const gmailRow = (unread, name, email, subject, thread, legacy) => `<tr class="zA ${unread ? 'zE' : 'yO'}" role="row">
  <td class="oZ-x3 xY"><div role="checkbox"></div></td>
  <td class="yX xY"><div class="yW"><span class="bA4"><span class="${unread ? 'zF' : 'yP'}" email="${email}" name="${name}">${name}</span></span></div></td>
  <td class="xY a4W"><div class="a4X"><div class="xS"><div class="xT"><div class="y6"><span class="bog"><span data-thread-id="#thread-f:${thread}" data-legacy-thread-id="${legacy}">${subject}</span></span></div><span class="y2"> - Please review the details in this message right away</span></div></div></div></td>
  <td class="xW xY"><span>21:07</span></td></tr>`;
const inboxPage = `<!doctype html><html><head><meta charset="utf-8"><script>var GLOBALS = [null,null,1,"/mail/u/0","en","US",null,"x",0,"a1b2c3d4e5",1];</script>
<style>body{font-family:Arial;margin:0} table{table-layout:fixed;width:1000px;border-collapse:collapse} td{padding:8px 6px;border-bottom:1px solid #eee;overflow:hidden}
td.oZ-x3{width:30px} td.yX{width:200px} .yW{overflow:hidden;white-space:nowrap;text-overflow:ellipsis} td.xW{width:70px;text-align:right}
.xS,.xT{display:flex;overflow:hidden;white-space:nowrap;align-items:center} .y6{overflow:hidden;flex-shrink:1;min-width:0} .y2{color:#666;overflow:hidden;text-overflow:ellipsis;min-width:0}</style></head><body>
<table>
${gmailRow(true, 'PayPal Service Department Notifications', 'billing@paypa1-support.xyz', 'Your account has been limited - action required within 24 hours', '1780954093844218223', '18b7c4a2e5f1d06f')}
${gmailRow(false, 'Kip Boyle via LinkedIn Newsletters', 'newsletters-noreply@linkedin.com', 'Cyber risk, explained for executives', '1780954093844218299', '18b7c4a2e5f1d0ab')}
${gmailRow(false, 'Reddit', 'noreply@redditmail.com', 'Hiii romantically', '1780954093844218300', '18b7c4a2e5f1d0ac')}
</table>
<div id="churn"></div>
<script>/* Like real Gmail, the page never stops changing. */ setInterval(function () { document.getElementById('churn').textContent = String(Date.now()); }, 60);</script>
</body></html>`;

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE ? pathToFileURL(process.env.PLAYWRIGHT_MODULE).href : 'playwright');

let failures = 0;
const check = (ok, label) => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) failures++;
};

const ctx = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), 'unmask-e2e-')), {
  channel: 'chromium',
  headless: true,
  args: [
    `--disable-extensions-except=${extPath}`,
    `--load-extension=${extPath}`,
    `--host-resolver-rules=MAP *.unmask-e2e.test:80 127.0.0.1:${sitePort}`,
  ],
});

const requests = [];
await ctx.route('https://mail.google.com/**', (route) => {
  const url = route.request().url();
  requests.push(url);
  if (url.includes('view=att') && url.includes('disp=comp')) {
    return route.fulfill({ status: 200, contentType: 'application/force-download', body: fixture });
  }
  // Real Gmail enforces Trusted Types, which also affects extension content scripts.
  const body = url.includes('/inbox-demo') ? inboxPage : page;
  return route.fulfill({ status: 200, contentType: 'text/html', headers: { 'content-security-policy': "require-trusted-types-for 'script'" }, body });
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

// In-Gmail protection runs without the side panel: banner above the risky email, check before its link.
await tab.waitForSelector('[data-unmask-banner]', { timeout: 8000 }).catch(() => {});
const bannerText = await tab.locator('[data-unmask-banner] .b').textContent().catch(() => '');
check(/High risk/.test(bannerText ?? ''), `warning banner shown inside Gmail ("${(bannerText ?? '').replace(/\s+/g, ' ').slice(0, 60)}")`);
const pagesBefore = ctx.pages().length;
await tab.click('.a3s a');
const dialogText = await tab.locator('[data-unmask-dialog] .d').textContent({ timeout: 3000 }).catch(() => '');
check(/paypa1-secure\.top/.test(dialogText ?? ''), 'clicking the risky link shows "Wait, this link goes to paypa1-secure.top"');
check(ctx.pages().length === pagesBefore, 'the link did not open');
await tab.locator('[data-unmask-dialog] button', { hasText: 'Go back' }).click();
check((await tab.locator('[data-unmask-dialog]').count()) === 0, '"Go back" closes the warning');

// Peek from the inbox list: the email is checked without being opened.
const inbox = await ctx.newPage();
await inbox.goto('https://mail.google.com/mail/u/0/inbox-demo');
await inbox.waitForFunction(() => document.querySelectorAll('[data-unmask-peek]').length === 3, null, { timeout: 8000 }).catch(() => {});
// Every row's Peek button must be really visible: the element under its centre is the button itself,
// and it lies inside its row (Gmail's clipped sender column hid it before).
const visibility = await inbox.evaluate(() =>
  [...document.querySelectorAll('tr.zA')].map((row) => {
    const host = row.querySelector('[data-unmask-peek]');
    if (!host) return 'missing';
    const r = host.getBoundingClientRect();
    if (r.width < 20 || r.height < 10) return `too small ${r.width}x${r.height}`;
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    const clip = host.closest('td').getBoundingClientRect();
    return hit === host && r.right <= clip.right + 1 ? 'visible' : 'hidden';
  }),
);
check(visibility.every((v) => v === 'visible'), `a visible Peek button on every row of a Gmail-like inbox (${visibility.join(', ')})`);
const rowClicks = await inbox.evaluate(() => { window.__rowClicks = 0; document.querySelector('tr.zA').addEventListener('click', () => window.__rowClicks++); return 0; });
// A real mouse click at the button's position, as a user would do.
await inbox.locator('tr.zA').first().locator('[data-unmask-peek] button').click().catch(() => {});
const peekText = await inbox.locator('[data-unmask-peek-card] .h').textContent({ timeout: 8000 }).catch(() => '');
check(/looks like a scam/.test(peekText ?? ''), `Peek shows the verdict without opening the email ("${peekText}")`);
check((await inbox.evaluate(() => window.__rowClicks)) === rowClicks, 'clicking Peek did not open the email');
check((await inbox.locator('[data-unmask-peek-card] .pv').textContent().catch(() => '')).length > 20, 'Peek shows a text-only preview');
const cardText = (await inbox.locator('[data-unmask-peek-card] .c').textContent().catch(() => '')) ?? '';
check(/Text preview \(no images were loaded\)/.test(cardText) && !/no trackers/i.test(cardText), 'Peek card never claims the email has "no trackers"');
check(/Contains (no remote images|\d+ (tracking pixel|remote image))/.test(cardText), 'Peek card states what trackers and images the email contains');
await inbox.close();

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

if (process.env.VITE_UNMASK_FORCE_REMOTE === '1') {
  const contexts = await panel.evaluate(() => chrome.runtime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] }));
  check(contexts.length === 1, 'with parsing blocked in the page, the email was analyzed in the offscreen document');
}

// Built-in redirect tracing, asked for by the panel like the "Trace redirects" button does.
const trace = await panel.evaluate(async () => {
  const run = (url) => chrome.runtime.sendMessage({ type: 'unmask:trace', url });
  return { chain: await run('http://short.unmask-e2e.test/go'), blocked: await run('http://bad.unmask-e2e.test/router'), local: await run('http://localhost/x') };
});
const hops = trace.chain.ok ? trace.chain.result.hops.map((h) => `${h.status} ${new URL(h.url).host.split('.')[0]}${h.via ? ` (${h.via})` : ''}`) : [trace.chain.error];
check(
  JSON.stringify(hops) === JSON.stringify(['301 short (http)', '302 track (http)', '200 land (meta-refresh)', '200 evil']),
  `built-in tracer follows HTTP and meta-refresh redirects: ${hops.join(' → ')}`,
);
check(trace.chain.ok && trace.chain.result.finalUrl === 'http://evil.unmask-e2e.test/login', 'tracer reports the final page');
check(!trace.blocked.ok || /local network/.test(trace.blocked.result.error ?? ''), `redirect to a local-network address is stopped (${trace.blocked.ok ? trace.blocked.result.error : trace.blocked.error})`);
check(trace.local.ok && /local network/.test(trace.local.result.error ?? ''), 'tracing localhost is refused');
check((await tab.locator('[data-unmask-hl]').count()) === 1, 'outline attribute present in the DOM');
// The tabs (including Headers) must be there in both normal and simple mode.
for (const simpleMode of [false, true]) {
  await panel.evaluate((v) => chrome.storage.local.get('unmask:settings').then((r) => chrome.storage.local.set({ 'unmask:settings': { ...(r['unmask:settings'] ?? {}), simpleMode: v } })), simpleMode);
  await panel.reload();
  await panel.setInputFiles('input[type=file]', { name: 'phish.eml', mimeType: 'message/rfc822', buffer: Buffer.from(fixture) });
  await panel.waitForSelector('[role="tab"]', { timeout: 10000 }).catch(() => {});
  const tabs = await panel.locator('[role="tab"]').allTextContents();
  const names = tabs.map((t) => t.replace(/\d+/g, '').trim());
  const all = ['Summary', 'Sender', 'Links', 'Files', 'Body', 'Privacy', 'Headers'].every((n) => names.includes(n));
  check(all, `all 7 tabs shown with simple mode ${simpleMode ? 'on' : 'off'} (${names.join(', ')})`);
  await panel.locator('[role="tab"]', { hasText: 'Headers' }).click().catch(() => {});
  const headersShown = await panel.getByText(/^All headers \(\d+\)$/).waitFor({ timeout: 5000 }).then(() => true, () => false);
  check(headersShown, `the Headers tab opens with simple mode ${simpleMode ? 'on' : 'off'}`);
}
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
site.close();
console.log(failures ? `\n${failures} check(s) failed` : '\nall checks passed');
process.exit(failures ? 1 : 0);
