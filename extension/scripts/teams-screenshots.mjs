// Screenshots for the teams guide (docs/TEAMS.md), from the real built extension in Chromium.
// The organisation's list normally comes from browser policy; here it is supplied to the page
// the same way policy would, so no managed browser is needed.
//
//   pnpm --filter unmask-extension build:e2e && node scripts/teams-screenshots.mjs
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const here = dirname(fileURLToPath(import.meta.url));
const ext = join(here, '..', '..', 'build', 'unmask-e2e');
const out = join(here, '..', '..', 'docs', 'images');

const ORG = {
  label: 'Acme IT',
  brands: [
    { name: 'Acme Payroll', domains: ['acmepayroll.com'] },
    { name: 'HDFC Bank', domains: ['hdfcbank.com', 'hdfcbank.net'] },
  ],
  contacts: [{ name: 'Priya Menon (CEO)', addresses: ['priya@acme.com'] }],
  trusted: ['acme.com'],
};
const OWN = {
  version: 1,
  brands: [{ name: 'Airtel', domains: ['airtel.in'] }],
  contacts: [{ name: 'Amma', addresses: ['lakshmi.r@gmail.com'] }],
  trusted: ['school.edu.in'],
};
const rec = (address, name, count, signer) => [
  address,
  { address, name, domain: address.split('@')[1].split('.').slice(-2).join('.'), count, firstSeen: 0, lastSeen: 0, ids: [], traits: { dkim: { [signer]: count }, route: {}, messageId: {}, mailer: {}, replyTo: {} } },
];
const HISTORY = {
  senders: Object.fromEntries([
    rec('alerts@hdfcbank.net', 'HDFC Bank', 14, 'hdfcbank.net'),
    rec('noreply@github.com', 'GitHub', 11, 'github.com'),
    rec('ravi@acmevendor.com', 'Ravi Kumar', 6, 'acmevendor.com'),
    rec('offers@spam-deals.top', 'Deals', 8, 'none'),
  ]),
};

const ctx = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), 'unmask-teams-')), {
  channel: 'chromium',
  headless: true,
  deviceScaleFactor: 2,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
});
const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent('serviceworker'));
const id = new URL(sw.url()).host;

const open = async ({ theme = 'light', managed = null, own = OWN } = {}) => {
  await sw.evaluate(
    ([theme, own, history]) =>
      chrome.storage.local.clear().then(() =>
        chrome.storage.local.set({ 'unmask:settings': { theme, autoDomainAge: false, domainIntel: false }, 'unmask:protection': own, 'unmask:sender-history': history }),
      ),
    [theme, own, HISTORY],
  );
  const p = await ctx.newPage();
  if (managed) {
    await p.addInitScript((list) => {
      chrome.storage.managed.get = (keys, cb) => {
        const v = { protectionList: list };
        return cb ? cb(v) : Promise.resolve(v);
      };
    }, managed);
  }
  await p.setViewportSize({ width: 400, height: 2200 });
  await p.goto(`chrome-extension://${id}/sidepanel.html`);
  await p.getByTitle('Settings').click();
  // The sticky header would cover the top of a tall element.
  await p.addStyleTag({ content: 'header { position: static !important; }' });
  await p.locator('#unmask-protection-list').scrollIntoViewIfNeeded();
  await p.waitForTimeout(400);
  return p;
};

const shoot = async (locator, name) => {
  await locator.screenshot({ path: join(out, name) });
  console.log('wrote', name);
};

// 1. A family's own list: everything in one card.
let p = await open();
await shoot(p.locator('#unmask-protection-list'), 'teams-own-list.png');
// 2. One-click trust suggestions.
await shoot(p.locator('#unmask-protection-list div.rounded-lg', { hasText: 'Suggested from your inbox' }), 'teams-suggestions.png');
// 3. Sharing: export, import, copy for IT admin.
await shoot(p.locator('#unmask-protection-list > div', { hasText: 'Share with family or your team' }), 'teams-share.png');
await p.close();

// 4. What every employee sees once the admin pushes the list.
p = await open({ managed: ORG, own: { version: 1, brands: [], contacts: [], trusted: [] } });
await shoot(p.locator('#unmask-protection-list div.rounded-lg', { hasText: 'From “Acme IT”' }), 'teams-org-list.png');
await p.close();

await ctx.close();
