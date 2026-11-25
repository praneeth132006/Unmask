// Renders the Chrome Web Store / Firefox Add-ons screenshots (1280x800) into docs/store/.
// Run from the repo root: node site/brand/store.mjs
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
const { chromium } = createRequire(resolve('extension/package.json'))('playwright');
const SLIDES = [
  ['1-stops-the-click', 'It stops the click', 'Wait. That link isn’t <em>PayPal.</em>', 'The email shows paypal.com. The link goes to paypa1-secure.top. Unmask stops it before the page opens, and says why.', 'inbox/gmail-link-warning.png', 'win', 700],
  ['2-plain-words', 'In plain words', 'Know if it’s a scam <em>in seconds.</em>', 'A clear verdict, the reasons in everyday words, and exactly what to do. Every point of the score explained.', 'panel/panel-summary.png', 'tall', 380],
  ['3-inbox', 'Right in your inbox', 'Warned <em>before</em> you open it.', 'Risky senders get a badge in the list. Peek checks an email without opening it, so its trackers never fire.', 'inbox/inbox-badges.png', 'win', 700],
  ['4-banner', 'Inside the email', 'Red flags, <em>where they are.</em>', 'A banner with the main reasons sits above every risky email in Gmail and Outlook.', 'inbox/gmail-banner.png', 'win', 700],
  ['5-private', 'Private by design', 'Your email <em>never leaves</em> your device.', 'Every check runs in your browser. No accounts, no tracking, no ads. Free and open source.', 'panel/links-dark.png', 'tall', 380],
];
const b = await chromium.launch();
const p = await b.newPage({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1 });
for (const [name, k, h, text, img, frame, w] of SLIDES) {
  const u = new URL(`file://${resolve('site/brand/store.html')}`);
  for (const [key, v] of Object.entries({ k, h, p: text, img, frame, w })) u.searchParams.set(key, String(v));
  await p.goto(u.href);
  await p.waitForTimeout(350);
  await p.screenshot({ path: `docs/store/${name}.png` });
  console.log('wrote', name);
}
await b.close();
