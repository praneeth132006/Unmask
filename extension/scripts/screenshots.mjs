// Takes the feature screenshots in docs/images from the real, built extension
// running in Chromium. Gmail is a local test double; no account is used.
//
//   pnpm --filter unmask-extension build:e2e && node scripts/screenshots.mjs
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import QRCode from 'qrcode';

const here = dirname(fileURLToPath(import.meta.url));
const ext = join(here, '..', '..', 'build', 'unmask-e2e');
const out = join(here, '..', '..', 'docs', 'images');

// ---- A realistic phishing email exercising the newer checks -------------------
const deflate = async (bytes) => new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(new CompressionStream('deflate'))).arrayBuffer());

async function qrPdf(text) {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  const n = qr.modules.size, scale = 6, side = (n + 8) * scale;
  const gray = new Uint8Array(side * side).fill(255);
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) if (qr.modules.get(y, x))
    for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) gray[((y + 4) * scale + dy) * side + (x + 4) * scale + dx] = 0;
  const img = await deflate(gray);
  const head = `%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R /Annots [<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://paypa1-secure.top/mfa-reset) >> >>] >> endobj\n4 0 obj << /Type /XObject /Subtype /Image /Width ${side} /Height ${side} /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length ${img.length} >>\nstream\n`;
  return Buffer.concat([Buffer.from(head, 'latin1'), Buffer.from(img), Buffer.from('\nendstream endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n', 'latin1')]);
}

function zip(files) {
  const le = (v, b) => Buffer.from(Array.from({ length: b }, (_, i) => (v >>> (8 * i)) & 0xff));
  const parts = [], central = [];
  let offset = 0;
  for (const [name, data] of files) {
    const nm = Buffer.from(name);
    const local = Buffer.concat([le(0x04034b50, 4), le(20, 2), le(0, 2), le(0, 2), le(0, 4), le(0, 4), le(data.length, 4), le(data.length, 4), le(nm.length, 2), le(0, 2), nm, data]);
    central.push(Buffer.concat([le(0x02014b50, 4), le(20, 2), le(20, 2), le(0, 2), le(0, 2), le(0, 4), le(0, 4), le(data.length, 4), le(data.length, 4), le(nm.length, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 2), le(0, 4), le(offset, 4), nm]));
    parts.push(local);
    offset += local.length;
  }
  const cd = Buffer.concat(central);
  return Buffer.concat([...parts, cd, le(0x06054b50, 4), le(0, 2), le(0, 2), le(files.length, 2), le(files.length, 2), le(cd.length, 4), le(offset, 4), le(0, 2)]);
}

const LINK = 'http://www.google.com/url?q=https://paypa1-secure.top/login?id=88&sa=D';
const html = `<div style="font-family:Arial,sans-serif;max-width:560px">
<p><img src="https://www.paypalobjects.com/webstatic/mktg/logo/pp_cc_mark_111x69.jpg" alt="PayPal" width="111"></p>
<p>Dear Customer,</p>
<p>We noticed unusual sign-in activity. Your account has been limited. You must verify your account within 24 hours or it will be permanently closed.</p>
<p>Please note our billing bank details have changed. Use the new account for any payment due this week.</p>
<p><a href="${LINK.replace(/&/g, '&amp;')}">https://www.paypal.com/signin</a></p>
<p>Or scan the QR code in the attached secure message with your phone.<img src="https://open.list-manage.com/track/open.php?u=8f2&amp;id=4c1" width="1" height="1" alt=""></p>
<p style="color:#ffffff;font-size:1px">paypal security team official notice account services</p>
</div>`;
const b64 = (b) => Buffer.from(b).toString('base64').replace(/.{76}/g, '$&\r\n');
const pdf = await qrPdf('https://m.paypa1-secure.top/verify');
const archive = zip([['Statement/Statement_Oct.pdf.exe', Buffer.from('MZ demo')], ['Statement/readme.txt', Buffer.from('open the statement')]]);
const eml = [
  'Delivered-To: you@example.com',
  'Authentication-Results: mx.google.com; spf=softfail smtp.mailfrom=paypa1-support.xyz; dkim=none; dmarc=fail (p=NONE) header.from=paypa1-support.xyz',
  'Return-Path: <bounce@mailer-paypa1.top>',
  'From: "PayPal Service" <billing@paypa1-support.xyz>',
  'Reply-To: secure-team@protonmail.com',
  'To: you@example.com',
  'Subject: Your account has been limited - action required within 24 hours',
  'Date: Mon, 19 Oct 2026 09:14:00 +0000',
  'Message-ID: <demo-1@paypa1-support.xyz>',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="b1"',
  '',
  '--b1',
  'Content-Type: text/html; charset=utf-8',
  'Content-Transfer-Encoding: base64',
  '',
  b64(html),
  '--b1',
  'Content-Type: application/pdf; name="Secure_Message.pdf"',
  'Content-Disposition: attachment; filename="Secure_Message.pdf"',
  'Content-Transfer-Encoding: base64',
  '',
  b64(pdf),
  '--b1',
  'Content-Type: application/zip; name="Statement_Oct.zip"',
  'Content-Disposition: attachment; filename="Statement_Oct.zip"',
  'Content-Transfer-Encoding: base64',
  '',
  b64(archive),
  '--b1--',
  '',
].join('\r\n');
writeFileSync(join(here, '..', 'e2e', 'demo.eml'), eml);

// ---- Fake Gmail pages -------------------------------------------------------------
const GLOBALS = '<script>var GLOBALS = [null,null,1,"/mail/u/0","en","US",null,"x",0,"a1b2c3d4e5",1];</script>';
const style = `<style>body{margin:0;font-family:"Google Sans",Roboto,Arial,sans-serif;color:#1f1f1f;background:#f6f8fc}
.top{height:56px;display:flex;align-items:center;padding:0 20px;gap:12px;font-size:20px;color:#444}
.card{background:#fff;border-radius:16px;margin:0 16px 16px;padding:20px 28px}
h2{font-size:22px;font-weight:400;margin:4px 0 16px}.from{font-size:14px}.from b{font-weight:600}.from span{color:#5e5e5e}
.a3s{font-size:14px;line-height:1.5}.btn{display:inline-block;border:1px solid #747775;border-radius:18px;padding:7px 18px;font-size:14px;margin-top:16px;cursor:pointer}
table{border-collapse:collapse;width:100%;background:#fff}tr.zA td{padding:11px 14px;border-bottom:1px solid #eef0f3;font-size:14px;white-space:nowrap}
table{table-layout:fixed}tr.zA td.s{width:200px;font-weight:600}.yW{overflow:hidden;white-space:nowrap;text-overflow:ellipsis}tr.zA td.m{color:#5e5e5e}.xT{display:flex;align-items:center;overflow:hidden;white-space:nowrap}.y2{overflow:hidden;text-overflow:ellipsis;min-width:0}tr.zA td.m b{color:#1f1f1f;font-weight:600}</style>`;
const message = `<!doctype html><html><head><meta charset="utf-8">${GLOBALS}${style}</head><body>
<div class="top">☰ &nbsp;<b style="color:#d93025">M</b> Gmail</div>
<div class="card">
<h2 class="hP" data-thread-perm-id="thread-f:1">Your account has been limited - action required within 24 hours</h2>
<div class="adn ads" data-message-id="#msg-f:1780954093844218223" data-legacy-message-id="18b7c4a2e5f1d06f">
  <div class="from"><b><span class="gD" email="billing@paypa1-support.xyz" name="PayPal Service" style="color:#1f1f1f">PayPal Service</span></b> <span>&lt;billing@paypa1-support.xyz&gt;</span></div>
  <div><div class="a3s ii">${html}</div></div>
  <div class="btn" role="button" aria-label="Reply">↩ Reply</div>
</div></div></body></html>`;
const rows = [
  ['GitHub', 'noreply@github.com', 'A new SSH key was added', 'thread-f:11'],
  ['PayPal Service', 'billing@paypa1-support.xyz', 'Your account has been limited - action required', 'thread-f:12'],
  ['Priya (Finance)', 'priya@acme-corp.com', 'Q3 budget review notes', 'thread-f:13'],
  ['Microsoft account team', 'no-reply@micros0ft-security.com', 'Unusual sign-in activity', 'thread-f:14'],
  ['Amazon Support', 'amazon.support.desk@gmail.com', 'Refund pending: confirm your card', 'thread-f:15'],
  ['Google', 'no-reply@accounts.google.com', 'Security alert for your account', 'thread-f:16'],
];
const inbox = `<!doctype html><html><head><meta charset="utf-8">${GLOBALS}${style}</head><body>
<div class="top">☰ &nbsp;<b style="color:#d93025">M</b> Gmail &nbsp;·&nbsp; Inbox</div>
<div class="card" style="padding:0;overflow:hidden"><table>${rows
  .map(([n, e, s, t]) => `<tr class="zA"><td class="s"><div class="yW"><span email="${e}" name="${n}">${n}</span></div></td><td class="m"><div class="xT"><span class="bog"><b data-thread-id="#${t}">${s}</b></span><span class="y2">&nbsp;- Please review the details in this message</span></div></td></tr>`)
  .join('')}</table></div></body></html>`;

// ---- Run --------------------------------------------------------------------------------
const ctx = await chromium.launchPersistentContext(mkdtempSync(join(tmpdir(), 'unmask-shots-')), {
  channel: 'chromium',
  headless: true,
  deviceScaleFactor: 2,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
});
await ctx.route('https://mail.google.com/**', (route) => {
  const url = route.request().url();
  if (url.includes('view=att')) return route.fulfill({ status: 200, contentType: 'application/force-download', body: eml });
  return route.fulfill({ status: 200, contentType: 'text/html', body: url.includes('/inbox-demo') ? inbox : message });
});
// Keep the screenshots offline and repeatable: no domain lookups.
const sw = ctx.serviceWorkers()[0] ?? (await ctx.waitForEvent('serviceworker'));
const extId = new URL(sw.url()).host;
await sw.evaluate(() => chrome.storage.local.set({ 'unmask:settings': { autoDomainAge: false, domainIntel: false, theme: 'light' } }));

const shot = async (page, name, clip) => {
  await page.screenshot({ path: join(out, name), clip });
  console.log('wrote', name);
};

// In Gmail: banner, link warning, reply warning.
const g = await ctx.newPage();
await g.setViewportSize({ width: 900, height: 600 });
await g.goto('https://mail.google.com/mail/u/0/', { waitUntil: 'domcontentloaded' });
await g.waitForSelector('[data-unmask-banner]', { timeout: 15000 });
await shot(g, 'gmail-banner.png');
await g.click('.a3s a');
await g.waitForSelector('[data-unmask-dialog] .d');
await g.waitForTimeout(150);
await shot(g, 'gmail-link-warning.png');
await g.locator('[data-unmask-dialog] button', { hasText: 'Go back' }).click();
await g.click('[aria-label="Reply"]');
await g.waitForSelector('[data-unmask-dialog] .d');
await g.waitForTimeout(150);
await shot(g, 'gmail-reply-warning.png');
await g.locator('[data-unmask-dialog] button', { hasText: 'Go back' }).click();

// Inbox badges.
const i = await ctx.newPage();
await i.setViewportSize({ width: 900, height: 420 });
await i.goto('https://mail.google.com/mail/u/0/inbox-demo', { waitUntil: 'domcontentloaded' });
await i.waitForSelector('[data-unmask-badge]', { timeout: 15000 });
await i.waitForTimeout(300);
await shot(i, 'inbox-badges.png');
// Peek at the PayPal row without opening it.
await i.setViewportSize({ width: 900, height: 760 });
await i.locator('tr.zA', { hasText: 'PayPal Service' }).locator('[data-unmask-peek] button').click();
await i.waitForSelector('[data-unmask-peek-card] .h', { timeout: 15000 });
await i.waitForTimeout(300);
await shot(i, 'inbox-peek.png');

// A protection list, as a family might set it up.
await sw.evaluate(() =>
  chrome.storage.local.set({
    'unmask:protection': {
      version: 1,
      label: 'Sharma family',
      brands: [{ name: 'PayPal', domains: ['paypal.com'] }, { name: 'Canara Bank', domains: ['canarabank.com'] }],
      contacts: [{ name: 'Rahul Sharma', addresses: ['rahul@acme-corp.com'] }],
      trusted: ['acme-corp.com'],
    },
  }),
);

// Side panel on the demo email.
const p = await ctx.newPage();
await p.setViewportSize({ width: 400, height: 860 });
await p.goto(`chrome-extension://${extId}/sidepanel.html`);
await p.setInputFiles('input[type=file]', { name: 'demo.eml', mimeType: 'message/rfc822', buffer: Buffer.from(eml) });
await p.waitForSelector('text=High risk', { timeout: 15000 });
await p.waitForTimeout(400);
await shot(p, 'panel-summary.png');
await p.locator('text=Report or export').scrollIntoViewIfNeeded();
await p.waitForTimeout(200);
await shot(p, 'panel-report.png');
await p.evaluate(() => window.scrollTo(0, 0));
await p.getByRole('tab', { name: /Files/ }).click();
await p.waitForTimeout(300);
await shot(p, 'panel-files.png');
await p.getByRole('tab', { name: /Links/ }).click();
const qrCard = p.locator('[id^="unmask-link-"]', { hasText: 'QR code in' });
await qrCard.scrollIntoViewIfNeeded();
await p.waitForTimeout(300);
await qrCard.screenshot({ path: join(out, 'panel-qr.png') });
console.log('wrote panel-qr.png');
// Where the tracking pixel is: Privacy tab entry, then its tag in the safe view.
await p.evaluate(() => window.scrollTo(0, 0));
await p.getByRole('tab', { name: /Privacy/ }).click();
const pixelCard = p.locator('#unmask-pixel-1');
await pixelCard.scrollIntoViewIfNeeded();
await p.waitForTimeout(300);
await pixelCard.screenshot({ path: join(out, 'panel-pixel-where.png') });
console.log('wrote panel-pixel-where.png');
await pixelCard.locator('button', { hasText: 'Show it in the safe view' }).click();
await p.waitForTimeout(600);
await shot(p, 'panel-pixel-tag.png');
await p.getByTitle('Settings').click();
await p.locator('text=Protection inside Gmail').scrollIntoViewIfNeeded();
await p.waitForTimeout(300);
await shot(p, 'settings-protection.png');
const listCard = p.locator('#unmask-protection-list');
await listCard.scrollIntoViewIfNeeded();
await p.waitForTimeout(200);
await listCard.screenshot({ path: join(out, 'settings-protection-list.png') });
console.log('wrote settings-protection-list.png');

// Simple mode: plain words only.
await sw.evaluate(() => chrome.storage.local.get('unmask:settings').then((r) => chrome.storage.local.set({ 'unmask:settings': { ...r['unmask:settings'], simpleMode: true } })));
await p.reload();
await p.setInputFiles('input[type=file]', { name: 'demo.eml', mimeType: 'message/rfc822', buffer: Buffer.from(eml) });
await p.waitForSelector('text=In plain words', { timeout: 15000 });
await p.waitForTimeout(400);
await shot(p, 'panel-simple.png');

await ctx.close();
