// Takes the feature screenshots in docs/images (sorted into folders by image-folders.mjs) from the real, built extension
// running in Chromium. Gmail is a local test double; no account is used.
//
//   pnpm --filter unmask-extension build:e2e && node scripts/screenshots.mjs
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { imagePath } from './image-folders.mjs';
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import QRCode from 'qrcode';
import { demoDocm, demoPdf, zipStore } from './fixtures.mjs';

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
const style = `<style>
*{box-sizing:border-box}body{margin:0;font-family:"Google Sans","Product Sans",Roboto,"Segoe UI",Arial,sans-serif;color:#1f1f1f;background:#f6f8fc;font-size:14px}
.gb{height:64px;display:flex;align-items:center;padding:0 16px 0 12px;gap:6px}
.ic{width:40px;height:40px;border-radius:50%;display:grid;place-items:center;color:#444746}.ic svg{width:22px;height:22px;fill:currentColor}
.logo{display:flex;align-items:center;gap:6px;width:200px;font-size:22px;color:#444746;letter-spacing:-.2px}.logo svg{width:36px;height:27px}
.search{flex:1;max-width:720px;height:48px;border-radius:24px;background:#e9eef6;display:flex;align-items:center;gap:14px;padding:0 16px;color:#444746;font-size:16px}
.search svg{width:22px;height:22px;fill:#444746}.right{margin-left:auto;display:flex;align-items:center;gap:4px}
.av{width:32px;height:32px;border-radius:50%;background:#0b57d0;color:#fff;display:grid;place-items:center;font-weight:500;font-size:15px}
.body{display:flex}.rail{width:256px;flex:none;padding:8px 16px 0 8px}
.compose{display:inline-flex;align-items:center;gap:14px;height:56px;padding:0 24px 0 18px;border-radius:16px;background:#c2e7ff;font-weight:500;font-size:14px;color:#001d35;margin:0 0 16px 0}
.compose svg{width:22px;height:22px;fill:#001d35}
.nav{display:flex;align-items:center;gap:18px;height:32px;padding:0 12px 0 24px;border-radius:0 16px 16px 0;color:#202124;font-size:14px}
.nav svg{width:20px;height:20px;fill:#444746}.nav.on{background:#d3e3fd;font-weight:700}.nav .n{margin-left:auto;font-size:12px;font-weight:700}
.main{flex:1;min-width:0;background:#fff;border-radius:16px;margin:0 16px 16px 0;overflow:hidden}
.tools{height:48px;display:flex;align-items:center;gap:6px;padding:0 12px;border-bottom:1px solid #f1f3f4}.tools .ic{width:36px;height:36px}.tools .ic svg{width:20px;height:20px}
.read{padding:8px 24px 24px 72px;position:relative}
h2{font-size:22px;font-weight:400;margin:12px 0 18px;color:#1f1f1f}.lab{font-size:12px;background:#e8eaed;border-radius:4px;padding:2px 6px;margin-left:10px;vertical-align:3px;color:#444}
.from{display:flex;align-items:flex-start;gap:12px;margin:0 0 18px -56px}.sav{width:40px;height:40px;border-radius:50%;background:#7e57c2;color:#fff;display:grid;place-items:center;font-size:18px;flex:none}
.who{flex:1;min-width:0;font-size:14px}.who b{font-weight:700}.who .addr{color:#5e5e5e;font-size:12px}.who .to{color:#5e5e5e;font-size:12px;margin-top:2px}.when{color:#5e5e5e;font-size:12px;white-space:nowrap}
.a3s{font-size:14px;line-height:1.55}.btns{display:flex;gap:10px;margin-top:22px}.btn{display:inline-flex;align-items:center;gap:8px;border:1px solid #747775;border-radius:18px;padding:8px 20px;font-size:14px;font-weight:500;color:#444746;cursor:pointer}
table{border-collapse:collapse;width:100%;table-layout:fixed}tr.zA td{height:40px;padding:0 10px;border-bottom:1px solid #f1f3f4;font-size:14px;white-space:nowrap}
tr.zA td.cb{width:64px;color:#c4c7c5}tr.zA td.s{width:200px;font-weight:700}.yW{overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
tr.zA td.m{color:#5e5e5e}.xT{display:flex;align-items:center;overflow:hidden;white-space:nowrap}.y2{overflow:hidden;text-overflow:ellipsis;min-width:0}tr.zA td.m b{color:#1f1f1f;font-weight:700}
tr.zA td.t{width:90px;text-align:right;font-weight:700;font-size:12px;color:#1f1f1f}
</style>`;
const svg = (d) => `<svg viewBox="0 0 24 24"><path d="${d}"/></svg>`;
const I = {
  menu: 'M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z',
  search: 'M15.5 14h-.79l-.28-.27A6.47 6.47 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z',
  help: 'M11 18h2v-2h-2v2zm1-16C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm0-14c-2.21 0-4 1.79-4 4h2c0-1.1.9-2 2-2s2 .9 2 2c0 2-3 1.75-3 5h2c0-2.25 3-2.5 3-5 0-2.21-1.79-4-4-4z',
  gear: 'M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.49.49 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.48.48 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.48.48 0 0 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32a.48.48 0 0 0-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1 1 12 8.4a3.6 3.6 0 0 1 0 7.2z',
  apps: 'M4 8h4V4H4v4zm6 12h4v-4h-4v4zm-6 0h4v-4H4v4zm0-6h4v-4H4v4zm6 0h4v-4h-4v4zm6-10v4h4V4h-4zm-6 4h4V4h-4v4zm6 6h4v-4h-4v4zm0 6h4v-4h-4v4z',
  pen: 'M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1 1 0 0 0 0-1.41l-2.34-2.34a1 1 0 0 0-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z',
  inbox: 'M19 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V5a2 2 0 0 0-2-2zm0 12h-4a3 3 0 0 1-6 0H5V5h14v10z',
  star: 'M12 17.27 18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z',
  clock: 'M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20c-4.42 0-8-3.58-8-8s3.58-8 8-8 8 3.58 8 8-3.58 8-8 8zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z',
  send: 'M2.01 21 23 12 2.01 3 2 10l15 2-15 2z',
  draft: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z',
  back: 'M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z',
  archive: 'M20.54 5.23 19.15 3.55A1.45 1.45 0 0 0 18 3H6c-.47 0-.88.21-1.16.55L3.46 5.23A1.98 1.98 0 0 0 3 6.5V19a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6.5c0-.48-.17-.93-.46-1.27zM12 17.5 6.5 12H10v-2h4v2h3.5L12 17.5zM5.12 5l.81-1h12l.94 1H5.12z',
  spam: 'M15.73 3H8.27L3 8.27v7.46L8.27 21h7.46L21 15.73V8.27L15.73 3zM12 17.3a1.3 1.3 0 1 1 0-2.6 1.3 1.3 0 0 1 0 2.6zm1-4.3h-2V7h2v6z',
  trash: 'M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z',
  reply: 'M10 9V5l-7 7 7 7v-4.1c5 0 8.5 1.6 11 5.1-1-5-4-10-11-11z',
  fwd: 'M14 9V5l7 7-7 7v-4.1c-5 0-8.5 1.6-11 5.1 1-5 4-10 11-11z',
};
// The Gmail mark, drawn in its four colours.
const gmailLogo = '<svg viewBox="0 0 48 36"><path fill="#4285f4" d="M3.3 36h7.6V17.6L0 9.4v23.3A3.3 3.3 0 0 0 3.3 36"/><path fill="#34a853" d="M37.1 36h7.6a3.3 3.3 0 0 0 3.3-3.3V9.4l-10.9 8.2"/><path fill="#fbbc04" d="M37.1 3.4v14.2L48 9.4V5a4.9 4.9 0 0 0-7.9-3.9"/><path fill="#ea4335" d="M10.9 17.6V3.4L24 13.2l13.1-9.8v14.2L24 27.4"/><path fill="#c5221f" d="M0 5v4.4l10.9 8.2V3.4L7.9 1.1A4.9 4.9 0 0 0 0 5"/></svg>';
const shell = (main, active = 'inbox') => `<div class="gb"><div class="ic">${svg(I.menu)}</div><div class="logo">${gmailLogo}Gmail</div>
<div class="search">${svg(I.search)}Search mail</div><div class="right"><div class="ic">${svg(I.help)}</div><div class="ic">${svg(I.gear)}</div><div class="ic">${svg(I.apps)}</div><div class="av">A</div></div></div>
<div class="body"><div class="rail"><div class="compose">${svg(I.pen)}Compose</div>
${[['inbox', 'Inbox', '6'], ['star', 'Starred', ''], ['clock', 'Snoozed', ''], ['send', 'Sent', ''], ['draft', 'Drafts', '2']].map(([i, l, n]) => `<div class="nav${i === active ? ' on' : ''}">${svg(I[i])}${l}<span class="n">${n}</span></div>`).join('')}</div>
<div class="main">${main}</div></div>`;
const message = `<!doctype html><html><head><meta charset="utf-8">${GLOBALS}${style}</head><body>
${shell(`<div class="tools"><div class="ic">${svg(I.back)}</div><div class="ic">${svg(I.archive)}</div><div class="ic">${svg(I.spam)}</div><div class="ic">${svg(I.trash)}</div></div>
<div class="read">
<h2 class="hP" data-thread-perm-id="thread-f:1">Your account has been limited - action required within 24 hours<span class="lab">Inbox</span></h2>
<div class="adn ads" data-message-id="#msg-f:1780954093844218223" data-legacy-message-id="18b7c4a2e5f1d06f">
  <div class="from"><div class="sav">P</div><div class="who"><b><span class="gD" email="billing@paypa1-support.xyz" name="PayPal Service" style="color:#1f1f1f">PayPal Service</span></b> <span class="addr">&lt;billing@paypa1-support.xyz&gt;</span><div class="to">to me ▾</div></div><div class="when">9:14 AM (2 hours ago)</div></div>
  <div><div class="a3s ii">${html}</div></div>
  <div class="btns"><div class="btn" role="button" aria-label="Reply">${svg(I.reply)}Reply</div><div class="btn">${svg(I.fwd)}Forward</div></div>
</div></div>`)}</body></html>`;
const rows = [
  ['GitHub', 'noreply@github.com', 'A new SSH key was added', 'thread-f:11', '11:02 AM'],
  ['PayPal Service', 'billing@paypa1-support.xyz', 'Your account has been limited - action required', 'thread-f:12', '9:14 AM'],
  ['Priya (Finance)', 'priya@acme-corp.com', 'Q3 budget review notes', 'thread-f:13', '8:40 AM'],
  ['Microsoft account team', 'no-reply@micros0ft-security.com', 'Unusual sign-in activity', 'thread-f:14', 'Yesterday'],
  ['Amazon Support', 'amazon.support.desk@gmail.com', 'Refund pending: confirm your card', 'thread-f:15', 'Nov 23'],
  ['Google', 'no-reply@accounts.google.com', 'Security alert for your account', 'thread-f:16', 'Nov 22'],
];
const inbox = `<!doctype html><html><head><meta charset="utf-8">${GLOBALS}${style}</head><body>
${shell(`<div class="tools"><div class="ic" style="color:#c4c7c5">☐</div><div class="ic">↻</div><div class="ic">⋮</div></div><table>${rows
  .map(([n, e, s, t, d]) => `<tr class="zA"><td class="cb">☐ &nbsp;☆</td><td class="s"><div class="yW"><span email="${e}" name="${n}">${n}</span></div></td><td class="m"><div class="xT"><span class="bog"><b data-thread-id="#${t}">${s}</b></span><span class="y2">&nbsp;- Please review the details in this message</span></div></td><td class="t">${d}</td></tr>`)
  .join('')}</table>`)}</body></html>`;

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
  await page.screenshot({ path: imagePath(out, name), clip });
  console.log('wrote', name);
};

// In Gmail: banner, link warning, reply warning.
const g = await ctx.newPage();
await g.setViewportSize({ width: 1280, height: 760 });
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
await i.setViewportSize({ width: 1280, height: 440 });
await i.goto('https://mail.google.com/mail/u/0/inbox-demo', { waitUntil: 'domcontentloaded' });
await i.waitForSelector('[data-unmask-badge]', { timeout: 15000 });
await i.waitForTimeout(300);
await shot(i, 'inbox-badges.png');
// Peek at the PayPal row without opening it.
await i.setViewportSize({ width: 1280, height: 800 });
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
await qrCard.screenshot({ path: imagePath(out, 'panel-qr.png') });
console.log('wrote panel-qr.png');
// Where the tracking pixel is: Privacy tab entry, then its tag in the safe view.
await p.evaluate(() => window.scrollTo(0, 0));
await p.getByRole('tab', { name: /Privacy/ }).click();
const pixelCard = p.locator('#unmask-pixel-1');
await pixelCard.scrollIntoViewIfNeeded();
await p.waitForTimeout(300);
await pixelCard.screenshot({ path: imagePath(out, 'panel-pixel-where.png') });
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
await listCard.screenshot({ path: imagePath(out, 'settings-protection-list.png') });
console.log('wrote settings-protection-list.png');

// ---- Analyst views on corpus samples ---------------------------------------------
const corpus = (name) => readFileSync(join(here, '..', 'tests', 'fixtures', 'corpus', name));
const openSample = async (name) => {
  await p.goto(`chrome-extension://${extId}/sidepanel.html`);
  await p.setInputFiles('input[type=file]', { name: 'sample.eml', mimeType: 'message/rfc822', buffer: corpus(name) });
  await p.waitForSelector('[aria-label="Assessment"]', { timeout: 15000 });
  await p.waitForTimeout(400);
};
const element = async (locator, name) => {
  await locator.scrollIntoViewIfNeeded();
  await p.waitForTimeout(200);
  await locator.screenshot({ path: imagePath(out, name) });
  console.log('wrote', name);
};
// A replayed genuine Google alert: what it looks like, and the header forensics.
await openSample('phish/dkim-replay-google-alert.eml');
await shot(p, 'panel-replay-summary.png');
await element(p.locator('[aria-label="Assessment"]'), 'panel-assessment.png');
await p.getByRole('tab', { name: /Headers/ }).click();
await p.waitForTimeout(300);
await shot(p, 'panel-forensics-headers.png');
// A mailing-list post: the ARC record and a trusted internal hop.
await openSample('ham/mailing-list-arc.eml');
await p.getByRole('tab', { name: /Headers/ }).click();
await p.waitForTimeout(300);
await element(p.locator('[aria-label="ARC chain"]'), 'panel-arc.png');
// HTML-entity obfuscation and invisible characters.
await openSample('phish/entity-obfuscated-m365.eml');
await element(p.locator('ul').filter({ hasText: 'character codes' }).first(), 'panel-obfuscation.png');
// Report or export with the analyst write-up.
await openSample('phish/docusign-lookalike-prefilled.eml');
await element(p.locator('[aria-label="Report or export"]'), 'panel-report-analyst.png');

// A private sandbox scan of the DocuSign link. urlscan.io is a local test double, like Gmail above,
// and the "landing page" is a demo phishing page rendered here, so no real site is contacted.
const landing = await ctx.newPage();
await landing.setViewportSize({ width: 1280, height: 800 });
await landing.setContent(`<body style="margin:0;font-family:Arial;background:#f4f4f4"><div style="background:#1e1e1e;color:#fff;padding:18px 32px;font-size:22px;font-weight:bold">Docu<span style="color:#ffcc22">Sign</span></div>
<div style="max-width:420px;margin:80px auto;background:#fff;padding:32px;border-radius:6px;box-shadow:0 2px 8px #0002"><h2 style="margin-top:0">Sign in to review your document</h2>
<p style="color:#555">Q4 Compensation Adjustment.pdf</p><input value="alex.morgan@example.org" style="width:100%;padding:10px;margin:8px 0;box-sizing:border-box"><input type="password" placeholder="Password" style="width:100%;padding:10px;margin:8px 0;box-sizing:border-box">
<button style="width:100%;padding:12px;background:#ffcc22;border:0;font-weight:bold;margin-top:8px">REVIEW DOCUMENT</button></div></body>`);
const landingPng = await landing.screenshot();
await landing.close();
await ctx.route('https://urlscan.io/**', (route) => {
  const url = route.request().url();
  if (url.endsWith('/api/v1/scan/')) return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ uuid: 'demo-scan' }) });
  if (url.includes('/api/v1/result/')) return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ page: { url: 'https://review-docs-7731.pages.dev/sign', domain: 'review-docs-7731.pages.dev', ip: '198.51.100.9', country: 'US', title: 'DocuSign - Sign in' }, verdicts: { overall: { malicious: true, score: 100, brands: [{ name: 'DocuSign' }] } } }) });
  if (url.includes('/screenshots/')) return route.fulfill({ status: 200, contentType: 'image/png', body: landingPng });
  return route.fulfill({ status: 200, body: '{}' });
});
await sw.evaluate(() => chrome.storage.local.get('unmask:settings').then((r) => chrome.storage.local.set({ 'unmask:settings': { ...r['unmask:settings'], urlscanApiKey: 'demo-key-00000000-0000-0000-0000-000000000000' } })));
await openSample('phish/docusign-lookalike-prefilled.eml');
await p.getByRole('tab', { name: /Links/ }).click();
const linkCard = p.locator('[id^="unmask-link-"]').first();
await linkCard.getByRole('button', { name: /Sandbox scan/ }).click();
await linkCard.locator('text=Save screenshot').waitFor({ timeout: 40000 });
await p.waitForTimeout(300);
await element(linkCard, 'panel-landing-page.png');

// ---- Documents tab, hash-only lookups, shared Google files and the investigation report ----------
// Every service below is a local test double, so nothing leaves this computer and no key is real.
const GDOC = '1AbCdEfGhIjKlMnOpQrStUvWxYz0123456789';
const sharedDoc = zipStore([
  ['[Content_Types].xml', Buffer.from('<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')],
  ['word/document.xml', Buffer.from('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:r><w:t>Shared secure document. Click below to view your payment details.</w:t></w:r></w:p><w:p><w:hyperlink r:id="rId5"><w:r><w:t>View document</w:t></w:r></w:hyperlink></w:p></w:body></w:document>')],
  ['word/_rels/document.xml.rels', Buffer.from('<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://paypa1-secure.top/login?doc=gd-8841" TargetMode="External"/></Relationships>')],
]);
const filesHtml = `<div style="font-family:Arial,sans-serif;max-width:560px"><p>Dear customer,</p><p>Your invoice 84213 is overdue. Open the attached files and review the shared document: <a href="https://docs.google.com/document/d/${GDOC}/edit?usp=sharing">Payment details</a></p></div>`;
const filesEml = [
  'Delivered-To: you@example.com',
  'Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=invoice-portal.example; dkim=none; dmarc=fail header.from=invoice-portal.example',
  'From: "Accounts Receivable" <billing@invoice-portal.example>',
  'To: you@example.com',
  'Subject: Invoice 84213 - payment overdue',
  'Date: Tue, 20 Oct 2026 08:00:00 +0000',
  'Message-ID: <files-demo-1@invoice-portal.example>',
  'MIME-Version: 1.0',
  'Content-Type: multipart/mixed; boundary="b2"',
  '',
  '--b2',
  'Content-Type: text/html; charset=utf-8',
  'Content-Transfer-Encoding: base64',
  '',
  b64(filesHtml),
  '--b2',
  'Content-Type: application/pdf; name="Invoice_84213.pdf"',
  'Content-Disposition: attachment; filename="Invoice_84213.pdf"',
  'Content-Transfer-Encoding: base64',
  '',
  b64(demoPdf()),
  '--b2',
  'Content-Type: application/vnd.ms-word.document.macroEnabled.12; name="Payment_Form.docm"',
  'Content-Disposition: attachment; filename="Payment_Form.docm"',
  'Content-Transfer-Encoding: base64',
  '',
  b64(demoDocm()),
  '--b2--',
  '',
].join('\r\n');

await ctx.route('https://docs.google.com/**', (route) => route.fulfill({ status: 200, contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', body: sharedDoc }));
await ctx.route('https://www.hybrid-analysis.com/**', (route) => route.fulfill({ status: 404, contentType: 'application/json', body: '{}' }));
await ctx.route('https://mb-api.abuse.ch/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ query_status: 'hash_not_found' }) }));
await ctx.route('https://urlhaus-api.abuse.ch/**', (route) => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ query_status: 'no_results' }) }));
await ctx.route('https://checkurl.phishtank.com/**', (route) => {
  const hit = /paypa1/.test(Buffer.from(new URLSearchParams(route.request().postData() ?? '').get('url') ?? '', 'base64').toString());
  return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ meta: { status: 'success' }, results: hit ? { in_database: true, phish_id: 8841, phish_detail_url: 'https://phishtank.org/phish_detail.php?phish_id=8841', verified: true, valid: true, verified_at: '2026-10-19T10:00:00+00:00' } : { in_database: false } }) });
});
await sw.evaluate(() => chrome.storage.local.get('unmask:settings').then((r) => chrome.storage.local.set({ 'unmask:settings': { ...r['unmask:settings'], hybridApiKey: 'h'.repeat(40), abuseChKey: 'a'.repeat(32), simpleMode: false } })));
await p.goto(`chrome-extension://${extId}/sidepanel.html`);
await p.setInputFiles('input[type=file]', { name: 'invoice.eml', mimeType: 'message/rfc822', buffer: Buffer.from(filesEml) });
await p.waitForSelector('text=High risk', { timeout: 15000 });
await p.getByRole('tab', { name: /Documents/ }).click();
await p.waitForSelector('[id^="unmask-doc-"]', { timeout: 15000 });
await p.waitForTimeout(400);
await shot(p, 'panel-documents.png');
// Tall element screenshots would show the sticky header halfway down: let it scroll away instead.
await p.evaluate(() => document.querySelectorAll('*').forEach((el) => { if (getComputedStyle(el).position === 'sticky') el.style.position = 'static'; }));
const pdfCard = p.locator('[id^="unmask-doc-"]', { hasText: 'Invoice_84213.pdf' });
await pdfCard.locator('details', { hasText: 'PDF structure' }).evaluate((d) => (d.open = true));
await element(pdfCard, 'panel-documents-pdf.png');
const docmCard = p.locator('[id^="unmask-doc-"]', { hasText: 'Payment_Form.docm' });
await element(docmCard, 'panel-documents-macros.png');
// Fingerprint lookups (simulated answers: no record found).
await pdfCard.getByRole('button', { name: /Hybrid Analysis/ }).click();
await pdfCard.getByRole('button', { name: /MalwareBazaar/ }).click();
await pdfCard.locator('text=never analyzed').waitFor({ timeout: 15000 });
await pdfCard.locator('text=no record').first().waitFor({ timeout: 15000 });
await element(pdfCard.locator('text=Look this file up by its fingerprint').locator('..'), 'panel-documents-lookups.png');
// Links found inside the file, checked against PhishTank (simulated: the demo domain is listed).
await pdfCard.getByRole('button', { name: /Check phishing lists/ }).click();
await pdfCard.locator('text=community-verified').first().waitFor({ timeout: 20000 });
await element(pdfCard.locator('details', { hasText: 'Links found inside this file' }), 'panel-documents-links.png');
// A shared Google Doc, read anonymously.
const gdocs = p.locator('text=Google files linked in this email').locator('..');
await gdocs.getByRole('button', { name: /Look inside/ }).click();
await gdocs.locator('text=Shared secure document').first().waitFor({ timeout: 20000 }).catch(() => {});
await p.waitForTimeout(400);
await element(gdocs, 'panel-documents-google.png');

// The investigation report: choose who it is for, then build it in each format.
await p.getByRole('tab', { name: /Summary/ }).click();
await p.locator('text=Report or export').scrollIntoViewIfNeeded();
await p.locator('summary', { hasText: 'Case details' }).click();
await p.getByLabel('Prepared by').fill('A. Analyst');
await p.getByLabel('Organisation').fill('Example Corp SOC');
await p.waitForTimeout(200);
await element(p.locator('[aria-label="Report or export"]'), 'panel-report-formats.png');
const download = async (name) => {
  const [dl] = await Promise.all([p.waitForEvent('download', { timeout: 20000 }), p.getByRole('button', { name }).click()]);
  const path = join(tmpdir(), `unmask-shot-${Date.now()}-${dl.suggestedFilename()}`);
  await dl.saveAs(path);
  return path;
};
const htmlPath = await download(/^HTML/);
const rp = await ctx.newPage();
await rp.setViewportSize({ width: 1000, height: 1250 });
await rp.goto(`file://${htmlPath}`);
await rp.waitForSelector('#summary');
await shot(rp, 'report-executive.png');
await rp.locator('#attachments').scrollIntoViewIfNeeded();
await rp.waitForTimeout(200);
await shot(rp, 'report-technical.png');
await rp.close();
const pdfPath = await download(/^PDF/);
try {
  const reports = dirname(imagePath(out, 'report-pdf-cover.png'));
  execFileSync('pdftoppm', ['-r', '80', '-png', '-f', '1', '-l', '1', pdfPath, join(reports, 'report-pdf-cover')]);
  execFileSync('pdftoppm', ['-r', '80', '-png', '-f', '4', '-l', '4', pdfPath, join(reports, 'report-pdf-summary')]);
  const { renameSync, readdirSync } = await import('node:fs');
  for (const f of readdirSync(reports).filter((n) => /^report-pdf-(cover|summary)-\d+\.png$/.test(n))) renameSync(join(reports, f), join(reports, f.replace(/-\d+\.png$/, '.png')));
  console.log('wrote report-pdf-cover.png, report-pdf-summary.png');
} catch {
  console.log('pdftoppm not available: skipped the PDF page images');
}

// Simple mode: plain words only.
await sw.evaluate(() => chrome.storage.local.get('unmask:settings').then((r) => chrome.storage.local.set({ 'unmask:settings': { ...r['unmask:settings'], simpleMode: true } })));
await p.reload();
await p.setInputFiles('input[type=file]', { name: 'demo.eml', mimeType: 'message/rfc822', buffer: Buffer.from(eml) });
await p.waitForSelector('text=In plain words', { timeout: 15000 });
await p.waitForTimeout(400);
await shot(p, 'panel-simple.png');

await ctx.close();
