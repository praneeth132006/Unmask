// Renders the Chrome Web Store brand images into docs/store/:
//   store-icon-128.png   128x128 store icon (96px mark with 16px padding, as the store guidelines ask)
//   promo-small-440x280.jpg, promo-marquee-1400x560.jpg   promo tiles (JPEG, so no alpha)
// Run from the repo root: node site/brand/promo.mjs
import { createRequire } from 'node:module';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
const require = createRequire(resolve('extension/package.json'));
const { chromium } = require('playwright');
const { Resvg } = require('@resvg/resvg-js');

// Store icon: the 96px mark centred on a transparent 128px canvas.
const mark = readFileSync('docs/brand/logo.svg', 'utf8').replace(/^[\s\S]*?<svg[^>]*>/, '').replace(/<\/svg>\s*$/, '');
const viewBox = readFileSync('docs/brand/logo.svg', 'utf8').match(/viewBox="([^"]+)"/)[1];
const icon = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128"><svg x="16" y="16" width="96" height="96" viewBox="${viewBox}">${mark}</svg></svg>`;
writeFileSync('docs/store/store-icon-128.png', new Resvg(icon, { fitTo: { mode: 'width', value: 128 } }).render().asPng());
console.log('wrote store-icon-128');

const b = await chromium.launch();
for (const [t, w, h] of [['small', 440, 280], ['marquee', 1400, 560]]) {
  const p = await b.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 1 });
  await p.goto(`file://${resolve('site/brand/promo.html')}?t=${t}`);
  await p.waitForTimeout(350);
  // JPEG has no alpha channel, which is what the store requires for promo tiles.
  await p.screenshot({ path: `docs/store/promo-${t}-${w}x${h}.jpg`, type: 'jpeg', quality: 95 });
  console.log('wrote', t);
}
await b.close();
