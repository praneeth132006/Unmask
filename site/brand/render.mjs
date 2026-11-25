// Renders the social preview images from site/brand/social.html:
//   GitHub (1280x640): docs/brand/social-preview.png — upload in the repo's Settings → Social preview.
//   Website (1200x630): site/media/og.png
// Run from the repo root: node site/brand/render.mjs
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
const { chromium } = createRequire(resolve('extension/package.json'))('playwright');
const page = `file://${resolve('site/brand/social.html')}`;
const b = await chromium.launch();
for (const [w, h, out] of [[1280, 640, 'docs/brand/social-preview.png'], [1200, 630, 'site/media/og.png']]) {
  const p = await b.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 1 });
  await p.goto(page);
  await p.addStyleTag({ content: `body{--w:${w}px;--h:${h}px}` });
  await p.waitForTimeout(300);
  await p.screenshot({ path: out });
  console.log('wrote', out);
}
await b.close();
