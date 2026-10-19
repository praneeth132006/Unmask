// Builds src/analyzers/logoHashes.json: perceptual fingerprints of the brand
// logos Unmask watches for, rendered from simple-icons (CC0) with resvg.
// Each brand gets a dark-on-white and a white-on-brand-colour rendering.
//
//   node scripts/gen-logo-hashes.mjs
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Resvg } from '@resvg/resvg-js';
import * as si from 'simple-icons';
import { dHash } from '../src/lib/dhash.ts';

const here = dirname(fileURLToPath(import.meta.url));

/** Brand name (as in brands.ts) → simple-icons slugs. */
const BRANDS = {
  PayPal: ['paypal'],
  Apple: ['apple'],
  Google: ['google', 'gmail'],
  Netflix: ['netflix'],
  'Meta / Facebook': ['facebook', 'meta'],
  Instagram: ['instagram'],
  WhatsApp: ['whatsapp'],
  'X / Twitter': ['x'],
  GitHub: ['github'],
  DHL: ['dhl'],
  FedEx: ['fedex'],
  UPS: ['ups'],
  USPS: ['usps'],
  Chase: ['chase'],
  'Bank of America': ['bankofamerica'],
  'Wells Fargo': ['wellsfargo'],
  HSBC: ['hsbc'],
  Coinbase: ['coinbase'],
  Binance: ['binance'],
  Dropbox: ['dropbox'],
  Steam: ['steam'],
  Spotify: ['spotify'],
  eBay: ['ebay'],
  Walmart: ['walmart'],
  Zoom: ['zoom'],
  Slack: ['slack'],
  Okta: ['okta'],
  Norton: ['norton'],
  McAfee: ['mcafee'],
  Venmo: ['venmo'],
  'Cash App': ['cashapp'],
  Revolut: ['revolut'],
  Wise: ['wise'],
  Paytm: ['paytm'],
  PhonePe: ['phonepe'],
  Flipkart: ['flipkart'],
  Airtel: ['airtel'],
  Jio: ['jio'],
  'ICICI Bank': ['icicibank'],
  'HDFC Bank': ['hdfcbank'],
  'Axis Bank': ['axisbank'],
};

// simple-icons does not ship Microsoft's mark; its four squares are drawn here.
const EXTRA = {
  Microsoft: [
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 23 23"><path fill="#f25022" d="M1 1h10v10H1z"/><path fill="#7fba00" d="M12 1h10v10H12z"/><path fill="#00a4ef" d="M1 12h10v10H1z"/><path fill="#ffb900" d="M12 12h10v10H12z"/></svg>',
  ],
};

function render(svg, size = 96) {
  const img = new Resvg(svg, { fitTo: { mode: 'width', value: size }, background: 'white' }).render();
  return { data: img.pixels, width: img.width, height: img.height };
}

const iconKey = (slug) => `si${slug.charAt(0).toUpperCase()}${slug.slice(1)}`;
const out = {};
for (const [brand, slugs] of Object.entries(BRANDS)) {
  const hashes = new Set();
  for (const slug of slugs) {
    const icon = si[iconKey(slug)];
    if (!icon) throw new Error(`simple-icons has no ${slug}`);
    const glyph = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-2 -2 28 28"><path fill="#${icon.hex}" d="${icon.path}"/></svg>`;
    const tile = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-4 -4 32 32"><rect x="-4" y="-4" width="32" height="32" rx="6" fill="#${icon.hex}"/><path fill="#fff" d="${icon.path}"/></svg>`;
    for (const svg of [glyph, tile]) {
      const h = dHash(render(svg));
      if (h) hashes.add(h);
    }
  }
  out[brand] = [...hashes];
}
for (const [brand, svgs] of Object.entries(EXTRA)) out[brand] = svgs.map((s) => dHash(render(s))).filter(Boolean);

writeFileSync(join(here, '..', 'src', 'analyzers', 'logoHashes.json'), `${JSON.stringify(out, null, 0).replace(/\],/g, '],\n')}\n`);
console.log(`logo fingerprints for ${Object.keys(out).length} brands written`);
