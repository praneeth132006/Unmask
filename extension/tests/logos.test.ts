import { Resvg } from '@resvg/resvg-js';
import * as si from 'simple-icons';
import { findBrandLogos, logoFindings, matchLogo } from '../src/analyzers/logos';
import type { ImageDecoder } from '../src/analyzers/qr';
import { parseEmail } from '../src/core/parse';
import { dHash, hamming } from '../src/lib/dhash';

/** Renders an icon at a size and padding different from the fingerprint table, like a real email logo. */
function logo(icon: { hex: string; path: string }, size = 180) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-8 -4 40 32"><path fill="#${icon.hex}" d="${icon.path}"/></svg>`;
  const img = new Resvg(svg, { fitTo: { mode: 'width', value: size }, background: 'white' }).render();
  return { data: img.pixels, width: img.width, height: img.height };
}

function html(from: string, body: string, subject = 'Notice'): string {
  return [`From: ${from}`, `Subject: ${subject}`, 'MIME-Version: 1.0', 'Content-Type: text/html; charset=utf-8', '', body].join('\r\n');
}

describe('fake brand logos', () => {
  it('fingerprints the same logo alike at different sizes', () => {
    const a = dHash(logo(si.siPaypal, 90))!;
    const b = dHash(logo(si.siPaypal, 400))!;
    expect(hamming(a, b)).toBeLessThanOrEqual(5);
  });

  it('recognises brand logos by their pixels', () => {
    expect(matchLogo(dHash(logo(si.siPaypal))!)?.name).toBe('PayPal');
    expect(matchLogo(dHash(logo(si.siNetflix))!)?.name).toBe('Netflix');
    expect(matchLogo(dHash(logo(si.siDhl))!)?.name).toBe('DHL');
  });

  it('does not match a logo it does not know', () => {
    expect(matchLogo(dHash(logo(si.siVite))!)).toBeNull();
  });

  it('flags an embedded PayPal logo in mail not from PayPal', async () => {
    const px = logo(si.siPaypal);
    const decode: ImageDecoder = async () => ({ data: new Uint8ClampedArray(px.data), width: px.width, height: px.height });
    const email = await parseEmail(html('Account Team <alerts@secure-mailer.top>', '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"><p>Verify now</p>'));
    const hits = await findBrandLogos(email, decode);
    expect(hits).toEqual([expect.objectContaining({ how: 'fingerprint' })]);
    expect(logoFindings(email, hits)[0]).toMatchObject({ severity: 'high', title: "Shows the PayPal logo, but PayPal didn't send it" });
  });

  it('notices logos hot-linked from the brand or named in alt text', async () => {
    const email = await parseEmail(html('PayPal Service <service@pp-support.xyz>', '<img src="https://www.paypalobjects.com/webstatic/logo.png"><img alt="Netflix" src="https://cdn.x.top/a.png">'));
    const hits = await findBrandLogos(email);
    expect(hits.map((h) => `${h.brand.name}:${h.how}`)).toEqual(['PayPal:asset-host', 'Netflix:label']);
    const f = logoFindings(email, hits);
    expect(f.find((x) => x.id === 'fake-logo-paypal')?.severity).toBe('high'); // display name also claims PayPal
    expect(f.find((x) => x.id === 'fake-logo-netflix')?.severity).toBe('medium');
  });

  it('ignores social icons and badges that link to the brand, and mail from the brand itself', async () => {
    const shop = await parseEmail(html('Shop <news@shop.com>', '<a href="https://facebook.com/shop"><img alt="Facebook" src="https://shop.com/fb.png"></a><a href="https://apps.apple.com/x"><img alt="Download on the App Store" src="x.png"></a>'));
    expect(await findBrandLogos(shop)).toEqual([]);
    const real = await parseEmail(html('PayPal <service@paypal.com>', '<img src="https://www.paypalobjects.com/logo.png">'));
    expect(logoFindings(real, await findBrandLogos(real))).toEqual([]);
  });
});
