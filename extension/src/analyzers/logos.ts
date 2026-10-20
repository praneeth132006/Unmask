/**
 * Fake brand logos: an email that shows PayPal's logo but was not sent by
 * PayPal. Three independent signals, none of which downloads anything:
 * - the image is loaded from the brand's own asset host (paypalobjects.com)
 * - the image's alt text, title or file name names the brand
 * - an embedded image's perceptual fingerprint matches the brand's logo
 * Logos that link to the brand's own site (social icons, app-store badges)
 * are normal in legitimate email and are ignored.
 */
import type { Finding, ParsedEmail } from '../core/types';
import { BRANDS, brandOwningDomain, brandsMentionedIn, isBrandDomain, type Brand } from './brands';
import type { ImageDecoder } from './qr';
import { unwrapUrl } from './links';
import { detectLookalike } from './lookalike';
import { registrableDomain, safeUrl } from '../lib/domain';
import { dHash, hamming } from '../lib/dhash';
import LOGO_HASHES from './logoHashes.json';

export interface LogoHit {
  brand: Brand;
  how: 'asset-host' | 'label' | 'fingerprint';
  evidence: string;
}

const MATCH_BITS = 8;
const MARGIN_BITS = 6;
const BADGE = /app ?store|google play|get it on|download on|available on/i;

/** The brand whose logo this fingerprint matches, only when one brand is a clear winner. */
export function matchLogo(hash: string, table: Record<string, string[]> = LOGO_HASHES): Brand | null {
  const scored = Object.entries(table)
    .map(([name, hashes]) => ({ name, d: Math.min(...hashes.map((h) => hamming(h, hash))) }))
    .sort((a, b) => a.d - b.d);
  const [best, second] = scored;
  if (!best || best.d > MATCH_BITS || (second && second.d < best.d + MARGIN_BITS)) return null;
  return BRANDS.find((b) => b.name === best.name) ?? null;
}

function words(path: string): string {
  return decodeURIComponent(path.split('/').pop() ?? '').replace(/\.[a-z0-9]{2,5}$/i, '').replace(/[-_.]+/g, ' ');
}

export async function findBrandLogos(email: ParsedEmail, decode?: ImageDecoder): Promise<LogoHit[]> {
  if (!email.html) return [];
  const doc = new DOMParser().parseFromString(email.html, 'text/html');
  const hits: LogoHit[] = [];
  const add = (hit: LogoHit) => {
    if (!hits.some((h) => h.brand === hit.brand && h.how === hit.how)) hits.push(hit);
  };
  const byCid = new Map(email.attachments.filter((a) => a.contentId).map((a) => [a.contentId!.replace(/^<|>$/g, ''), a]));
  let decoded = 0;

  for (const img of Array.from(doc.querySelectorAll('img')).slice(0, 60)) {
    const src = (img.getAttribute('src') ?? '').trim();
    const label = `${img.getAttribute('alt') ?? ''} ${img.getAttribute('title') ?? ''}`.trim();
    if (BADGE.test(label)) continue;
    // A logo that links to the brand itself (footer social icons, "Pay with PayPal" badges) is not an impersonation.
    const linkHref = img.closest('a[href]')?.getAttribute('href') ?? '';
    const linkDomain = registrableDomain(safeUrl(unwrapUrl(linkHref).url)?.hostname ?? '');
    const linksToBrand = (b: Brand) => linkDomain !== '' && isBrandDomain(b, linkDomain);

    const url = /^https?:/i.test(src) ? safeUrl(src) : null;
    if (url) {
      const owner = brandOwningDomain(registrableDomain(url.hostname));
      if (owner && !linksToBrand(owner)) add({ brand: owner, how: 'asset-host', evidence: `image loaded from ${url.hostname}` });
    }
    const named = brandsMentionedIn(`${label} ${url ? words(url.pathname) : ''}`);
    for (const b of named) if (!linksToBrand(b)) add({ brand: b, how: 'label', evidence: label ? `image labelled "${label.slice(0, 60)}"` : `image file "${url ? url.pathname.split('/').pop() : src}"` });

    if (!decode || decoded >= 20) continue;
    let bytes: Uint8Array | null = null;
    let mime = '';
    if (/^cid:/i.test(src)) {
      const att = byCid.get(src.slice(4));
      if (att && att.size < 5_000_000 && /^image\//i.test(att.mimeType)) (bytes = att.content), (mime = att.mimeType);
    } else {
      const m = src.match(/^data:(image\/[a-z+.-]+);base64,([a-z0-9+/=\s]{20,7000000})$/i);
      if (m) {
        try {
          const bin = atob(m[2]!.replace(/\s/g, ''));
          bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
          mime = m[1]!;
        } catch {
          bytes = null;
        }
      }
    }
    if (!bytes) continue;
    decoded++;
    const px = await decode(bytes, mime).catch(() => null);
    const hash = px ? dHash(px) : null;
    const brand = hash ? matchLogo(hash) : null;
    if (brand && !linksToBrand(brand)) add({ brand, how: 'fingerprint', evidence: 'embedded image matches its logo' });
  }
  return hits;
}

/** `pressure`: the email also asks you to log in, verify, pay or act fast. */
export function logoFindings(email: ParsedEmail, hits: LogoHit[], pressure = false): Finding[] {
  const from = email.from;
  if (!from || !hits.length) return [];
  const fromOrg = registrableDomain(from.domain);
  const claimed = new Set(brandsMentionedIn(`${from.name} ${email.subject}`).map((b) => b.name));
  const byBrand = new Map<Brand, LogoHit[]>();
  for (const h of hits) if (!isBrandDomain(h.brand, fromOrg)) byBrand.set(h.brand, [...(byBrand.get(h.brand) ?? []), h]);

  const findings: Finding[] = [];
  const lookalike = detectLookalike(from.domain);
  for (const [brand, list] of byBrand) {
    // A logo only matters when the email presents itself as that brand (sender name, subject,
    // look-alike domain) or uses it to push you to log in or pay. Newsletters about Meta or Google
    // show their logos all the time.
    if (!claimed.has(brand.name) && lookalike?.brand.name !== brand.name && !pressure) continue;
    const strong = list.some((h) => h.how === 'fingerprint') || list.length > 1 || claimed.has(brand.name);
    findings.push({
      id: `fake-logo-${brand.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
      category: 'sender',
      severity: strong ? 'high' : 'medium',
      points: strong ? 20 : 8,
      target: { kind: 'tab', tab: 'body' },
      title: `Shows the ${brand.name} logo, but ${brand.name} didn't send it`,
      detail: `${list.map((h) => h.evidence).join('; ')}. The email is from ${fromOrg}, not ${brand.domains[0]}. Anyone can paste a logo into an email.`,
    });
  }
  return findings;
}
