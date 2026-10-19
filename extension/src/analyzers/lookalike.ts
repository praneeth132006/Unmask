import { BRANDS, isBrandDomain, type Brand } from './brands';
import { hostInfo } from '../lib/domain';
import { toUnicode } from 'punycode/';

export type LookalikeKind = 'homoglyph' | 'typo' | 'brand-in-domain' | 'brand-in-subdomain';

export interface LookalikeMatch {
  brand: Brand;
  kind: LookalikeKind;
  /** Human-readable explanation, e.g. "uses '1' instead of 'l'". */
  explanation: string;
}

/** Characters that render (nearly) identically to Latin letters. */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', і: 'i', ј: 'j', ԁ: 'd', ɡ: 'g', ӏ: 'l', ѕ: 's', ԛ: 'q', ԝ: 'w', һ: 'h', к: 'k', м: 'm', т: 't', в: 'b', н: 'h',
  // Greek
  α: 'a', ο: 'o', ν: 'v', ρ: 'p', τ: 't', ι: 'i', κ: 'k', ε: 'e', υ: 'u', χ: 'x',
  // Latin look-alikes and digits
  ı: 'i', ł: 'l', ɑ: 'a', ⅼ: 'l', ǀ: 'l', '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't', '8': 'b', '|': 'l',
};

/** Reduce a label to a "skeleton" so visually confusable strings compare equal. */
export function skeleton(input: string): string {
  const stripped = input
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '');
  let out = '';
  for (const ch of stripped) out += CONFUSABLES[ch] ?? ch;
  return out.replace(/rn/g, 'm').replace(/vv/g, 'w');
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0]!;
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j]!;
      prev[j] = Math.min(prev[j]! + 1, prev[j - 1]! + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length]!;
}

function describeSwap(raw: string, keyword: string): string {
  const swaps: string[] = [];
  const chars = Array.from(raw.toLowerCase());
  chars.forEach((ch, i) => {
    const mapped = CONFUSABLES[ch];
    if (mapped && keyword.includes(mapped) && ch !== mapped) {
      const code = ch.codePointAt(0)!;
      const label = /[0-9|]/.test(ch) ? `'${ch}'` : `'${ch}' (U+${code.toString(16).toUpperCase().padStart(4, '0')})`;
      swaps.push(`${label} instead of '${mapped}'`);
    }
    if (ch === 'r' && chars[i + 1] === 'n' && keyword.includes('m')) swaps.push(`'rn' instead of 'm'`);
  });
  return swaps.length ? `uses ${[...new Set(swaps)].join(', ')}` : 'visually identical characters';
}

/**
 * Checks whether a host imitates a known brand. Hosts that belong to the
 * brand itself never match.
 */
export function detectLookalike(host: string, brands: Brand[] = BRANDS): LookalikeMatch | null {
  const info = hostInfo(host);
  if (info.isIp || !info.label) return null;
  if (brands.some((b) => isBrandDomain(b, info.domain))) return null;

  let label = info.label;
  if (label.startsWith('xn--')) {
    try {
      label = toUnicode(label);
    } catch {
      // keep the ascii form
    }
  }
  const labelSkel = skeleton(label);
  const rawPieces = label.toLowerCase().split('-').filter(Boolean);
  const pieces = rawPieces.map(skeleton);
  const subdomainSkel = skeleton(info.host.slice(0, Math.max(0, info.host.length - info.domain.length - 1)));

  for (const brand of brands) {
    for (const kw of brand.keywords) {
      const keyword = kw.replace(/\s+/g, '');
      const kwSkel = skeleton(keyword);

      // Exact after normalisation, but not literally the same → homoglyph / digit swap.
      if (labelSkel === kwSkel && label.toLowerCase() !== keyword) {
        return { brand, kind: 'homoglyph', explanation: describeSwap(label, keyword) };
      }
      const pieceIdx = pieces.indexOf(kwSkel);
      if (pieceIdx >= 0) {
        const rawPiece = rawPieces[pieceIdx]!;
        const swapped = rawPiece !== keyword;
        return {
          brand,
          kind: swapped ? 'homoglyph' : 'brand-in-domain',
          explanation: swapped ? describeSwap(rawPiece, keyword) : `contains "${keyword}" but is not a ${brand.name} domain`,
        };
      }
      // Edit-distance typos only for distinctive names; short words ("chase", "steam") collide with real words.
      if (keyword.length >= 6) {
        const maxDist = keyword.length >= 9 ? 2 : 1;
        const candidates = [labelSkel, ...pieces];
        if (candidates.some((c) => c !== kwSkel && Math.abs(c.length - kwSkel.length) <= maxDist && levenshtein(c, kwSkel) <= maxDist)) {
          return { brand, kind: 'typo', explanation: `one or two letters away from "${keyword}"` };
        }
        if (labelSkel.includes(kwSkel)) {
          return { brand, kind: 'brand-in-domain', explanation: `contains "${keyword}" but is not a ${brand.name} domain` };
        }
      }
      if (keyword.length >= 4 && subdomainSkel.split(/[.-]/).includes(kwSkel)) {
        return { brand, kind: 'brand-in-subdomain', explanation: `puts "${keyword}" in the subdomain of ${info.domain}` };
      }
    }
  }
  return null;
}
