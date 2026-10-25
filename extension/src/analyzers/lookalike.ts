import { BRANDS, COMMON_WORD_KEYWORDS, OFFICIAL_CONTEXT, isBrandDomain, type Brand } from './brands';
import { hostInfo } from '../lib/domain';
import { toUnicode } from 'punycode/';
import unicodeConfusables from './confusables.json';

/** Unicode's own list (UTS #39) of characters confusable with an ASCII letter or digit, ~1,600 of them. */
const UNICODE_CONFUSABLES: Record<string, string> = unicodeConfusables.map;

export type LookalikeKind = 'homoglyph' | 'typo' | 'brand-in-domain' | 'brand-in-subdomain';

export interface LookalikeMatch {
  brand: Brand;
  kind: LookalikeKind;
  /** Human-readable explanation, e.g. "uses '1' instead of 'l'". */
  explanation: string;
}

/** Characters that render (nearly) identically to Latin letters, checked before Unicode's list (digits like 1 → l are ours). */
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
  const stripped = input.normalize('NFKD').replace(/[̀-ͯ]/g, '');
  let out = '';
  // Look up before lowercasing too: some look-alikes are listed only as capitals (Cherokee Ꮲ, not ꮲ).
  for (const ch of stripped) {
    const lower = ch.toLowerCase();
    out += CONFUSABLES[lower] ?? UNICODE_CONFUSABLES[ch] ?? UNICODE_CONFUSABLES[lower] ?? lower;
  }
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

/** Real words one or two letters from a brand name: "finance" is not a misspelled Binance. */
const NOT_TYPOS = new Set(['palpal', 'papal', 'parpal', 'acloud', 'cloud', 'goggle', 'googly', 'amazona', 'lessener', 'passenger', 'atwitter', 'titter', 'twister', 'twitten', 'witter', 'finance', 'finances', 'corton', 'morton', 'revolt', 'revolute', 'revolts', 'onliness', 'phoneme', 'artel', 'outbook', 'microstat', 'microvolt']);

/** Suspicious extras around a brand name: "apple-id-verify", "chase-secure". */
function soundsOfficial(host: string): boolean {
  return OFFICIAL_CONTEXT.test(host.replace(/[.-]/g, ' '));
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
      // The brand's own name on another ending (meta.ai, google.co.in, amazon.de) is how
      // big companies run country and product sites, not a phishing trick.
      if (label.toLowerCase() === keyword && brand.domains.some((d) => d.split('.')[0] === keyword)) continue;
      // Everyday words (apple, chase, zoom) spelled correctly need the rest of the host to
      // sound official; misspellings and swapped letters are suspicious on their own.
      const plainWord = COMMON_WORD_KEYWORDS.has(keyword) && !soundsOfficial(info.host);
      const pieceIdx = pieces.indexOf(kwSkel);
      if (pieceIdx >= 0 && !(plainWord && rawPieces[pieceIdx] === keyword)) {
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
        if (candidates.some((c) => c !== kwSkel && !NOT_TYPOS.has(c) && Math.abs(c.length - kwSkel.length) <= maxDist && levenshtein(c, kwSkel) <= maxDist)) {
          return { brand, kind: 'typo', explanation: `one or two letters away from "${keyword}"` };
        }
        if (labelSkel.includes(kwSkel) && !plainWord) {
          return { brand, kind: 'brand-in-domain', explanation: `contains "${keyword}" but is not a ${brand.name} domain` };
        }
      }
      if (keyword.length >= 4 && !plainWord && subdomainSkel.split(/[.-]/).includes(kwSkel)) {
        return { brand, kind: 'brand-in-subdomain', explanation: `puts "${keyword}" in the subdomain of ${info.domain}` };
      }
    }
  }
  return null;
}

/** Zero-width and direction-control characters: invisible, used to break up words filters look for. */
export const INVISIBLE = /[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\u3164\ufeff]/g;

/** Words that mix Latin letters with look-alikes from another alphabet, e.g. "PаyPal" with a Cyrillic а. */
export function mixedScriptWords(text: string): string[] {
  return (text.match(/[\p{L}\p{M}]+/gu) ?? []).filter((w) => /\p{Script=Latin}/u.test(w) && /[\p{Script=Cyrillic}\p{Script=Greek}\p{Script=Armenian}\p{Script=Cherokee}]/u.test(w));
}
