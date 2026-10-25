/**
 * Encoding tricks in the email's HTML source. Your mail app decodes them and
 * shows normal text; keyword and link filters reading the source see
 * something else. Legitimate email builders encode punctuation (&#39; &#8217;
 * &nbsp;), never ordinary letters, link hosts, or words split by invisible
 * characters.
 */
import type { Finding } from '../core/types';
import { brandsMentionedIn } from './brands';
import { mixedScriptWords, skeleton } from './lookalike';

/** Numeric character references (&#112; &#x70;) and the character each stands for. */
const NUMERIC_REF = /&#(x[0-9a-f]+|\d+);?/gi;

function decodeRef(ref: string): string {
  const body = ref.replace(/^&#|;$/g, '');
  const code = body[0] === 'x' || body[0] === 'X' ? parseInt(body.slice(1), 16) : parseInt(body, 10);
  try {
    return Number.isFinite(code) ? String.fromCodePoint(code) : '';
  } catch {
    return '';
  }
}

/** Words containing three or more letters written as character codes, decoded: "&#112;&#97;&#121;pal" → "paypal". */
export function encodedWords(html: string): string[] {
  const words: string[] = [];
  // Text between tags only: attribute values are checked separately.
  const units: { ch: string; coded: boolean }[] = [];
  const textOnly = html.replace(/<[^>]*>/g, ' ');
  for (let i = 0; i < textOnly.length; ) {
    const m = /^&#(x[0-9a-f]+|\d+);?/i.exec(textOnly.slice(i, i + 12));
    if (m) {
      units.push({ ch: decodeRef(m[0]), coded: true });
      i += m[0].length;
    } else units.push({ ch: textOnly[i++]!, coded: false });
  }
  let word = '';
  let coded = 0;
  for (const u of [...units, { ch: ' ', coded: false }]) {
    if (/^[a-z0-9@.]$/i.test(u.ch)) {
      word += u.ch;
      if (u.coded) coded++;
    } else {
      if (coded >= 3 && word.replace(/[.@]/g, '').length >= 3) words.push(word.replace(/^\.+|\.+$/g, ''));
      word = '';
      coded = 0;
    }
  }
  return [...new Set(words)];
}

/** Link addresses written with character codes or with %-encoded letters in the host name. */
export function disguisedHrefs(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/\bhref\s*=\s*(["'])(.*?)\1/gis)) {
    const raw = m[2]!;
    const decoded = raw.replace(NUMERIC_REF, (r) => decodeRef(r));
    const codedLetters = [...raw.matchAll(NUMERIC_REF)].filter((r) => /^[a-z0-9.:/]$/i.test(decodeRef(r[0]))).length;
    const host = decoded.match(/^\s*[a-z][a-z0-9+.-]*:\/\/([^/?#\s]+)/i)?.[1] ?? '';
    const percentHost = /%[0-9a-f]{2}/i.test(host);
    if (codedLetters >= 3 || percentHost) {
      let shown = decoded;
      try {
        shown = decodeURIComponent(decoded);
      } catch {
        /* keep */
      }
      out.push(shown.trim());
    }
  }
  return [...new Set(out)];
}

/** Soft hyphens and zero-width characters inside words: invisible, but they split keywords for filters. */
const SPLITTERS = /[\p{L}\p{N}][\u00ad\u200b\u200c\u200d\u2060\ufeff]+[\p{L}\p{N}]/gu;

export function obfuscationFindings(html: string | null, visibleText: string): Finding[] {
  const findings: Finding[] = [];
  if (html) {
    const words = encodedWords(html);
    if (words.length) {
      const brands = brandsMentionedIn(words.join(' '));
      const strong = brands.length > 0 || words.some((w) => w.includes('@') || /\.[a-z]{2,}$/i.test(w));
      findings.push({
        id: 'entity-encoded-text',
        category: 'content',
        severity: strong ? 'high' : 'medium',
        points: strong ? 18 : 10,
        title: brands.length ? `"${brands[0]!.name}" is written in character codes to hide it from filters` : 'Words are written in character codes to hide them from filters',
        detail: `The HTML spells ${words.slice(0, 3).map((w) => `"${w}"`).join(', ')} letter by letter as codes like &#112;. Your mail app shows normal text, but filters reading the source don't see the words. Real email tools only encode punctuation this way.`,
        target: { kind: 'text', phrases: words.slice(0, 5) },
      });
    }
    const hrefs = disguisedHrefs(html);
    if (hrefs.length) {
      findings.push({
        id: 'link-encoded-href',
        category: 'links',
        severity: 'high',
        points: 18,
        title: 'A link address is disguised with character codes',
        detail: `The link really goes to ${hrefs[0]}, but its address is written in codes (&#46; for a dot, %70 for a "p") so filters can't read where it goes.`,
        target: { kind: 'tab', tab: 'links' },
      });
    }
  }

  const split = visibleText.match(SPLITTERS) ?? [];
  if (split.length >= 3) {
    // The words that were split, put back together.
    const splitWords = (visibleText.match(/[\p{L}\p{N}]*(?:[\u00ad\u200b\u200c\u200d\u2060\ufeff]+[\p{L}\p{N}]+)+/gu) ?? []).map((w) => w.replace(/[\u00ad\u200b\u200c\u200d\u2060\ufeff]/g, ''));
    const brand = brandsMentionedIn(splitWords.join(' '))[0];
    findings.push({
      id: 'invisible-splitters',
      category: 'content',
      severity: brand ? 'high' : 'medium',
      points: brand ? 15 : 8,
      title: brand ? `"${brand.name}" is broken up with invisible characters` : 'Words are broken up with invisible characters',
      detail: `${split.length} invisible soft hyphens or zero-width spaces sit inside words. They don't show on screen but stop filters from matching the words, a trick Microsoft calls "text padding".`,
      target: { kind: 'body' },
    });
  }

  const mixed = mixedScriptWords(visibleText);
  if (mixed.length) {
    const brand = brandsMentionedIn(mixed.map(skeleton).join(' '))[0];
    findings.push({
      id: 'mixed-script-text',
      category: 'content',
      severity: brand ? 'high' : 'low',
      points: brand ? 15 : 4,
      title: brand ? `"${brand.name}" is spelt with letters from another alphabet` : 'Some words mix letters from different alphabets',
      detail: `"${mixed[0]}" looks like a normal word but mixes Latin letters with look-alikes (for example a Cyrillic "о" for "o"), so filters searching for the real word miss it.`,
      target: { kind: 'text', phrases: mixed.slice(0, 5) },
    });
  }
  return findings;
}
