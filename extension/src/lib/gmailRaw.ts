/**
 * Pure helpers for downloading an email's raw source from Gmail's own
 * "Show original" / "Download original" endpoints. Pure string functions, so
 * they work under Gmail's Trusted Types policy and can be unit-tested.
 */
import type { GmailMessageRef } from './messages';

export interface Candidate {
  /** Short label used in diagnostics. */
  label: string;
  url: string;
  kind: 'original-page' | 'download';
}

export interface Attempt {
  label: string;
  outcome: string;
}

/** "msg-f:1780954093844218223" → "18b7c4a2e5f1d06f" (the hex id Gmail's older URLs use). */
export function permIdToLegacy(permId: string | null): string | null {
  const dec = permId?.match(/^msg-[af]:(\d+)$/)?.[1];
  if (!dec) return null;
  try {
    return BigInt(dec).toString(16);
  } catch {
    return null;
  }
}

/**
 * Finds Gmail's per-session "ik" token in page HTML. Gmail puts it in the
 * GLOBALS array and in many internal URLs (?ik=0123456789).
 */
export function findIkInHtml(html: string): string | null {
  // Current Gmail: `var GM_ID_KEY = '0123456789';` and `"/mail/u/0",50,"0123456789"` in its boot data.
  const gmIdKey = html.match(/GM_ID_KEY\s*=\s*['"]([0-9a-f]{8,12})['"]/i)?.[1];
  if (gmIdKey) return gmIdKey;
  const boot = html.match(/"\/mail\/u\/\d+",\d+,"([0-9a-f]{8,12})"/i)?.[1];
  if (boot) return boot;
  const fromUrl = html.match(/[?&;]ik=([0-9a-f]{8,12})\b/i)?.[1];
  if (fromUrl) return fromUrl;
  const globals = html.match(/GLOBALS\s*=\s*\[([\s\S]{0,4000}?)\]\s*;/)?.[1];
  if (globals) {
    // GLOBALS[9] is the ik: a short hex string among the first dozen entries.
    const parts = globals.split(',').slice(0, 20);
    const hit = parts[9]?.trim().match(/^"([0-9a-f]{8,12})"$/i)?.[1];
    if (hit) return hit;
    const any = parts.map((p) => p.trim().match(/^"([0-9a-f]{10})"$/i)?.[1]).find(Boolean);
    if (any) return any;
  }
  return null;
}

/** Every URL shape Gmail has used for the original message, most reliable first. */
export function candidateUrls(origin: string, accountIndex: string, msg: GmailMessageRef, ik: string | null): Candidate[] {
  const base = `${origin}/mail/u/${accountIndex}/`;
  const legacy = msg.legacyId ?? permIdToLegacy(msg.permId);
  const ikParam = ik ? `ik=${encodeURIComponent(ik)}&` : '';
  const list: Candidate[] = [];
  const add = (label: string, url: string, kind: Candidate['kind']) => {
    if (!list.some((c) => c.url === url)) list.push({ label, url, kind });
  };

  if (legacy) add('download (th)', `${base}?ui=2&${ikParam}view=att&th=${legacy}&attid=0&disp=comp&safe=1&zw`, 'download');
  if (msg.permId) add('show original (permmsgid)', `${base}?${ikParam}view=om&permmsgid=${encodeURIComponent(msg.permId)}`, 'original-page');
  if (legacy) add('show original (th)', `${base}?ui=2&${ikParam}view=om&th=${legacy}`, 'original-page');
  if (ik) {
    // Same shapes without the token, in case it was read wrongly.
    if (legacy) add('download (th, no ik)', `${base}?ui=2&view=att&th=${legacy}&attid=0&disp=comp&safe=1&zw`, 'download');
    if (msg.permId) add('show original (no ik)', `${base}?view=om&permmsgid=${encodeURIComponent(msg.permId)}`, 'original-page');
  }
  return list;
}

/** Heuristic: does this text start like an RFC 5322 message? */
export function looksLikeRawEmail(text: string): boolean {
  const head = text.replace(/^﻿/, '').slice(0, 6000);
  if (/^\s*<(!doctype|html)/i.test(head)) return false;
  const headerLines = head.split(/\r?\n/).slice(0, 40).filter((l) => /^[A-Za-z][\w-]*:\s/.test(l));
  return headerLines.length >= 3 && /^(received|from|message-id|date|delivered-to|mime-version|return-path|subject|to|arc-[\w-]+|x-[\w-]+):/im.test(head);
}

export interface OriginalPage {
  raw: string | null;
  /** "Download original" link found on the page, if any (absolute URL). */
  downloadUrl: string | null;
}

/** Decodes the HTML entities Gmail uses when it prints the raw message inside a <pre>. */
export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|lt|gt|amp|quot|apos|#39|nbsp);/gi, (m, e: string) => {
    const k = e.toLowerCase();
    if (k.startsWith('#x')) return String.fromCodePoint(parseInt(k.slice(2), 16));
    if (k.startsWith('#')) return String.fromCodePoint(parseInt(k.slice(1), 10));
    return ({ lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: '\u00a0' } as Record<string, string>)[k] ?? m;
  });
}

/**
 * Extracts the raw message (and the download link) from Gmail's "Show original"
 * HTML. Uses string parsing, not DOMParser: Gmail enforces Trusted Types, and
 * DOMParser.parseFromString throws "requires 'TrustedHTML' assignment" there,
 * including in extension content scripts.
 */
export function parseOriginalPage(html: string, pageUrl: string): OriginalPage {
  const lower = html.toLowerCase();
  let downloadUrl: string | null = null;
  // Linear tag scanning (no open-ended regexes over the whole page, which can be quadratic).
  for (let i = lower.indexOf('<a'); i >= 0; i = lower.indexOf('<a', i + 2)) {
    const end = lower.indexOf('>', i);
    const tag = html.slice(i, Math.min(end < 0 ? html.length : end + 1, i + 4096));
    const href = tag.match(/\bhref\s*=\s*(?:"([^"]{0,4000})"|'([^']{0,4000})')/i);
    const value = decodeEntities(href?.[1] ?? href?.[2] ?? '');
    if (/disp=comp|view=att/.test(value)) {
      try {
        downloadUrl = new URL(value, pageUrl).href;
      } catch {
        downloadUrl = null;
      }
      break;
    }
  }
  const pres: string[] = [];
  for (let i = lower.indexOf('<pre'); i >= 0; ) {
    const open = lower.indexOf('>', i);
    if (open < 0) break;
    const close = lower.indexOf('</pre>', open);
    const body = html.slice(open + 1, close < 0 ? html.length : close);
    if (/\bid\s*=\s*["']?raw_message_text/i.test(html.slice(i, open))) pres.unshift(body);
    else pres.push(body);
    if (close < 0) break;
    i = lower.indexOf('<pre', close);
  }
  const raw =
    pres
      .map((p) => decodeEntities(stripTags(p)))
      .sort((a, b) => b.length - a.length)
      .find(looksLikeRawEmail) ?? null;
  return { raw, downloadUrl };
}

/** Removes tags in one pass (linear, unlike /<[^>]+>/g on unterminated input). */
function stripTags(s: string): string {
  let out = '';
  let inTag = false;
  for (const ch of s) {
    if (ch === '<') inTag = true;
    else if (ch === '>' && inTag) inTag = false;
    else if (!inTag) out += ch;
  }
  return out;
}

export function describeResponse(status: number, finalUrl: string, contentType: string, body: string): string {
  let host = '';
  try {
    const u = new URL(finalUrl);
    host = `${u.host}${u.pathname.length > 1 ? u.pathname.slice(0, 30) : ''}`;
  } catch {
    host = finalUrl.slice(0, 40);
  }
  const title = body.match(/<title>([^<]{0,80})/i)?.[1]?.trim();
  return `HTTP ${status} from ${host} (${contentType.split(';')[0] || 'no type'}, ${body.length} bytes${title ? `, title "${title}"` : ''})`;
}
