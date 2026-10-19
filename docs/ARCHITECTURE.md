# How Unmask works

A technical tour for contributors and security reviewers.

- [Overview](#overview)
- [Repository layout](#repository-layout)
- [Reading the message from Gmail](#reading-the-message-from-gmail)
- [The analysis pipeline](#the-analysis-pipeline)
- [The side panel](#the-side-panel)
- [Highlighting in Gmail](#highlighting-in-gmail)
- [Online integrations](#online-integrations)
- [Security model](#security-model)
- [Permissions](#permissions)

---

## Overview

```
┌──────────────── Gmail tab (mail.google.com) ─────────────────┐
│                                                               │
│  gmail-ik.content.ts   (MAIN world)                           │
│     reads GLOBALS[9] → data-unmask-ik attribute               │
│                                                               │
│  gmail.content.ts      (isolated world)                       │
│     • watches the DOM for open messages                       │
│     • downloads the raw message (Download / Show original)    │
│     • outlines elements when asked (lib/highlight.ts)         │
└──────────────┬────────────────────────────▲──────────────────┘
               │ runtime messages           │ tabs.sendMessage
               ▼                            │
┌──────────────────────── Side panel (extension page) ─────────┐
│  useGmail()  →  analyzeRawEmail()  →  Report  →  React UI     │
│                   parse · auth · sender · content ·           │
│                   links · attachments · trackers · score      │
│                                                               │
│  On click: VirusTotal · urlscan.io · RDAP · trace backend     │
└──────────────────────────────────────────────────────────────┘
               │ (only if the page fetch is blocked)
               ▼
   background.ts: same-origin Gmail fetch with host permissions
```

The full report runs in the **side panel**, an extension page with no Gmail code in it. The Gmail and Outlook content scripts also run the same `analyzeRawEmail()` on each email you open, to draw the in-page banner, inbox badges and link/reply warnings ([`lib/gmailProtect.ts`](../extension/src/lib/gmailProtect.ts)); the panel and the content script share one download per email. If a page blocks HTML parsing in the content script (see Trusted Types below), the email is analyzed in an extension-owned offscreen document instead ([`lib/remoteAnalyze.ts`](../extension/src/lib/remoteAnalyze.ts)).

## Repository layout

```
extension/
  entrypoints/
    background.ts            opens the panel on icon click; fallback fetch for Gmail URLs
    gmail.content.ts         message detection, raw fetch, highlight bridge
    gmail-ik.content.ts      MAIN-world script that exposes Gmail's session token
    sidepanel/               panel entry (index.html, main.tsx, style.css with design tokens)
  src/
    core/                    types, MIME parsing, scoring, analyzeRawEmail()
    analyzers/               auth, sender, lookalike, brands, content, links, attachments, trackers
    integrations/            rdap, virustotal, urlscan, trace, keyTest
    lib/                     domain helpers, settings, messages, gmailRaw, highlight
    ui/                      App, hooks, targets (finding → highlight/focus), components
  tests/                     Vitest suites + fixtures/*.eml
  scripts/gen-icons.mjs      renders icons from docs/brand/*.svg
backend/                     Hono redirect tracer (see BACKEND.md)
docs/                        guides, brand assets, screenshots
build/unmask-chrome/         production build output (git-ignored)
```

## Reading the message from Gmail

Unmask doesn't use the Gmail API or OAuth. It downloads the message the way you would with **⋮ → Show original**, inside your signed-in tab.

**1. Finding the open message.** `readState()` looks for elements with `data-message-id="#msg-f:<decimal>"` and `data-legacy-message-id="<hex>"` that contain a rendered body (`.a3s`). Only expanded messages count. A debounced `MutationObserver` reports changes to the panel.

**2. The session token.** Gmail's original-message endpoints need the per-session `ik` token. Without it, *Show original* returns 404. Content scripts can't read page variables, so a tiny **MAIN-world** script copies `window.GLOBALS[9]` into a `data-unmask-ik` attribute. As a fallback, the isolated script scans inline scripts for `GM_ID_KEY = '…'` or Gmail's boot data.

**3. URL candidates**, most reliable first ([`lib/gmailRaw.ts`](../extension/src/lib/gmailRaw.ts)):

| Label | URL |
|---|---|
| download (th) | `/mail/u/N/?ui=2&ik=…&view=att&th=<hex>&attid=0&disp=comp&safe=1&zw` |
| show original (permmsgid) | `/mail/u/N/?ik=…&view=om&permmsgid=msg-f:<decimal>` |
| show original (th) | `/mail/u/N/?ui=2&ik=…&view=om&th=<hex>` |
| … without ik | as fallbacks |

The hex id is derived from the decimal id with `BigInt(dec).toString(16)` when the attribute is missing. *Download original* redirects to `mail-attachment.googleusercontent.com` and returns the raw RFC 5322 message.

**4. Trusted Types.** Gmail enforces Trusted Types, so `DOMParser.parseFromString` and `innerHTML =` throw *"requires 'TrustedHTML' assignment"* in the page. Whether that also reaches extension content scripts has varied between browser versions (current Chromium does not apply it to the isolated world), so the code never relies on it: the *Show original* page is parsed with string functions (`parseOriginalPage`, `decodeEntities`), the highlighter and the in-page warnings only use `createElement`, `splitText`, `textContent` and attributes, and the analysis checks whether parsing works ([`lib/htmlParsing.ts`](../extension/src/lib/htmlParsing.ts)). If it doesn't, it tries a Trusted Types policy used only by Unmask's world, and failing that sends the email to an offscreen document (Chrome, Edge) or the background page (Firefox). The e2e test serves the fake Gmail with Gmail's `require-trusted-types-for 'script'` header, and `pnpm test:e2e:offscreen` forces the fallback path.

**5. Fallback fetch.** If the page-context fetch throws (for example a cross-origin redirect blocked by CORS), the content script asks the background worker to fetch the same URL. The worker only accepts requests from its own content script on a Gmail tab, for `mail.google.com` or `*.googleusercontent.com` URLs.

**6. Diagnostics.** Every attempt is recorded (`HTTP 302 from accounts.google.com/ServiceLogin …`) and shown under **Technical details** if all of them fail. These details never include message content.

## The analysis pipeline

`analyzeRawEmail(raw)` in [`core/analyze.ts`](../extension/src/core/analyze.ts) is pure apart from `crypto.subtle` and `DOMParser`, and makes **no network requests**:

1. **parse** with [postal-mime](https://github.com/postalsys/postal-mime): headers, addresses, HTML and text parts, attachments as bytes.
2. **auth**: parse `Authentication-Results` (RFC 8601), preferring the big providers' header.
3. **sender**: display-name tricks, look-alikes, brand claims, free webmail, Reply-To, Return-Path.
4. **content**: walk the HTML DOM to tag hidden elements (`data-unmask-hidden`), collect links, find forms and scripts, match phrase lists.
5. **links**: unwrap redirectors, flag each link, group flags into findings that keep the link indexes.
6. **attachments**: hash, classify by extension, MIME and magic bytes.
7. **trackers**: pixels, CSS beacons, tracked links.
8. **score**: see [CHECKS.md](CHECKS.md#how-the-score-works).

Each `Finding` carries a **`target`** saying what it refers to:

```ts
type FindingTarget =
  | { kind: 'links'; indexes: number[] }
  | { kind: 'attachment'; sha256: string }
  | { kind: 'sender' }
  | { kind: 'header'; key: string }
  | { kind: 'hidden' } | { kind: 'body' }
  | { kind: 'text'; phrases: string[] }
  | { kind: 'tab'; tab: TabId };
```

Online checks call `withExtraFindings(report, findings)`, which replaces findings with the same id and re-scores.

## The side panel

React 19 + Tailwind CSS 4, built with [WXT](https://wxt.dev). All colours come from CSS custom properties in [`sidepanel/style.css`](../extension/entrypoints/sidepanel/style.css) with a `prefers-color-scheme: dark` counterpart.

- [`ui/useGmail.ts`](../extension/src/ui/useGmail.ts) follows the active tab, asks the content script for state, and exposes `fetchRaw` and `highlight`.
- [`ui/App.tsx`](../extension/src/ui/App.tsx) runs analyses (cached per message, guarded by a run id so late results are dropped), manages tabs and focus, and remembers your Summary position for **Back to summary**.
- [`ui/targets.ts`](../extension/src/ui/targets.ts) maps a finding's `target` to a Gmail highlight and to a panel focus (tab + item).
- [`ui/safeHtml.ts`](../extension/src/ui/safeHtml.ts) builds the Body tab's `srcdoc`: scripts, frames and handlers removed, links disarmed (`href` removed, destination in `title`), `cid:` images inlined, and a CSP that blocks all requests unless you allow remote images. It's shown in an `<iframe sandbox="">`.

## Highlighting in Gmail

[`lib/highlight.ts`](../extension/src/lib/highlight.ts), run by the content script on `unmask:highlight` messages:

| Target | How it's found |
|---|---|
| links | `a[href]` in the message body matching the URL, or Gmail's `data-saferedirecturl` `q=` parameter |
| sender | the `[email]` element in the message header |
| attachments | chips whose `download_url` contains `:<filename>:`, or matching `aria-label`/`title` |
| text | text nodes split around each phrase and wrapped in `<mark data-unmask-mark>`; phrases spanning tags outline the smallest containing element |

Elements get a `data-unmask-hl` attribute styled by one injected `<style>`. `clearHighlights()` removes attributes and unwraps marks, then calls `normalize()`, so Gmail's text is restored exactly. A test asserts this.

## Online integrations

| Module | Endpoint | Notes |
|---|---|---|
| `rdap.ts` | `https://rdap.org/domain/<domain>` | Registration date and registrar; 404 means no record |
| `virustotal.ts` | `/api/v3/files/<sha256>`, `/urls/<id>`, `/files` (upload), `/analyses/<id>` | URL ids are unpadded base64url; upload polling respects the free 4/min limit |
| `urlscan.ts` | `/api/v1/scan/`, `/api/v1/result/<uuid>/` | Polls until ready; screenshot from `/screenshots/<uuid>.png` |
| `trace.ts` | built-in (background worker) or `<backend>/api/trace?url=` | Built-in: `lib/builtinTrace.ts` fetches with `credentials: 'omit'`, records hops with `webRequest.onBeforeRedirect` (matched by request id, initiator and `tabId -1`), parses meta/JS redirects from 256 KB, blocks local-network targets at every hop; traces are serialized. Needs the optional `<all_urls>` permission, requested from a click |
| `keyTest.ts` | VirusTotal EICAR lookup, urlscan quotas, backend `/api/health` | Validates a key before saving it |

## Security model

- **The email never leaves the browser** unless you click an online check, which sends only a URL, a hash, or (after explicit confirmation) a file.
- **Untrusted HTML** is never rendered in a privileged context. The Body view is a sandboxed iframe with no scripts, no same-origin access, disarmed links and a deny-all CSP.
- **The MAIN-world script** only reads one value and writes one attribute. It has no listeners and no messaging.
- **The background fetch** is restricted to its own content script on Gmail tabs and to Gmail and Google content hosts.
- **Keys** live in `chrome.storage.local`. Nothing syncs.
- **The trace backend** blocks private and reserved IP ranges at connect time (SSRF and DNS rebinding), restricts ports, strips URL credentials, rate-limits, and logs nothing.

Found a vulnerability? See [SECURITY.md](../SECURITY.md).

## Permissions

| Permission | Why |
|---|---|
| `sidePanel` | Show the Unmask panel |
| `storage` | Save settings and API keys locally |
| `tabs` | Know whether the active tab is Gmail, and talk to it |
| `https://mail.google.com/*` | Content scripts; fetch the original message |
| `https://*.googleusercontent.com/*` | *Download original* redirects here |
| `https://www.virustotal.com/*`, `https://urlscan.io/*` | Online checks you start |
| `webRequest` + optional `<all_urls>` | Built-in redirect tracing only; requested on first use |
