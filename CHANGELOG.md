# Changelog

All notable changes to Unmask. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Warnings inside Gmail:** a red or amber banner above risky emails, risk badges next to risky senders in the inbox list, *"Wait, this link goes to …"* before risky links, and a warning when Reply would go to a different address. Works without opening the panel.
- **Sender history** kept only on your device: first-contact warnings, "your PayPal emails usually come from paypal.com", and a contact's name used from a different address.
- **QR-code phishing:** QR codes in images and PDFs are decoded and their links checked.
- **Payment fraud (BEC):** changed bank details, payment and gift-card requests, secrecy openers.
- **Looking inside attachments:** links in PDFs, Office macros and remote templates, ZIP file lists, and a safe preview of HTML attachments.
- **Fake brand logos**, by asset host, alt text or image fingerprint.
- **Domain intelligence:** first TLS certificate from Certificate Transparency (crt.sh) and MX/SPF/DMARC records (dns.google).
- **Report or export:** Gmail's Report phishing, APWG, Netcraft, Google Safe Browsing and PhishTank, plus PDF, JSON and .eml downloads.
- **Outlook on the web** support.
- **Firefox and Edge** builds, a store listing guide and a *Publish to stores* workflow.
- Website 404 page.
- **One-click redirect tracing inside Unmask**: no server needed. It follows HTTP, meta-refresh and JavaScript redirects in the background without cookies, blocks local-network targets, and asks for its optional permission once.
- **VirusTotal "Scan it now"** for links VirusTotal has never seen.
- **Hover a URL in the Plain text view** to outline that link in the Gmail email.
- **Copy all headers** and **Copy delivery path** buttons.
- **Theme switch** (System / Light / Dark) in the header and in Settings → Appearance.
- **Website** at praneeth132006.github.io/Unmask and a **GitHub Wiki**, both generated from the docs; README quick start.

### Fixed
- Headers tab: the copy buttons no longer touch the delivery path, and each is one clear button.
- Chrome refused to load a content script containing U+FFFF; the build now fails if that ever happens again.

### Changed
- New palette: charcoal and greys with lime/olive accents, red reserved for warnings; green logo.
- Tabs wrap onto two rows so all seven are always visible.

## [0.2.1] - 2026-10-19

### Fixed
- **"Uncaught Error: Extension context invalidated"** on `chrome://extensions` after Unmask was reloaded or updated while Gmail was open. The Gmail script now detects that it's orphaned and shuts down without calling extension APIs.
- **Security:** two ReDoS bugs, where crafted HTML could freeze the panel or tie up the trace server, are fixed with linear-time parsing. The safe view now also removes `<link>` prefetch hints, all `<meta>` tags, `<noscript>` and `ping`, and turns off DNS prefetching. Only real images are inlined from `cid:` parts. The trace server's rate limit no longer trusts a spoofable `X-Forwarded-For`. Files over 40 MB are refused instead of freezing the panel.

### Added
- [Free limits and costs](docs/LIMITS_AND_COSTS.md) for VirusTotal, urlscan.io, RDAP and Vercel, also shown in the setup cards and Settings.
- End-to-end tests that load the built extension in Chromium (`pnpm test:e2e`, run in CI); CodeQL and Dependabot.
- Code of conduct, issue and PR templates, expanded security policy; licence notices inside the extension zip.
- Clearer install guide: which file to download, how to check the folder, common errors, updating without losing settings.

### Changed
- urlscan.io *Private* visibility is labelled correctly as available on the free plan (50 a day).

## [0.2.0] - 2026-10-19

### Added
- **Hover to highlight:** hovering a finding, link, attachment or the sender outlines the matching part of the open Gmail message and scrolls it into view. Pressure phrases are marked word by word.
- **Click to jump:** clicking a finding opens its tab focused on that item; **Back to summary** returns to the same finding.
- **Guided setup** for VirusTotal and urlscan.io, shown where the key is needed, with links to the exact pages and **Save & test** validation. Settings shows each service as *Connected* or *Not set up*.
- **Privacy tab** with tracking-pixel and click-tracking detection for ~40 services.
- Summary chips for sender, links, files and trackers.
- New logo and icons.
- Full documentation: user guide, checks reference, architecture, backend, contributing.
- Prebuilt `unmask-chrome-<version>.zip` on GitHub Releases, so Unmask installs without Node or pnpm.
- CI on every push and pull request (tests, typecheck, build).

### Changed
- Clean redesign with design tokens for light and dark mode; pinned pill tabs with warning dots.
- Redirect tracing moved under **Settings → Advanced**, with **Use local server**.
- The build now outputs to a visible `build/unmask-chrome` folder.

### Fixed
- **Reading messages from Gmail.** *Show original* needs Gmail's session token, and Gmail's Trusted Types policy blocked `DOMParser`. Unmask now reads the token, tries *Download original* first, parses the page without `DOMParser`, falls back to the background worker, and shows per-URL diagnostics if everything fails.
- Fewer false alarms on legitimate mail: `.html` pages aren't "downloads", the sender's own click-tracking redirects aren't flagged, a single urgency word weighs less, and short hidden preview text no longer scores.

## [0.1.0] - 2026-10-19

### Added
- Side panel for Gmail with risk score, verdict and plain-language findings.
- Checks for sender authentication (SPF/DKIM/DMARC), identity tricks, look-alike domains (50+ brands), links, attachments, hidden text and pressure language.
- Safe body view, delivery path from `Received` headers, raw headers.
- VirusTotal (hash lookup and opt-in upload), urlscan.io sandbox scans, RDAP domain age.
- Redirect-trace backend with SSRF protection.
- `.eml` file and pasted-source analysis for other mail apps.
