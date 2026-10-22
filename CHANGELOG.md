# Changelog

All notable changes to Unmask. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.4] - 2026-10-20

### Added
- **See where each tracking pixel is.** The Privacy tab lists every pixel with its service, full address, why it counts as a pixel, and where it sits: image number, how far through the visible text, the words just before and after it, and whether it's inside a hidden block. **Show it in the safe view** opens the Body tab with a red tag at that exact spot. With the email open in Gmail, hovering a pixel labels its spot there.

### Fixed
- **Load remote images** in the Body tab also loaded tracking pixels, which told the sender you opened the email. Tracking pixels now stay blocked; the switch says so, and its warning now says images load straight from the sender's servers (so they see your IP address).

## [0.3.3] - 2026-10-20

### Fixed
- **Simple mode hid the tabs**, so Sender, Links, Files, Body, Privacy and Headers couldn't be opened from the Summary. The tabs are now always shown; simple mode only folds the technical red flags on the Summary. The end-to-end test checks all seven tabs and the Headers tab in both modes.

## [0.3.2] - 2026-10-20

### Fixed
- **The Peek card said "no trackers" for emails that have trackers.** Its preview label "(no images, no trackers)" meant *nothing was loaded*, but read as *the email has none*. The card now lists exactly what the email contains (tracking pixels, remote images, click-tracked links) and says that Peek loaded none of them, and that opening it in Gmail will.
- **"No red flags found" above a list titled "Red flags".** A clean verdict with minor points is now **Low risk**, and its list is **Worth knowing**. "No red flags" appears only when there is nothing to point out. The plain summary says "Nothing serious found. Worth knowing:" instead of "Nothing looks wrong" followed by warnings.
- The Summary chip says what the trackers are, for example "1 pixel · 24 tracked links", instead of adding them into one number.
- The side panel no longer says a peeked email's trackers "haven't fired" after you open that email in Gmail; it says Gmail has loaded its images.
- Privacy wording corrected: in Gmail, images load through Google's proxy, so senders learn *that* and *when* you opened an email, not your IP address.
- "Replies go to a different address" names the address instead of calling it "a stranger", and is medium (not high) when the sender's domain is verified. Free forms and hosting links (Typeform, Google Forms, Notion) are a low note on their own.

## [0.3.1] - 2026-10-20

### Fixed
- **Peek buttons were invisible in real Gmail.** They sat after the sender's name, inside Gmail's fixed-width sender column, which cut them off for longer names. They're now at the start of the subject, where Gmail shows its own labels. The end-to-end test now copies Gmail's real inbox layout and checks every button is visible and clickable.
- **False alarms on legitimate links and newsletters:** `research.meta.ai` flagged as "not a Meta domain"; link text like `CLAUDE.md` read as a website; brands' own country and product domains (`google.co.in`, `amazon.de`, `paypal.de`, `meta.ai`) treated as lookalikes; everyday words (a person called Chase, `apple-farm.com`, `wise-owl.org`) treated as brand claims; real words treated as typos (`finance` vs Binance, `revolt` vs Revolut); newsletters showing a company's logo flagged as fakes; LinkedIn's `lnkd.in` and Google's `docs.google.com` flagged in those companies' own emails. A 100-case accuracy corpus of real links, senders and phishing patterns now guards against this.
- **urlscan.io "taking too long":** results of unlisted and private scans were fetched without the API key, so they could never be found. A scan still running after 2.5 minutes now shows a link to its report instead of an error.

## [0.3.0] - 2026-10-20

### Added
- **All protection inside Gmail is on by default**, including checking new emails before you open them; settings saved by older versions are switched on once. Simple mode moved to Settings → Appearance. The panel shows how many emails have a Peek button, and Settings shows the version (now 0.3.0).
- **Peek:** a button on every Gmail inbox row checks the email without opening it. You see the verdict, plain reasons and a text-only preview; images and trackers never load. *Read it safely in Unmask* opens the full report, still unopened. Optional automatic checks of unread emails.
- **Plain words and simple mode:** an "In plain words" card (one sentence, everyday reasons, what to do) on every report and in the Gmail banner; simple mode hides the technical details until asked.
- **Your protection list:** companies you use, people who might be impersonated and trusted senders, with critical warnings for anything imitating them. One-click *Trust this sender* / *Protect name*. Export and import as a file to set it up for a family or team.
- **Warnings inside Gmail:** a red or amber banner above risky emails, risk badges next to risky senders in the inbox list, *"Wait, this link goes to …"* before risky links, and a warning when Reply would go to a different address. Works without opening the panel.
- **Sender history** kept only on your device: first-contact warnings, "your PayPal emails usually come from paypal.com", and a contact's name used from a different address.
- **QR-code phishing:** QR codes in images and PDFs are decoded and their links checked.
- **Payment fraud (BEC):** changed bank details, payment and gift-card requests, secrecy openers.
- **Looking inside attachments:** links in PDFs, Office macros and remote templates, ZIP file lists, and a safe preview of HTML attachments.
- **Fake brand logos**, by asset host, alt text or image fingerprint.
- **Domain intelligence:** first TLS certificate from Certificate Transparency (crt.sh) and MX/SPF/DMARC records (dns.google).
- **Report or export:** Gmail's Report phishing, APWG, Netcraft, Google Safe Browsing and PhishTank, plus PDF, JSON and .eml downloads.
- **Outlook on the web** support.
- **Firefox and Edge** builds.
- Website 404 page.
- **Screenshots of every new feature** in the README and on the website, made from the real extension by `pnpm --filter unmask-extension screenshots`.
- **Changelog** page on the website.
- **One-click redirect tracing inside Unmask**: no server needed. It follows HTTP, meta-refresh and JavaScript redirects in the background without cookies, blocks local-network targets, and asks for its optional permission once.
- **VirusTotal "Scan it now"** for links VirusTotal has never seen.
- **Hover a URL in the Plain text view** to outline that link in the Gmail email.
- **Copy all headers** and **Copy delivery path** buttons.
- **Theme switch** (System / Light / Dark) in the header and in Settings → Appearance.
- **Website** at praneeth132006.github.io/Unmask and a **GitHub Wiki**, both generated from the docs; README quick start.

### Fixed
- **Peek buttons and inbox badges never appeared in a busy Gmail inbox.** Gmail changes the page constantly, and the inbox scan waited for a quiet moment that never came. It now runs at least every 1.5 s, and puts back buttons Gmail wipes when it redraws a row. The panel's "follow the open email" had the same delay.
- Hovering a file pointed at the wrong attachment in Gmail when names were similar or repeated; it now outlines exactly one tile, matched by name, shortened name or position.
- **Send file to VirusTotal** says clearly that the file goes straight from the email (no download needed) and which files not to share.
- A QR code pointing to the same address as a link in the same PDF was hidden on the Links tab.
- A ZIP whose contents were listed still said "contents could not be checked".
- Redirect tracing could miss the first redirects on a busy computer.
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
