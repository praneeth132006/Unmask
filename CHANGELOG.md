# Changelog

All notable changes to Unmask. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
