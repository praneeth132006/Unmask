# Roadmap

Unmask's goal: **anyone can tell a phishing email from a real one before they click, without giving their email to anyone.** Everything runs in the browser, it is free for people and organisations alike, and the code is MIT-licensed.

This page lists what is done and what comes next. The next pieces are split into milestones that each end in something users can install, so they can be funded and checked one at a time.

## Where it stands (version 0.5.0, November 2026)

- Browser extension for **Gmail and Outlook on the web**, in the Chrome Web Store and Firefox Add-ons, with Edge builds.
- **Checks on the device:** sender authentication (SPF, DKIM, DMARC, with DKIM signatures verified locally), look-alike and homoglyph domains, brand impersonation, links whose text and target differ, redirect chains, QR codes in images and PDFs, fake logos, tracking pixels, hidden text, and attachments (PDF, Office macros, archives, RTF).
- **Warnings where people act:** a banner in the email, a stop before a risky link opens, a warning before replying to an impostor, and badges in the inbox list.
- **A protection list** of your bank, your boss, your trusted senders, shareable as a file or pushed by IT policy ([For teams](docs/TEAMS.md)).
- **Reports** for users and security teams (PDF, Word, HTML, STIX 2.1).
- **Measured:** 346 of 400 real phishing emails from the public phishing_pot collection caught in the first corpus run. Every reported false alarm becomes a test (see `extension/tests/falsePositives.test.ts`).
- **Engineering:** 480+ unit tests, end-to-end tests in a real Chromium, CodeQL, and CI on every change.

## Next milestones

Each milestone is a deliverable with an estimated effort for one developer.

### 1. Accuracy you can check (6 weeks)
- A public benchmark: a labelled set of real phishing and real legitimate emails (newsletters, banks, platforms that send for others), with personal data removed.
- Detection rate and false-alarm rate published for every release, measured by CI.
- A **"Was this right?"** button. Nothing is sent unless the user presses it and chooses what to share (the sender's domain and the check that fired, never the email).
- **Done when:** the benchmark and its scores are in the repository, and the false-alarm rate on legitimate mail is published and falling.

### 2. Unmask in more languages (5 weeks)
- Translation framework for the extension, the warnings and the plain-language summaries.
- Hindi, Spanish, Portuguese, French, German and Indonesian first, with native-speaker review.
- Detection of scams written in those languages (urgency and payment wording, local banks and couriers).
- **Done when:** a user can pick a language in Settings, and every warning reads naturally in it.

### 3. Accessible to everyone (3 weeks)
- A WCAG 2.1 AA audit of the panel and the warnings inside Gmail and Outlook.
- Screen reader support for the warnings, keyboard-only use, and better contrast.
- **Done when:** the audit findings are fixed and documented.

### 4. More mail apps (6 weeks)
- A **Thunderbird** add-on, which reuses the same analysis engine.
- Better support for Outlook on the web, plus reading `.msg` files.
- **Done when:** Thunderbird users can install it from addons.thunderbird.net.

### 5. Teams and schools (4 weeks)
- A **"Report to IT"** button that sends the analysis to an address the admin sets by policy, with no Unmask server in between.
- Admin policies for each setting (for example, turning off outside lookups on work computers).
- Ready-made guides and templates for Google Workspace, Microsoft 365 and school IT.
- **Done when:** a school or small company can roll out Unmask and receive reports in an afternoon.

### 6. Independent security review (2 weeks of fixes)
- An outside audit of how Unmask handles untrusted email content (HTML, attachments, the safe view) and its permissions.
- Every finding fixed, and the report published.

## Not planned

- Ads, accounts, selling or sharing data, or a paid tier that holds back protection.
- Sending emails to a server for analysis. Unmask stays on the device.

Ideas and votes: [open an issue](https://github.com/praneeth132006/Unmask/issues/new/choose).
