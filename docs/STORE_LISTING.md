# Store listings

Everything needed to publish Unmask to the Chrome Web Store, Firefox Add-ons (AMO) and Microsoft Edge Add-ons. Creating the developer accounts and pressing **Submit** the first time has to be done by the maintainer; after that, the **Publish to stores** workflow uploads new versions.

## 1. Build the packages

```bash
pnpm zip:all
```

This writes `build/unmask-chrome-<version>.zip`, `build/unmask-edge-<version>.zip`, `build/unmask-firefox-<version>.zip` and `build/unmask-extension-<version>-sources.zip` (AMO asks for the source code because the bundle is minified).

## 2. Listing text (same for every store)

**Name:** Unmask — Phishing Email Inspector

**Short description (132 characters max):**
See what a suspicious email is really hiding: real sender, real links, QR codes, hidden text and risky attachments. Runs locally.

**Category:** Productivity (Chrome, Edge) · Privacy & Security (Firefox)

**Full description:**

> Unmask checks the email you open in Gmail or Outlook on the web and tells you, in plain words, whether it looks like phishing.
>
> - **Warnings inside your inbox.** A red or amber banner above risky emails and a badge next to risky senders, without opening anything.
> - **Stops risky clicks.** "Wait, this goes to paypa1-secure.top" before a dangerous link opens, and a warning when Reply would go to a different address.
> - **First-contact warnings.** Unmask remembers, only on your device, who normally emails you: "You've never received mail from paypa1-support.xyz. Your PayPal emails usually come from paypal.com."
> - **QR-code phishing.** Reads QR codes in images and PDFs and checks where they really go.
> - **Payment fraud.** Flags changed bank details, payment and gift-card requests, and a contact's name used from another address.
> - **Inside attachments.** Links hidden in PDFs, macros in Office files, the file list of ZIPs, and a safe preview of HTML files.
> - **Fake logos.** Spots an email showing PayPal's logo that PayPal didn't send.
> - **Domain checks.** Brand-new domains, brand-new TLS certificates and missing mail records.
> - **Report it.** One click to Gmail's Report phishing, APWG, Netcraft, Google Safe Browsing or PhishTank, plus a PDF or JSON report for your IT team.
>
> Every check runs in your browser. Unmask has no server and no account. Optional lookups send only a domain name or a file fingerprint, and you can turn each one off.

**Privacy policy URL:** https://praneeth132006.github.io/Unmask/privacy.html
**Homepage / support URL:** https://github.com/praneeth132006/Unmask

**Screenshots** (1280×800 or 640×400; Chrome needs at least one): crop from `docs/images/overview-light.png`, `links-dark.png`, `sender-light.png`, `body-light.png`, `privacy-light.png`. **Promo tile** (440×280): `docs/brand/logo-512.png` on the brand background.

## 3. Single purpose (Chrome)

Unmask analyzes the email the user is reading in Gmail or Outlook on the web and warns about phishing.

## 4. Permission justifications

| Permission | Why |
| --- | --- |
| `storage` | Saves settings, optional API keys, the on-device sender history and recent verdicts. Never synced or uploaded. |
| `tabs` | Finds the active Gmail or Outlook tab so the side panel can show the open email, and opens report pages in a new tab. |
| `sidePanel` | Shows the report next to the inbox (Chrome, Edge). Firefox uses its sidebar. |
| `offscreen` | A hidden extension page that parses the open email's HTML when the mail page blocks parsing in the content script. Local only. |
| `webRequest` | Only for the optional *Trace redirects* button: watches the redirects of the one link the user asked to trace. |
| `https://mail.google.com/*` | Reads the open email's original source from Gmail's own "Show original" page and shows warnings inside Gmail. |
| `https://*.googleusercontent.com/*` | Gmail's "Download original" can redirect here. |
| Outlook hosts (content scripts) | Reads the open email from the page and shows warnings inside Outlook on the web. |
| `https://www.virustotal.com/*`, `https://urlscan.io/*` | Optional checks the user starts with a button, using their own API key. |
| `https://crt.sh/*`, `https://dns.google/*` | Domain checks: certificate history and mail DNS records. Sends only domain names. Can be turned off. |
| Optional `<all_urls>` | Asked for only when the user first clicks *Trace redirects*. |

**Remote code:** none. All code ships in the package.

## 5. Data disclosure answers

- **Chrome "Privacy practices":** Unmask does not collect or transmit user data to the developer. Tick *none* of the data categories. Certify that data is not sold, not used for unrelated purposes, and not used for creditworthiness.
- **Firefox:** the manifest declares `data_collection_permissions: { required: ["none"] }`. The automatic domain lookups send public domain names (not email content) to rdap.org, crt.sh and dns.google; mention this in the reviewer notes.
- **Edge:** same answers as Chrome.

**Reviewer notes (paste into AMO/Edge):** Build with `pnpm install && pnpm zip:all` (Node 24, pnpm 10). To test without a mail account, open the side panel on any page and drop `extension/tests/fixtures/phishing-paypal.eml` (from the sources zip) onto it.

## 6. Automatic publishing

After the first manual submission, add these repository secrets (Settings → Secrets and variables → Actions) and run **Actions → Publish to stores** (start with *dry run*):

| Store | Secrets | Where to get them |
| --- | --- | --- |
| Chrome Web Store | `CHROME_EXTENSION_ID`, `CHROME_PUBLISHER_ID`, `CHROME_SERVICE_ACCOUNT_CLIENT_EMAIL`, `CHROME_SERVICE_ACCOUNT_PRIVATE_KEY` | Developer Dashboard → Account (publisher ID); a Google Cloud service account added to the publisher with the Chrome Web Store API enabled. |
| Firefox Add-ons | `FIREFOX_JWT_ISSUER`, `FIREFOX_JWT_SECRET` | addons.mozilla.org → Developer Hub → Manage API Keys. The add-on ID is fixed in the manifest: `unmask@praneeth132006.github.io`. |
| Edge Add-ons | `EDGE_PRODUCT_ID`, `EDGE_CLIENT_ID`, `EDGE_API_KEY` | Partner Center → Microsoft Edge → Publish API. |

Each store is skipped until its secrets exist, so you can add them one at a time.
