<p align="center">
  <img src="docs/brand/logo-512.png" width="112" alt="Unmask logo">
</p>

<h1 align="center">Unmask</h1>

<p align="center"><b>See what a suspicious email is really hiding.</b><br>
A Chrome extension that inspects the email open in Gmail and explains, in plain language, why it might be phishing.</p>

---

## What it does

Open an email in Gmail, click the Unmask icon, and a side panel shows a **risk score from 0 to 100** with the reasons behind it.

| Tab | What you see |
|---|---|
| **Overview** | Verdict (High risk / Suspicious / No red flags found) and every finding, worst first |
| **Sender** | Who *really* sent it: display name vs. address, Reply-To, Return-Path, SPF / DKIM / DMARC, domain age |
| **Links** | Each link's visible text vs. its real destination, with redirect wrappers peeled off, plus **Trace redirects**, **Sandbox scan** (urlscan.io screenshot) and **VirusTotal** buttons |
| **Files** | SHA-256 of each attachment, risky-type warnings, and a VirusTotal hash lookup (upload only after an explicit warning) |
| **Body** | The email rendered safely: scripts off, links disabled, remote images blocked, with a **Reveal hidden text** switch |
| **Headers** | The delivery path (origin → inbox) from `Received` headers, and every raw header with a filter |

Not using Gmail? Save the email as an `.eml` file and drop it on the panel, or paste the raw source.

### Checks

**Sender and authentication**
- SPF, DKIM and DMARC results from `Authentication-Results` (Gmail and Outlook formats)
- Display names that hide a different address: `"service@paypal.com" <billing@paypa1-support.xyz>`
- Lookalike domains against 50+ commonly impersonated brands: homoglyphs (`pаypal` with a Cyrillic а), digit swaps (`paypa1`), `rn` → `m`, typos (`amazn`), brand-in-domain (`paypal-secure-login.com`) and brand-in-subdomain (`paypal.com.verify.net`)
- Brand names in the display name that don't match the sending domain
- Organisation-sounding names ("IT Helpdesk", "Billing") sending from free webmail
- Reply-To and Return-Path on other domains
- Domain age via RDAP: brand-new domains are a strong phishing signal

**Content**
- Hidden text (display:none, zero-size fonts, text coloured like its background) used to fool spam filters
- Forms and password fields inside the email
- Pressure language, credential requests and money lures
- Tracking pixels

**Links**
- Visible text showing one domain while the link goes to another
- Local unwrapping of Google redirects, Microsoft Safe Links, Proofpoint, Facebook/LinkedIn/YouTube redirectors and open-redirect parameters
- IP-address hosts, punycode, `user@host` tricks, URL shorteners, free hosting and form services, risky TLDs, odd ports, direct downloads, `javascript:` links
- Mail tracking services (SendGrid, Mailchimp, …) are recognised so normal newsletters aren't flagged

**Attachments**
- Executables, scripts, disk images, HTML/SVG attachments, macro documents, OneNote
- Double extensions (`Invoice.pdf.html`), right-to-left override filename tricks, MIME type mismatches
- Password-protected ZIPs, PDFs with JavaScript or launch actions, HTML attachments with password forms or obfuscated JavaScript

### Scoring

Each finding carries points. The score is their sum (capped at 100); reassuring signals such as a DMARC pass can take off at most 15 points. Any **critical** finding, or two **high** ones, forces a *High risk* verdict. Unmask never says an email is "safe", only that no red flags were found.

## Privacy

- Parsing and every local check run **in your browser**. The email is never sent to an Unmask server.
- Online checks are opt-in, per click, and send the minimum: the sender's **domain name** to rdap.org (automatic lookup can be turned off), a single **URL** to the trace backend or urlscan.io, a file **hash** to VirusTotal.
- Uploading a file to VirusTotal needs an extra confirmation, because uploaded files can be downloaded by VirusTotal's paying customers.
- API keys are stored only in `chrome.storage.local`.

See [PRIVACY.md](PRIVACY.md) for the full policy.

## Getting started

Requirements: Node 20+ and [pnpm](https://pnpm.io).

```bash
pnpm install
pnpm build
```

Then load the extension:
1. Open `chrome://extensions` and enable **Developer mode**
2. Click **Load unpacked** and choose the `build/unmask-chrome` folder
3. Open Gmail (reload it if it was already open), open an email and click the Unmask icon

For development with hot reload:

```bash
pnpm dev
```

### Optional: API keys

Open the panel's ⚙ settings and add:
- a free **VirusTotal** API key (virustotal.com → your profile → API key) for hash and URL lookups
- a free **urlscan.io** API key (urlscan.io → Settings & API) for sandbox scans with screenshots

### Optional: redirect-trace backend

**Trace redirects** follows a link's redirect chain from a server instead of your browser. It handles HTTP redirects, `<meta refresh>` and simple JavaScript redirects without running any page code, refuses private and reserved IP ranges (re-checked at connect time, which also blocks DNS rebinding), and logs nothing.

Run it locally:

```bash
pnpm backend   # http://localhost:8787
```

or deploy the `backend/` folder to Vercel (zero-config Hono). Then put its URL in the panel's settings.

## Project layout

```
extension/                 WXT + React + Tailwind, Manifest V3
  entrypoints/
    gmail.content.ts       finds open emails, downloads their raw source via Gmail's "Show original"
    background.ts          opens the side panel when the toolbar icon is clicked
    sidepanel/             panel entry
  src/core/                MIME parsing, scoring, the analyzeRawEmail pipeline
  src/analyzers/           auth, sender, lookalike, content, links, attachments
  src/integrations/        RDAP, VirusTotal, urlscan.io, trace backend clients
  src/ui/                  panel components and the safe HTML renderer
  tests/                   Vitest suites and sample .eml files
backend/                   Hono redirect tracer (Node locally, Vercel in production)
```

## Tests

```bash
pnpm test        # extension + backend
pnpm typecheck
```

## Limitations

- Gmail only for automatic detection; other mail apps work through `.eml` files or pasted source.
- Gmail's page structure changes over time. If Unmask stops seeing open emails, use the `.eml` fallback and open an issue.
- Heuristics produce false positives and miss some attacks. Treat the score as advice, not a guarantee.

## License

[MIT](LICENSE)
