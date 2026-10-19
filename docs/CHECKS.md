# What Unmask checks

Every check, what it means, and how much it adds to the risk score. The numbers here match the code in [`extension/src/analyzers`](../extension/src/analyzers) and [`extension/src/integrations`](../extension/src/integrations).

- [How the score works](#how-the-score-works)
- [Sender authentication](#sender-authentication)
- [Sender identity](#sender-identity)
- [Look-alike domains](#look-alike-domains)
- [Links](#links)
- [Attachments](#attachments)
- [Body content](#body-content)
- [Privacy and tracking](#privacy-and-tracking)
- [Online checks](#online-checks)

---

## How the score works

Each finding has a **severity** and **points**:

| Severity | Meaning |
|---|---|
| 🔴 Critical | Almost never legitimate: a password form, an executable, a look-alike brand domain |
| 🔴 High | Strong phishing signal |
| 🟠 Medium | Suspicious on its own, stronger in combination |
| 🟡 Low | Weak signal, common in legitimate mail too |
| ⚪ Note | Information only (0 points) |
| 🟢 Good | Reassuring (negative points) |

The **score** is the sum of points, from 0 to 100:

- Reassuring findings can take off **at most 15 points** in total, so a passing DMARC check can't hide real problems.
- **Any critical finding, or two high findings, forces at least 60**, which means *High risk*.
- Verdict: **0–19** *No red flags found* · **20–49** *Suspicious* · **50–100** *High risk*.

Online checks (domain age, VirusTotal, urlscan.io) add their findings when they finish, and the score updates.

Source: [`core/score.ts`](../extension/src/core/score.ts).

---

## Sender authentication

Read from the `Authentication-Results` header that the receiving mail server (Gmail, Outlook, Yahoo, iCloud) added. Both Gmail and Outlook formats are supported. Source: [`analyzers/auth.ts`](../extension/src/analyzers/auth.ts).

| Check | Severity | Points | Meaning |
|---|---|---|---|
| DMARC failed | High | 30 | The From domain did not authorize this email. Spoofed mail fails this. |
| DMARC passed | Good | −10 | The email really came from the domain in the From address. (Scammers can pass DMARC on domains they own.) |
| SPF failed | Medium | 15 | Sent from a server the domain does not allow. |
| SPF soft-failed | Low | 8 | The sending server is not clearly authorized. |
| No SPF | Low | 4 | The sending domain publishes no SPF policy. |
| DKIM failed | Medium | 12 | The signature doesn't match: altered or forged. |
| Not DKIM-signed | Low | 4 | No digital signature at all. |
| Signed by a different domain | Low | 5 | Signed, but not by the From domain (normal for some mailing services). Only when DMARC didn't pass. |
| No authentication results | Note | 0 | Usually a forwarded or pasted email that lost its headers. |

---

## Sender identity

Source: [`analyzers/sender.ts`](../extension/src/analyzers/sender.ts).

| Check | Severity | Points | Example |
|---|---|---|---|
| Display name hides a different address | High | 25 | `"service@paypal.com" <billing@paypa1-support.xyz>` |
| Sender domain imitates a brand (look-alike or typo) | Critical | 35 | `paypa1.com`, `pаypal.com`, `amazn.com` |
| Sender domain contains a brand it doesn't own | High | 20 | `paypal-secure-login.com` |
| Claims to be a brand, sent from another domain | High | 25 | Name "Netflix Billing", sent from `mailer-77.ru` |
| ↳ same, already explained by a look-alike finding | Medium | 10 | |
| Organisation name from free webmail | Medium | 15 | "IT Helpdesk" or "PayPal" sending from gmail.com |
| Replies go to a free webmail address | High | 20 | Reply-To `secure-team@protonmail.com` |
| Replies go to another domain | Medium | 12 | |
| Bounce address on another domain | Low | 3 | Normal for newsletters, so it barely counts |
| No valid From address | Medium | 10 | |

**Domain age** (online, on by default; see [Online checks](#online-checks)): registered under 30 days ago **High 25**; under 6 months **Medium 10**; no registration record **Medium 10**; older is a note. Skipped for free webmail and known brands.

---

## Look-alike domains

Source: [`analyzers/lookalike.ts`](../extension/src/analyzers/lookalike.ts), brand list in [`analyzers/brands.ts`](../extension/src/analyzers/brands.ts).

Unmask compares each domain against **50+ frequently impersonated brands** (PayPal, Apple, Microsoft, Google, Amazon, Netflix, banks, couriers, crypto exchanges, Indian banks and services, and more), each with the domains it really uses. A brand's own domains never match.

How a domain is normalized before comparing:

- Unicode tricks are decoded (`xn--pypal-4ve.com` → `pаypal.com`).
- Look-alike characters become their Latin twins: Cyrillic `а е о р с у х`, Greek `ο ν ρ`, digits `0→o 1→l 3→e 5→s`, and `rn→m`, `vv→w`.
- Accents are removed.

What counts as a match:

| Kind | Example | Explanation shown |
|---|---|---|
| Homoglyph | `paypa1.com`, `rnicrosoft.com` | "uses '1' instead of 'l'" |
| Typo (1–2 letters off, names of 6+ letters) | `amazn.com` | "one or two letters away from 'amazon'" |
| Brand inside the domain | `paypal-secure-login.com` | "contains 'paypal' but is not a PayPal domain" |
| Brand in a subdomain | `paypal.com.verify-account.net` | "puts 'paypal' in the subdomain of verify-account.net" |

---

## Links

Every link in the HTML and the plain-text part. Source: [`analyzers/links.ts`](../extension/src/analyzers/links.ts).

**Unwrapping, done locally with no network requests:** Google redirects, Microsoft Safe Links, Proofpoint URL Defense (v2 and v3), Facebook/Instagram link shims, YouTube and LinkedIn redirects, Slack redirects, and generic `?url=`/`?redirect=` parameters.

Findings are grouped by type: the same problem on several links becomes one finding (+2 points per extra link, at most +8).

| Check | Severity | Points |
|---|---|---|
| Domain imitates a brand | Critical | 35 |
| `javascript:` / `data:` link | Critical | 30 |
| Text shows one site, link goes to another | High | 25 |
| Real host hidden behind `@` (`https://paypal.com@evil.top`) | High | 25 |
| Punycode / internationalized domain | High | 20 |
| Points straight at an IP address | High | 20 |
| Domain contains a brand it doesn't own | High | 18 |
| URL shortener (bit.ly, tinyurl, …) | Medium | 10 |
| Free hosting or forms service (Firebase, Netlify, Google Forms, IPFS, …) | Medium | 10 |
| Downloads a risky file (`.exe`, `.zip`, `.iso`, …) | Medium | 8 |
| Domain ending popular with scammers (`.top`, `.xyz`, `.zip`, …) | Low | 6 |
| 4+ subdomains | Low | 5 |
| Non-standard port | Low | 5 |
| Bounces through a redirect on an unrelated site | Low | 4 |
| Not encrypted (`http://`) | Low | 3 |
| Goes through a mail-tracking service, so the final site is unknown | Low | 3 |

To avoid false alarms on normal newsletters:
- Links through known mailing services (SendGrid, Mailchimp, HubSpot, …) whose text shows another domain count as *tracking* (3), not *mismatch* (25).
- Redirects through the **sender's own** domain are not flagged.
- Ordinary `.html` pages are not "downloads".

---

## Attachments

Every attachment is hashed (SHA-256) on your computer. Source: [`analyzers/attachments.ts`](../extension/src/analyzers/attachments.ts).

| Check | Severity | Example |
|---|---|---|
| Executable or script | Critical | `.exe .scr .js .vbs .hta .ps1 .bat .lnk .msi .jar .apk …` |
| Right-to-left override in the name | Critical | `invoice‮fdp.exe` displays as `invoiceexe.pdf` |
| HTML attachment with a password form | Critical | Fake login page |
| Disk image | High | `.iso .img .vhd .dmg` |
| HTML / SVG attachment | High | Often a fake login page that opens in your browser |
| Macro document or OneNote | High | `.docm .xlsm .pptm .one …` |
| Double extension | High | `Invoice.pdf.html` |
| Password-protected archive | High | Hides its contents from scanners |
| PDF with JavaScript, launch actions or embedded files | High | |
| Obfuscated JavaScript in an HTML attachment | High | `atob(`, `eval(`, `fromCharCode` |
| Name and content type don't match | Medium | `report.pdf` that is really `text/html` |
| Archive | Low | `.zip .rar .7z` (contents not checked) |

The attachment's worst flag sets its points (Critical 35, High 22, Medium 10, Low 4), plus 4 for each extra flag, at most 45 per file.

---

## Body content

Source: [`analyzers/content.ts`](../extension/src/analyzers/content.ts).

| Check | Severity | Points |
|---|---|---|
| Password field inside the email | Critical | 35 |
| Form inside the email | High | 20 |
| Asks you to verify or re-enter account details | Medium | 15 |
| Pressure and urgency, 2+ phrases | Medium | 12 |
| Pressure and urgency, 1 phrase | Low | 5 |
| JavaScript inside the email | Medium | 10 |
| Mentions money, prizes or payments | Low | 8 |
| Hidden text over 600 characters | Medium | 8 |
| Hidden text 200–600 characters | Low | 3 |
| Short hidden text (usually an inbox preview line) | Note | 0 |

**Hidden text** means elements styled `display:none`, `visibility:hidden`, fully transparent, a zero-size font, collapsed to zero height, or text coloured the same as its background. The Body tab's **Show hidden text** switch outlines it in red.

**Phrases** include "within 24 hours", "account has been suspended", "unusual sign-in", "final notice", "verify your account", "confirm your password", "update your payment information", "mailbox full", "gift card", "wire transfer" and more. Hovering these findings marks the words in the email.

---

## Privacy and tracking

Source: [`analyzers/trackers.ts`](../extension/src/analyzers/trackers.ts). These are **privacy notes worth 0 points**: tracking is normal for newsletters and isn't phishing.

- **Tracking pixels:** remote images 3×3 pixels or smaller, hidden or transparent images, images at tracking paths (`/open`, `/wf/open`, `/pixel`, …), and CSS background images from tracking addresses.
- **Click-tracked links:** links routed through a known tracking service.
- **Services recognized (~40):** Mailchimp, SendGrid, HubSpot, Mailtrack, Mixmax, Yesware, Streak, Superhuman, Bananatag, ContactMonkey, Boomerang, Mailgun, SparkPost, Amazon SES, Postmark, Salesforce Marketing Cloud, Klaviyo, Campaign Monitor, Constant Contact, Customer.io, Intercom, Iterable, Braze, Mailjet, Brevo, Kit, Substack, beehiiv, MailerLite, GetResponse, ActiveCampaign, Marketo, Oracle Eloqua, Zoho Campaigns, Omnisend, Drip, Google Analytics, Google Ads, Meta Pixel, LinkedIn Ads.

---

## Online checks

These run only when you click them, except domain age, which you can turn off in Settings.

| Check | Sends | Finding |
|---|---|---|
| **Domain age** (rdap.org) | The sender's domain name | See [Sender identity](#sender-identity) |
| **VirusTotal: file** | The file's SHA-256 hash | 3+ engines: Critical 40 · 1–2: High 20 · clean or unknown: Note 0 |
| **VirusTotal: upload** (after confirmation) | The file itself | Same as above |
| **VirusTotal: link** | The link | 3+ engines: Critical 40 · 1–2: High 20 |
| **urlscan.io sandbox scan** | The link | urlscan says malicious: Critical 40, plus the final page, a screenshot and any brand it impersonates |
| **Redirect trace** (your server) | The link | The redirect chain (informational) |
