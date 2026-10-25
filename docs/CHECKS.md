# What Unmask checks

Every check, what it means, and how much it adds to the risk score. The numbers here match the code in [`extension/src/analyzers`](../extension/src/analyzers) and [`extension/src/integrations`](../extension/src/integrations).

- [How the score works](#how-the-score-works)
- [Sender authentication](#sender-authentication)
- [Sender identity](#sender-identity)
- [Look-alike domains](#look-alike-domains)
- [Links](#links)
- [Attachments](#attachments)
- [Body content](#body-content)
- [Sender history](#sender-history)
- [Your protection list](#your-protection-list)
- [Payment fraud (BEC)](#payment-fraud-bec)
- [QR codes](#qr-codes)
- [Fake brand logos](#fake-brand-logos)
- [Privacy and tracking](#privacy-and-tracking)
- [Online checks](#online-checks)
- [Warnings inside Gmail and Outlook](#warnings-inside-gmail-and-outlook)

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
| Fake "passed" stamp | High | 25 | An `Authentication-Results` header names a big mail provider (Google, Microsoft, Yahoo, Apple) that never handled the email. The sender wrote it; Unmask ignores it. |

Which `Authentication-Results` header is used: the first one written by the provider that delivered the email to you (matched against the trusted part of the delivery path), never one from a provider that isn't in the path.

### Inside the DKIM signatures

Unmask also reads every `DKIM-Signature` itself and recomputes its body hash on your computer (relaxed and simple canonicalization, SHA-256 and SHA-1, the `l=` length limit). Source: [`lib/dkim.ts`](../extension/src/lib/dkim.ts), [`analyzers/dkim.ts`](../extension/src/analyzers/dkim.ts).

| Check | Severity | Points | Meaning |
|---|---|---|---|
| A second Subject/From/Reply-To/To/Date header was added after signing | High | 22 | The signature still passes, but your mail app may show the unsigned copy |
| The body no longer matches its signature (and your provider didn't already report the DKIM failure) | Medium | 12 | Changed after signing: a forwarder's footer or tampering. Low (4) when the copy lost its line endings |
| Content added after an `l=` limit | Medium | 10 | Only the first part is signed; text or links were appended below it |
| Only part of the body is signed | Low | 3 | |
| Signature doesn't cover From | Medium | 10 | Says nothing about who sent it |
| Signed more than 7 days before it arrived | Medium | 10 | A "DKIM replay": an old genuine email re-sent to new people |
| Signature expired (`x=`) before it arrived | Low | 4 | |
| Reply-To not signed by the From domain | Low | 4 | |
| Only SHA-1 signatures | Low | 3 | |

With online checks on, Unmask also fetches each signer's public key and verifies the signature itself (RSA-SHA256, RSA-SHA1 and Ed25519), the same check your provider ran on arrival. A signature that passed on arrival but fails now is treated as a rotated key, not tampering. See [Online checks](#online-checks).
| This copy differs from what your provider verified | Note | 0 | Usually a pasted copy rather than the original |

### DKIM replay

A genuine signed email (often a notification the attacker triggered on their own account, with the lure in a field they control) re-sent unchanged to many people. The signature verifies and DMARC can pass, so it needs several signs together. Source: [`analyzers/replay.ts`](../extension/src/analyzers/replay.ts).

| Check | Severity | Points |
|---|---|---|
| Signed by the From domain, plus two or more of: signed or written days before arrival · addressed to someone else · passed at an earlier ARC hop and failed at yours · passed on by a forwarding service (SRS bounce address) · SPF failed for an unrelated delivering server | High | 20 |

When it fires, the *DMARC passed* reassurance is removed.

### Forwarding record (ARC)

Forwarding servers that support ARC record the authentication results they saw and seal them (`ARC-Seal`, `ARC-Message-Signature`, `ARC-Authentication-Results`). Unmask reads the chain's structure and results; it does not verify the seals' signatures. Source: [`analyzers/arc.ts`](../extension/src/analyzers/arc.ts).

| Check | Severity | Points | Meaning |
|---|---|---|---|
| Chain broken: a set missing or incomplete, or a server marked it `cv=fail` | Low | 3 | |
| Passed at the first server, DMARC failed at yours | Note | 0 | Forwarded or re-sent in between: normal for mailing lists, and also how replayed emails look |

---

## Delivery path

The `Received` headers, read from the bottom up the way an analyst reads them. Lines written by your own mail provider are trusted; lines below the point where your provider took the email were written by servers you can't check, possibly the sender itself, and the Headers tab marks them *can't be verified*. Source: [`analyzers/received.ts`](../extension/src/analyzers/received.ts).

| Check | Severity | Points | Meaning |
|---|---|---|---|
| Delivery times out of order by over 6 hours, involving an unverifiable line | Medium | 10 | Forged delivery lines are written by the sender, who guesses the times |
| Delivery times out of order by over 10 minutes | Low | 4 | Usually a wrong server clock |
| Sent straight from a computer (`DESKTOP-…`, `localhost`, an IP, a name without a dot) | Medium | 10 | Companies send through named mail servers |
| The server that handed it to your provider has no DNS name | Low | 4 | |
| Written more than 3 days before it arrived | Low | 6 | Old signed emails re-sent to new people ("DKIM replay") look like this |
| Dated more than 2 hours in the future | Low | 5 | |

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

### How the email was built

Each mail service builds its emails its own way; scam tools build them differently. Source: [`analyzers/identity.ts`](../extension/src/analyzers/identity.ts).

| Check | Severity | Points | Example |
|---|---|---|---|
| Two or more From headers | High | 20 | Your mail app shows one sender, filters checked another |
| Claims Gmail, Outlook.com or Yahoo, but its Message-ID wasn't made there (and DMARC didn't pass) | Medium | 12 | `ceo.office@gmail.com` with `Message-ID: <…@vps-1234.example.net>` |
| Sent with a bulk spam tool (`X-Mailer`) | Medium | 12 | Leaf PHPMailer, Atomic Mail Sender, Gammadyne, SendBlaster |
| Sent by a script on a website (`X-PHP-Originating-Script`, PHPMailer, …) | Medium (10) when it claims a brand, otherwise Low (3) | | |
| "Re:" in the subject with no In-Reply-To, References or Thread-Index | Low | 6 | A made-up conversation. "Fwd:" is not flagged |
| Your provider had to add the Message-ID (`SMTPIN_ADDED`) | Low | 3 | |
| A genuine, signed brand email addressed to someone else (not a list or your own forwarding) | Low | 5 | A replayed notification |
| The sender name or subject spells a brand with disguised letters | Medium | 15 | `PаyPal` with a Cyrillic а, `Net\u200bflix` with a zero-width space |
| The sender name mixes alphabets or hides invisible characters | Medium | 10 | |
| The subject does | Low | 5 | |

---

## Look-alike domains

Source: [`analyzers/lookalike.ts`](../extension/src/analyzers/lookalike.ts), brand list in [`analyzers/brands.ts`](../extension/src/analyzers/brands.ts).

Unmask compares each domain against **50+ frequently impersonated brands** (PayPal, Apple, Microsoft, Google, Amazon, Netflix, banks, couriers, crypto exchanges, Indian banks and services, and more), each with the domains it really uses. A brand's own domains never match.

How a domain is normalized before comparing:

- Unicode tricks are decoded (`xn--pypal-4ve.com` → `pаypal.com`).
- Look-alike characters become their Latin twins: Unicode's own confusables list ([UTS #39](https://www.unicode.org/reports/tr39/), about 1,600 characters from Cyrillic, Greek, Coptic, Cherokee, mathematical and full-width letters), plus digits `0→o 1→l 3→e 5→s`, and `rn→m`, `vv→w`. The table is generated by `node scripts/gen-confusables.mjs confusables.txt`.
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
| Carries an email address after the `#`, plain or base64 (a phishing kit pre-filling its fake login page) | High | 18 |
| Punycode / internationalized domain | High | 20 |
| Points straight at an IP address | High | 20 |
| Domain contains a brand it doesn't own | High | 18 |
| URL shortener (bit.ly, tinyurl, …) | Medium | 10 |
| Carries a base64-encoded email address in its path or query (not on the sender's own or a mail-tracking domain) | Medium | 10 |
| Free hosting or forms service (Firebase, Netlify, Cloudflare Pages/Workers/R2, Azure Web Apps, Google Forms, IPFS, Telegraph, …) | Low | 5 |
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
| Archive | Low | `.zip .rar .7z` |

**Looking inside** ([`analyzers/documents.ts`](../extension/src/analyzers/documents.ts)). Files are parsed as bytes; nothing is opened or run. Links found inside go through every [link check](#links) and appear on the Links tab marked with the file they came from.

| File | Check | Severity |
|---|---|---|
| PDF | Tries to launch a program | Critical |
| PDF | JavaScript · embedded files · a form that submits to a website · `javascript:`/`file:` links | High |
| PDF | 1–2 page PDF built around links (a classic way to slip phishing links past filters) | Medium |
| Word / Excel / PowerPoint | Loads a template or object from the internet (template injection) | Critical |
| Word / Excel / PowerPoint, legacy `.doc/.xls` | Macros (`vbaProject.bin`, `_VBA_PROJECT`) · DDE fields | High |
| Word / Excel / PowerPoint | Embedded OLE objects | Medium |
| RTF | Embedded object (`\object`, used by Office exploits) | High |
| ZIP | A program inside (`.exe .js .lnk .hta …`) | Critical |
| ZIP | Risky files inside (`.html .iso .one .docm …`) | High |
| ZIP | Archive inside an archive · zip bomb | Medium |
| HTML | Form targets and links are listed; **Safe preview** renders it sandboxed with scripts, forms, links and network off | |

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
| The whole message is a clickable picture (under 40 characters of text) | Medium | 10 |
| The message is only a picture | Low | 4 |
| Mentions money, prizes or payments | Low | 8 |
| Hidden text over 600 characters | Medium | 8 |
| Hidden text 200–600 characters | Low | 3 |
| Short hidden text (usually an inbox preview line) | Note | 0 |

**Hidden text** means elements styled `display:none`, `visibility:hidden`, fully transparent, a zero-size font, collapsed to zero height, or text coloured the same as its background. The Body tab's **Show hidden text** switch outlines it in red.

**Phrases** include "within 24 hours", "account has been suspended", "unusual sign-in", "final notice", "verify your account", "confirm your password", "update your payment information", "mailbox full", "gift card", "wire transfer" and more. Hovering these findings marks the words in the email.

---

## Attack techniques

Named techniques that analysts recognise by their shape rather than by a bad link or a failed check. Source: [`analyzers/techniques.ts`](../extension/src/analyzers/techniques.ts).

| Check | Severity | Points | What it looks for |
|---|---|---|---|
| Callback scam ("TOAD") | High | 22 | A phone number, an instruction to call, a charge, renewal or invoice, and a dispute or an amount. No link: the scam happens on the phone. From a verified brand (DMARC pass) it is only a Low (3) note |
| A real notification platform carrying a scammer's message | High | 22 | An email that passed DMARC from PayPal, DocuSign, QuickBooks/Intuit, Square, Google, Microsoft, Dropbox, Adobe Sign, Zoom… (services that let anyone send invoices, shares and invites with their own text) containing a callback phone number, a link with its own high-risk flags, or a personal webmail contact. Replaces the callback finding |
| Device-code phishing | High | 22 | A link to a real device sign-in page (`microsoft.com/devicelogin`, `google.com/device`, `github.com/login/device`…) or a code to enter there. The page is genuine; the code signs the attacker's device in |
| Consent (app-permission) link | High (20) when it asks for mail/file access (`offline_access`, `Mail.Read`, Gmail, Drive…) or sends you on to an unrelated `redirect_uri`, otherwise Medium (12) | | A link straight to a Microsoft or Google OAuth authorize page |
| "ClickFix": paste a command into your computer | Critical (35) with both keyboard steps and a command, otherwise High (22) | | Steps like *Windows key + R, Ctrl + V* together with Run/PowerShell/Terminal, or commands such as `powershell -enc`, `mshta https://…`, `iex(`, `curl … \| sh` |
| HTML/SVG attachment that copies a command to your clipboard | Critical | 35 | `navigator.clipboard.writeText` or `execCommand('copy')` with PowerShell, mshta or cmd |
| Password-protected archive with its password in the email | Critical | 30 | A locked ZIP (so scanners can't look inside) plus "Password: 4471" in the subject or body |

---

## Sender history

Source: [`analyzers/history.ts`](../extension/src/analyzers/history.ts). Unmask remembers, in this browser only, which addresses have emailed you, how often and since when. High-risk emails and emails opened from files are never learned. You can turn this off or forget everything in Settings → Privacy.

| Check | Severity | Points |
|---|---|---|
| "Your PayPal emails usually come from paypal.com": the email claims a brand (display name or look-alike domain) that normally emails you from another domain | High | 25 |
| Uses the display name of a contact you've had 2+ emails from, from a different address and domain | High | 25, or 30 from webmail |
| "You've never received mail from example.xyz": first email from both this address and its domain | Low (Medium with another sender problem) | 5 (10) |
| First email from this address, but you know the domain | Note | 0 |
| You've had 3+ emails from this sender | Good | −5 |
| **Fingerprint changed:** a sender you've had 3+ emails from asks, for the first time, for replies to go to another domain | Medium | 15 |
| Fingerprint changed: a sender who always signed their emails sent one without a signature, or two or more traits changed | Medium | 12 |
| Fingerprint changed: one trait (delivering mail service, Message-ID domain, mail program) | Low | 4 |

**Fingerprints.** For every sender, Unmask remembers how their emails are usually built: the DKIM signing domain, the mail service that handed them to your provider, the Message-ID domain, the mail program, and any Reply-To domain. Analysts compare a suspicious email with a known-good one from the same sender; this does it automatically, but only for traits that were consistent in at least 75% of earlier emails. Emails without real headers (Outlook's page view) are not used. Source: [`analyzers/fingerprint.ts`](../extension/src/analyzers/fingerprint.ts).

First-contact warnings start once Unmask knows 10 senders, so a new install doesn't flag everyone.

---

## Your protection list

Source: [`analyzers/protection.ts`](../extension/src/analyzers/protection.ts). Only runs for entries you add in Settings.

| Check | Severity | Points |
|---|---|---|
| Uses the name of a protected person from an address not on their list | Critical | 40 |
| Sender domain imitates a protected company (look-alike, typo, brand inside the domain) | Critical | 40 |
| A link goes to a look-alike of a protected company | Critical | 40 |
| Names a protected company in the sender name or subject but comes from another domain | Critical | 35 |
| Uses a trusted address, but fails authentication | High | 25 |
| Trusted sender, verified by DMARC or a DKIM signature from their domain | Good | −10, and no first-contact warning |
| Trusted sender, but the email has no authentication results to verify | Note | 0 |

---

## Plain words

Source: [`core/plain.ts`](../extension/src/core/plain.ts). The plain-words card and banner sentence are built only from the findings above: the verdict picks the headline ("This email looks like a scam." / "Be careful with this email." / "Nothing looks wrong with this email."), and the most serious findings, one per problem, become up to three everyday reasons. They add no points of their own.

---

## Payment fraud (BEC)

Source: [`analyzers/bec.ts`](../extension/src/analyzers/bec.ts). Business email compromise needs no link or file, only a convincing request.

| Check | Severity | Points |
|---|---|---|
| Says bank or payment details have changed | High | 25 |
| Asks you to buy gift cards or send card codes | High | 22 |
| A money request plus replies going elsewhere, a webmail sender, or a secrecy opener | High | 15 |
| Asks for a payment, wire or transfer; mentions IBAN, SWIFT, routing numbers | Medium | 10 |
| "Are you available?", "keep this confidential", "I'm in a meeting" | Medium with a money request (10), otherwise Low (3) | |

---

## QR codes

Source: [`analyzers/qr.ts`](../extension/src/analyzers/qr.ts). QR codes are decoded on your computer from image attachments, inline and embedded (`data:`) images, and images inside PDFs. Remote images are not downloaded.

| Check | Severity | Points |
|---|---|---|
| Contains a QR code that opens a website | Medium | 10 |
| Contains a QR code with other content (Wi-Fi, phone, text) | Note | 0 |

Each decoded link is also put through every [link check](#links), so a QR code pointing at a look-alike domain gets that finding too.

---

## Fake brand logos

Source: [`analyzers/logos.ts`](../extension/src/analyzers/logos.ts). Flags an email that shows a brand's logo but wasn't sent from that brand's domain. Signals, none of which download anything:

- the image is loaded from the brand's own asset host (for example `paypalobjects.com`)
- its alt text, title or file name names the brand
- an embedded image's perceptual fingerprint (dHash) matches the brand's logo; fingerprints for 42 brands are generated from [simple-icons](https://simpleicons.org) by `pnpm --filter unmask-extension logos`

Logos that link to the brand itself (social icons, app-store badges) are ignored.

| Check | Severity | Points |
|---|---|---|
| Brand logo, and the email also claims to be the brand, or the pixels match, or two signals agree | High | 20 |
| One signal only | Medium | 8 |

---

## Privacy and tracking

Source: [`analyzers/trackers.ts`](../extension/src/analyzers/trackers.ts). These are **privacy notes worth 0 points**: tracking is normal for newsletters and isn't phishing.

- **Tracking pixels:** remote images 3×3 pixels or smaller, hidden or transparent images, images at tracking paths (`/open`, `/wf/open`, `/pixel`, …), and CSS background images from tracking addresses.
- **Click-tracked links:** links routed through a known tracking service.
- **Where each pixel is:** its number, image position ("image 2 of 2"), how far through the visible text it sits, the words just before and after it, whether it's inside a hidden block, its size and its full address. The Body tab's safe view tags each pixel's spot, and pixels are never loaded there, even when other remote images are. Source: [`analyzers/trackers.ts`](../extension/src/analyzers/trackers.ts).
- **Services recognized (~40):** Mailchimp, SendGrid, HubSpot, Mailtrack, Mixmax, Yesware, Streak, Superhuman, Bananatag, ContactMonkey, Boomerang, Mailgun, SparkPost, Amazon SES, Postmark, Salesforce Marketing Cloud, Klaviyo, Campaign Monitor, Constant Contact, Customer.io, Intercom, Iterable, Braze, Mailjet, Brevo, Kit, Substack, beehiiv, MailerLite, GetResponse, ActiveCampaign, Marketo, Oracle Eloqua, Zoho Campaigns, Omnisend, Drip, Google Analytics, Google Ads, Meta Pixel, LinkedIn Ads.

---

## Online checks

These run only when you click them, except domain age and domain intelligence, which run automatically and can be turned off in Settings.

| Check | Sends | Finding |
|---|---|---|
| **Domain age** (rdap.org) | The sender's domain name | See [Sender identity](#sender-identity) |
| **VirusTotal: file** | The file's SHA-256 hash | 3+ engines: Critical 40 · 1–2: High 20 · clean or unknown: Note 0 |
| **VirusTotal: upload** (after confirmation) | The file itself | Same as above |
| **VirusTotal: link** | The link | 3+ engines: Critical 40 · 1–2: High 20 |
| **urlscan.io sandbox scan** | The link | urlscan says malicious: Critical 40, plus the final page, a screenshot and any brand it impersonates |
| **Redirect trace** (your server) | The link | The redirect chain (informational) |
| **First TLS certificate** (crt.sh) | The sender's domain and up to 3 link domains | First certificate in the last 7 days: High 20 · last 30 days: Medium 10 · a link domain that never had one: Low 4 |
| **Mail records** (dns.google) | The sender's domain | No mail server and no website: Medium 12 · no MX: Medium 8 · missing SPF/DMARC: Low 2 each |
| **How hard the domain is to fake** (dns.google, same lookup) | The sender's domain | SPF `+all` (anyone may send): Medium 10 · SPF `?all`: Low 3 · DMARC `p=none` on an email that didn't pass: Low 4 · certified BIMI logo with enforced DMARC, and this email passed: Good −3 |
| **Who runs the sending server** (dns.google; off by default) | The IP of the server that delivered the email to your provider | Home or mobile connection (`dynamic`, `dsl`, `pool`, `cable`… in its DNS name): Medium 10 · rented-server network (DigitalOcean, Hetzner, Contabo, Vultr, OVH, M247…): Medium 8 when it claims a brand, otherwise Low 3 · DNS name doesn't resolve back to the IP: Low 3. The network and country are shown on the Headers tab |
| **DKIM signature check** (dns.google) | Each signing key's DNS name (`selector._domainkey.domain`) | Headers changed after signing: Medium 12 · signature names a brand key that doesn't exist: Medium 12 (other domains Low 4) · key withdrawn: Low 5 · key under 1024 bits: Low 5 · key in test mode: Low 2 · verified and aligned with From: Good −5 |

Well-known brands and webmail providers are skipped for the automatic lookups.

---

## Warnings inside Gmail and Outlook

Source: [`lib/gmailProtect.ts`](../extension/src/lib/gmailProtect.ts), [`lib/protect.ts`](../extension/src/lib/protect.ts). Each can be turned off in Settings → Protection inside Gmail.

- **Banner** above emails rated Suspicious or High risk, with the top three reasons.
- **Inbox badges** next to risky senders: from the verdict of a conversation you already opened, or a quick check of the sender line (display-name tricks, look-alike domains, brand claims, sender history).
- **"Wait, this link goes to …"** before a link opens when the link has a High/Critical flag, has a Medium flag in a suspicious email, or leaves the sender's domain in a high-risk email.
- **Reply warning** when Reply would send your answer to an address on another domain.
- **Peek** (Gmail): a button on each inbox row downloads that email's source and runs every check above without opening it, showing a text-only preview. Optionally, up to 15 unread rows per list are checked automatically.

In **Outlook on the web** Unmask reads the email from the page, because Outlook doesn't give pages the original source. Header checks (SPF, DKIM, DMARC, delivery path) need … → View → View message source pasted into the panel.
