# Investigation reports

When an email is serious, someone has to act on it: a manager decides, a security team investigates, a bank or a regulator may need the details. Unmask builds **one report with two audiences**, in the format each of them expects.

<p align="center">
  <img src="images/panel-report-formats.png" width="340" alt="The Report or export card: choose Complete, Executive only or Technical only, then PDF, Word, HTML or STIX">
</p>

Open the **Summary** tab, scroll to **Report or export**, choose who the report is for and click a format. Everything is built on your computer; nothing is uploaded.

## Who it is for

| Choice | What you get |
|---|---|
| **Complete** | Part A (executive) followed by Part B (technical) and the appendices |
| **Executive only** | A few pages in plain language for managers, leaders and non-technical staff |
| **Technical only** | The full evidence for security analysts, incident responders and investigators |

### Part A: Executive summary

Plain language, no technical background needed.

1. **Summary**: the verdict, what to do, and a table of the key facts.
2. **What happened**: who the email appeared to be from, what kind of attack it is and the main reasons.
3. **Why it matters to the organisation**: stolen passwords, malware, financial loss, phone scams, silent account access, trust damage, each with what could happen and how serious.
4. **What to do now**: for everyone; for anyone who already clicked, opened or replied; for IT and security; for finance and management.
5. **Who to tell**: internal security first, then APWG, Netcraft, Google Safe Browsing and national reporting channels (US, UK, India and a pointer for elsewhere).
6. **How sure are we**: the confidence and what could not be checked.

### Part B: Technical analysis

For the people who investigate.

| Section | Contents |
|---|---|
| Case information | Case ID, analyst, organisation, TLP, tool version, **SHA-256 of the original `.eml`** when available, chain-of-custody note |
| Verdict and scoring | Score by category, the assessed attack types with their evidence |
| Message and sender | Every identity header, display-name and look-alike findings |
| Authentication | SPF, DKIM, DMARC, ARC, a DKIM signature table (selector, algorithm, key size, body-hash result, signing time) |
| Delivery path | Hop table: server, IP, time, delay, whether your provider wrote it |
| Content | Hidden text, QR codes, tracking pixels with their position |
| Link analysis | Shown text versus real destination, source, findings |
| **Attachment and file forensics** | Hashes, entropy, structural findings with **MITRE ATT&CK** ids, the `pdfid`-style table, JavaScript, macros, embedded files, links and indicators inside each file |
| Threat-intelligence lookups | Whatever lookups you ran (VirusTotal, Hybrid Analysis, MalwareBazaar, urlscan.io, URLhaus, PhishTank) |
| MITRE ATT&CK mapping | Technique, name and the evidence for it |
| Timeline | Email date, signing time, every hop |
| Indicators of compromise | Senders, domains, URLs, IPs, programs, commands, file names, hashes: **defanged** |
| Detection and hunting | Ready-to-paste queries for Microsoft Defender/Sentinel (KQL) and Google Workspace search |
| Containment checklist | Preserve, scope, purge, block, reset, report, close |
| Method and references | What was checked, what was not, references and credits |
| Appendices | All findings, all headers, a glossary |

## Formats

| Format | Best for |
|---|---|
| **PDF** | Sharing with leaders, auditors, banks and authorities. A cover page, a contents page with page numbers, bordered tables, coloured call-outs |
| **Word** (`.docx`) | Editing: real headings (the navigation pane works), tables with repeating headers, a page-numbered footer. Opens in Word, LibreOffice and Google Docs |
| **HTML** | One self-contained file with no scripts and no network use. Prints cleanly to PDF from any browser |
| **STIX 2.1** | Threat-intelligence platforms (MISP, OpenCTI, Sentinel, Splunk ES): a bundle with the report, indicators with exact values, ATT&CK patterns, the observed email and a TLP marking. A clear verdict exports no indicators, so nothing harmless can reach a block list |
| **JSON** | Everything Unmask knows, for your own tooling |
| **Original `.eml`** | The evidence itself. Its hash is recorded in the report |

<p align="center">
  <img src="images/report-pdf-cover.png" width="300" alt="PDF report cover with verdict, case ID and TLP marking">
  &nbsp;
  <img src="images/report-pdf-summary.png" width="300" alt="PDF executive summary page">
</p>
<p align="center">
  <img src="images/report-executive.png" width="420" alt="HTML report: executive summary">
  &nbsp;
  <img src="images/report-technical.png" width="420" alt="HTML report: attachment and file forensics">
</p>

## Safe to share

- **Indicators are defanged** (`hxxps://evil[.]example`, `name[@]example[.]com`) so nobody clicks them by accident. STIX and JSON carry exact values for tools.
- **Case details** (case or ticket ID, analyst, organisation, TLP, notes) are optional. The analyst, organisation and TLP are remembered on this computer for next time; the case ID and notes are not.
- The report says plainly that the analysis ran on the analyst's own computer.
- **Classification (TLP)** is printed on the cover and every page footer, and written into the STIX markings.

See [Privacy](../PRIVACY.md) for what is, and is never, sent anywhere.

## Real examples
These reports were built by Unmask from **real phishing emails** in the public [phishing_pot](https://github.com/rf-peixoto/phishing_pot) research collection. Nothing was staged: each email was analysed exactly as it arrived, and the report was exported with the standard **Complete** option. Only the analysis is published: the original emails are not redistributed, and every indicator is defanged so the reports are safe to open.

Each report has **Part A**, a plain-language summary for leaders and non-technical staff, and **Part B**, the full technical analysis for security teams. Open the HTML version in your browser or download the PDF.

> **Tested on 400 real phishing emails from this collection: 346 caught (86.5%), 285 of them rated High risk, no failures.** See [how that was measured](../CONTRIBUTING.md).

### 1. A fake Binance "withdrawal successful" email

**High risk, 81 out of 100.** A message pretending to be Binance announces a withdrawal and offers a "Cancel this transaction" button: the classic panic lure.

What Unmask found, in the report's own words:

- It claims to be **Binance but is not sent from Binance's domain** (it comes from `auswestbc[.]com[.]au`), yet shows the real Binance logo, loaded from Binance's servers.
- It was **sent by a script (PHPMailer)**, not by a company mail system.
- The whole message is **one clickable picture** with almost no text, so spam filters cannot read it, plus 602 characters of hidden text.
- The **Cancel Transaction** links go to a different website from `binance.com`.
- A genuine **DKIM signature from the mailing service passes**, which is why a simple check would have trusted it. Unmask notices it is signed by a different domain than the From address.

<p align="center">
  <img src="images/example-binance-withdrawal-executive.png" width="470" alt="Executive part of the report for the fake Binance email">
  &nbsp;
  <img src="images/example-binance-withdrawal-technical.png" width="470" alt="Technical part: link table, ATT&CK mapping and timeline">
</p>

**[Open the HTML report](https://praneeth132006.github.io/Unmask/examples/binance-withdrawal.html)** · **[Download the PDF](examples/binance-withdrawal.pdf)**

### 2. A fake COLDCARD "security advisory"

**High risk, 60 out of 100.** An email in the name of a hardware-wallet maker tells owners to book a "10-minute call" through a link to collect a "refund". It passes DMARC, because the scammers own the look-alike domain.

- The **sender domain imitates the brand** (`coldcardblog[.]org` contains "coldcard" but is not theirs), and so does the **link domain** (`book.coinkiteadvisory[.]com`).
- The display name uses the brand, and the text pushes urgency ("as soon as possible").
- Unmask points out that **DMARC passing proves nothing here**: scammers can pass it on domains they control.

This email was missed before this release. Reading it showed that hardware-wallet makers were not on the brand list, so Coinkite/COLDCARD, Ledger, Trezor and Kraken were added.

<p align="center">
  <img src="images/example-coldcard-advisory-executive.png" width="470" alt="Executive part of the report for the fake COLDCARD advisory">
</p>

**[Open the HTML report](https://praneeth132006.github.io/Unmask/examples/coldcard-advisory.html)** · **[Download the PDF](examples/coldcard-advisory.pdf)**

### 3. A fake Efteling gift-card survey

**High risk, 59 out of 100.** A Dutch email in the name of a theme park offers a gift card for "confirming your participation".

- A link **shows `www.efteling.com` but really goes to another website**, and **23 links are not even encrypted** (`http://`).
- **Replies go to a different address** from the one the email came from.
- The sender name is written with **look-alike mathematical letters** to dodge filters, the domain has **no SPF protection** and the email is **not DKIM-signed**.
- It carries **41 tracking pixels**, which tell the sender when and where it is opened.

<p align="center">
  <img src="images/example-efteling-giftcard-executive.png" width="470" alt="Executive part of the report for the fake Efteling email">
</p>

**[Open the HTML report](https://praneeth132006.github.io/Unmask/examples/efteling-giftcard.html)** · **[Download the PDF](examples/efteling-giftcard.pdf)**

### What these show

- A single scam email is judged on **many independent signals** at once, so one clever trick (a passing signature, a real logo) does not hide it.
- Each report lets **a manager decide** what to do in two minutes, and gives **an analyst** everything needed to investigate: authentication, delivery path, links, MITRE ATT&CK techniques, defanged indicators and hunting queries.
- Reports are built **entirely on your computer**. Nothing is uploaded.

To build one yourself, install Unmask and use **Report or export** on any email.

*Source of the sample emails: the phishing_pot collection by rf-peixoto, a research dataset for developers of detection tools. Unmask is not affiliated with it, and the original messages are not included here.*
