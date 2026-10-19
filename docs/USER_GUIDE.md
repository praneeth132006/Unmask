# Unmask user guide

This guide is for everyone, no technical background needed. It covers installing Unmask, reading its report, setting up the optional checks, and fixing common problems.

- [1. Install](#1-install)
- [2. Your first check](#2-your-first-check)
- [3. Reading the report](#3-reading-the-report)
- [4. Hover to see it in the email](#4-hover-to-see-it-in-the-email)
- [5. Setting up VirusTotal](#5-setting-up-virustotal)
- [6. Setting up urlscan.io](#6-setting-up-urlscanio)
- [7. Redirect tracing (advanced)](#7-redirect-tracing-advanced)
- [8. Emails from Outlook and other apps](#8-emails-from-outlook-and-other-apps)
- [9. Settings](#9-settings)
- [10. Troubleshooting](#10-troubleshooting)
- [11. FAQ](#11-faq)

---

## 1. Install

Unmask isn't on the Chrome Web Store yet, so it's installed as a "developer" extension. You only do this once. Pick **Option 1** unless you want to build Unmask yourself.

### 1a. Option 1: No-code install (recommended)

No programming tools needed.

1. Open the [latest Unmask release](https://github.com/praneeth132006/Unmask/releases/latest).
2. Under **Assets**, click **`unmask-chrome-0.2.0.zip`** to download it.
3. Unzip it: double-click the file on a Mac, or right-click → **Extract All** on Windows. You get a folder named **`unmask-chrome-0.2.0`**.
4. Move that folder somewhere permanent, such as your Documents folder. Chrome loads Unmask from it, so don't delete it.

Now [load it into Chrome](#1c-load-it-into-chrome).

### 1b. Option 2: Build from source

You need [Node.js](https://nodejs.org) (version 20 or newer) and [pnpm](https://pnpm.io/installation). In a terminal:

```bash
git clone https://github.com/praneeth132006/Unmask.git
cd Unmask
pnpm install
pnpm build
```

This creates the folder **`build/unmask-chrome`**. That folder *is* the extension.

### 1c. Load it into Chrome

1. In Chrome's address bar, type `chrome://extensions` and press Enter.
   *(This is Chrome's own settings page, not the Chrome Web Store.)*
2. Turn on **Developer mode** with the switch in the **top-right corner**.
3. Three buttons appear on the left. Click **Load unpacked**.
4. Select the extension folder and click **Select**:
   - Option 1: the unzipped **`unmask-chrome-0.2.0`** folder.
   - Option 2: open the project folder, open **`build`**, and click **`unmask-chrome`** once.
5. Unmask appears in your list of extensions.
6. Click the **puzzle-piece icon** in Chrome's toolbar and click the **pin** next to Unmask so its icon is always visible.

> Edge and Brave work the same way: use `edge://extensions` or `brave://extensions`.

### 1d. Reload Gmail

If Gmail was already open, **reload the Gmail tab** (press ⌘R or Ctrl+R). Unmask can only connect to Gmail pages opened after it was installed.

### Updating

- **Option 1:** download the newer zip from the [latest release](https://github.com/praneeth132006/Unmask/releases/latest) and unzip it. Replace everything inside your existing Unmask folder with the new files (keep the same folder, so Chrome keeps your settings and API keys), then click the **↻ reload** button on the Unmask card in `chrome://extensions`.
- **Option 2:** after pulling new code and running `pnpm build` again, click the **↻ reload** button on the Unmask card.

Then reload Gmail.

---

## 2. Your first check

1. Open Gmail and open any email.
2. Click the **Unmask icon** in the toolbar. A side panel opens on the right.
3. Unmask reads the email and shows its report within a second or two.

When you open a different email, the panel follows automatically. In a conversation with several messages, a menu at the top lets you pick which message to inspect.

---

## 3. Reading the report

### The summary

<img src="images/overview-light.png" width="300" align="right" alt="Summary tab">

At the top is the **verdict**:

| Verdict | Score | What to do |
|---|---|---|
| 🔴 **High risk** | 50 to 100 | Strong signs of phishing. Don't click links, open attachments or reply. |
| 🟠 **Suspicious** | 20 to 49 | Some warning signs. Check with the sender another way, for example by calling them, before acting. |
| 🟢 **No red flags found** | 0 to 19 | Nothing obviously wrong. That's not a guarantee, so stay careful. |

Below it, four **summary chips** give the state of the sender, links, files and trackers at a glance. Click a chip to open that section.

Then come the findings:

- **Red flags**: problems, worst first. Each one says what's wrong in plain words.
- **Good signs**: things that check out, such as a verified sender.
- **Notes**: neutral information, such as how old the sender's domain is.

> Unmask never says an email is "safe". A clean result means the checks found nothing, not that nothing is there.

<br clear="right">

### The tabs

The row under the Unmask logo stays visible while you scroll. A **red dot** on a tab means it contains a warning. Every tab has a **Back to summary** button that returns you to where you were.

| Tab | What it shows |
|---|---|
| **Summary** | Verdict, summary chips and all findings |
| **Sender** | Who really sent the email: the real address, where replies go, how old the domain is, and SPF/DKIM/DMARC results explained in plain language |
| **Links** | Each link: the text you see, where it **really** goes (with the real website in bold), warnings, and buttons for extra checks |
| **Files** | Each attachment: type, size, fingerprint (SHA-256), warnings, and a VirusTotal check |
| **Body** | The email shown safely: scripts off, links disabled, images blocked. Switch on **Show hidden text** to see invisible text outlined in red |
| **Privacy** | Tracking pixels and click-tracked links, which company runs them, and how to avoid tracking |
| **Headers** | The path the email took to reach you, and every technical header, with a filter box |

<p>
  <img src="images/sender-light.png" width="230" alt="Sender tab">
  <img src="images/body-light.png" width="230" alt="Body tab with hidden text revealed">
  <img src="images/privacy-light.png" width="230" alt="Privacy tab">
</p>

### What the most common red flags mean

| Red flag | In plain words |
|---|---|
| *Display name shows a different email address* | The name says one address but the email came from another. A classic trick. |
| *Sender domain imitates PayPal* (or another brand) | The address looks like the real company's but has swapped letters, such as `paypa1` or a Cyrillic `а`. |
| *Failed DMARC* | The domain in the From address did not authorize this email. Spoofed emails fail this. |
| *Replies go to a different address* | If you hit Reply, your answer goes to someone else, often a free webmail account. |
| *Link text shows one website but goes to another* | The link *looks* like `paypal.com` but takes you somewhere else. |
| *Risky attachment* | A file type that can run code or open a fake login page, or a file pretending to be a PDF. |
| *Hidden text blocks* | Invisible text, often stuffed in to fool spam filters. |
| *Sender domain was registered N days ago* | Real companies use domains that are years old. New ones are a strong warning sign. |

The full list, with points, is in [CHECKS.md](CHECKS.md).

---

## 4. Hover to see it in the email

<img src="images/highlight-link.png" width="420" alt="A link outlined in the email">

**Hover over any red flag** in the Summary, and Unmask outlines the matching part of the email in Gmail, scrolling it into view if needed:

- link warnings outline the **links**,
- sender warnings outline the **sender's name**,
- attachment warnings outline the **attachment**,
- pressure-language warnings **mark the exact words**, such as "verify your account" or "within 24 hours".

<img src="images/highlight-text.png" width="420" alt="Phrases marked in the email">

Hovering a link card in the Links tab, an attachment in the Files tab, or the sender box in the Sender tab works the same way.

**Click** a red flag to jump to its details, for example the exact link card. Use **Back to summary** to return to the same spot.

> The outline only appears for emails opened in Gmail. It isn't available for `.eml` files, since there's no Gmail page to point at.

---

## 5. Setting up VirusTotal

VirusTotal checks files and links against 70+ antivirus engines. It's free. Unmask only sends a file's **fingerprint** (a SHA-256 hash), never the file itself, unless you choose to upload it.

<img src="images/setup-virustotal.png" width="300" align="right" alt="VirusTotal setup steps in the panel">

**The easy way:** click **Check on VirusTotal** on any attachment, or **VirusTotal** on any link. If no key is set up yet, the panel shows these steps right there:

1. Click **Create a free VirusTotal account** (or sign in if you have one).
2. Click **your API key page**. You can also find it by clicking your profile picture on virustotal.com, then **API key**.
3. Click the **copy icon** next to your key. It's a long string of 64 letters and numbers.
4. Paste it into the box in Unmask and click **Save & test**.

Unmask checks the key works before saving it. You'll see **"Connected to VirusTotal"**, and the check you clicked runs automatically.

> **What is an "API key"?** A password that lets an app use your VirusTotal account. It's not your account password. Unmask stores it only in your browser.

**Limits:** free keys allow 4 lookups per minute and 500 per day. That's plenty for checking emails.

**Uploading files:** if VirusTotal has never seen a file, Unmask offers **Upload file…**. Uploaded files can be downloaded by VirusTotal's paying customers, so **never upload anything confidential** such as invoices, contracts, payslips or ID documents. Unmask asks you to confirm first.

<br clear="right">

---

## 6. Setting up urlscan.io

urlscan.io opens a link in **its own** sandbox browser, never yours, and shows you a screenshot of where it lands, the final address, and whether it's known to be malicious. Free.

Click **Sandbox scan** on any link and follow the steps in the panel:

1. Click **Create a free urlscan.io account** (or sign in).
2. Click **Settings & API**, then **New API key**.
3. Copy the key, which looks like `1a2b3c4d-…` (36 characters with dashes).
4. Paste it into Unmask and click **Save & test**.

A scan takes 10 to 30 seconds. Scans are **unlisted** by default: hidden from urlscan's public feed, but visible to its security partners. You can change this in Settings.

---

## 7. Redirect tracing (advanced)

**Trace redirects** follows a link's chain of redirects (for example `bit.ly → tracker → final page`) from a small server **you run**, so your browser never opens the link. It's meant for technical users. Most people should use **Sandbox scan** instead, which shows the final page too.

To use it:

1. In the Unmask project folder, run `pnpm backend` and leave it running.
2. In Unmask, click **Trace redirects** on a link (or open **Settings → Advanced**), then click **Use local server**.

You can also deploy the server to Vercel so it's always available. See [BACKEND.md](BACKEND.md).

---

## 8. Emails from Outlook and other apps

Unmask can analyze any email, not just Gmail:

- **Drop a file:** save the email as an `.eml` file and drag it onto the Unmask panel, or click the **upload icon** at the top.
  - *Gmail:* open the email → ⋮ → **Download message**
  - *Outlook on the web:* open the email → … → **Save as** (or **Download**)
  - *Apple Mail:* File → **Save As…** → format **Raw Message Source**
  - *Thunderbird:* File → **Save As** → **File**
- **Paste the source:** click the **clipboard icon** and paste the raw email.
  - *Gmail:* ⋮ → **Show original** → **Copy to clipboard**
  - *Outlook:* … → **View** → **View message source**

To open Unmask's panel outside Gmail, click its toolbar icon on any page.

---

## 9. Settings

<img src="images/settings-light.png" width="280" align="right" alt="Settings">

Open Settings with the **gear icon**.

- **Extra checks:** each service shows **Connected** or **Not set up**, with buttons to set up, change or remove its key.
- **urlscan.io scan visibility:** unlisted (recommended), private (paid urlscan plans) or public.
- **Privacy → Check how old the sender's domain is:** on by default. It sends only the domain name (for example `example.com`) to rdap.org, the public registry lookup.
- **Advanced → Redirect tracing:** the address of your trace server.

<br clear="right">

---

## 10. Troubleshooting

**The panel says "Open Gmail to get started" even though Gmail is open.**
Click inside the Gmail tab so it's the active tab. The panel follows the tab you're looking at.

**The panel says "Reload Gmail to connect Unmask".**
Gmail was open before Unmask was installed or updated. Click **Reload Gmail** in the panel, or reload the tab.

**"Could not analyze this email".**
<img src="images/error-light.png" width="260" align="right" alt="Error box with technical details">
Click **Try again**. If it still fails, you can always analyze the email as a file: in Gmail, ⋮ → **Download message**, then drop the file on the panel. To report the problem, open **Technical details**, click **Copy details**, and include them in a [GitHub issue](https://github.com/praneeth132006/Unmask/issues). The details contain only status codes, never your email.

<br clear="right">

**The outline doesn't appear when I hover.**
Make sure the email is open in Gmail (not a downloaded file), and that the message is expanded rather than collapsed in the conversation. Some parts, such as headers and hidden text, have nothing visible to outline: click those findings instead.

**"VirusTotal says this key is not valid."**
Copy the key again from your [API key page](https://www.virustotal.com/gui/my-apikey) using the copy icon. Don't paste the page address.

**"VirusTotal rate limit reached."**
Free keys allow 4 lookups per minute. Wait a minute and try again.

**I updated the code but nothing changed.**
Run `pnpm build`, click **↻** on the Unmask card in `chrome://extensions`, then reload Gmail.

---

## 11. FAQ

**Does Unmask read all my email?**
No. It reads only the email you have open, and only while the panel is open. Nothing is stored or sent anywhere unless you click an online check.

**Does it need my Google password or Gmail access permissions?**
No. It uses Gmail's own "Show original" feature in your already signed-in tab. There's no OAuth and no Google API access.

**Why "No red flags found" instead of "Safe"?**
Because no tool can prove an email is safe. New attacks can pass every check. Unmask tells you what it found and what it didn't.

**A legitimate email got a warning. Is that a bug?**
Not necessarily. Some legitimate senders do things phishers also do, such as using link shorteners or sending from a new domain. Read the explanation and judge for yourself. If a check is clearly wrong, [open an issue](https://github.com/praneeth132006/Unmask/issues).

**Why do newsletters show trackers?**
Most marketing emails include tracking pixels so senders know who opened them. That's a privacy matter, not phishing, so trackers don't raise the risk score.

**Is it free?**
Yes, Unmask is open source under the MIT license. VirusTotal and urlscan.io have free plans.
