# Unmask privacy policy

_Last updated: 19 October 2026_

Unmask is a browser extension that analyses emails for signs of phishing. It is designed so your email content stays on your computer.

## What stays on your device

- **Highlighting.** When you hover a finding, Unmask adds a temporary outline to the email in your Gmail tab and removes it when you move away. Nothing is sent anywhere.
- **Tracker detection.** Tracking pixels are found by reading the email's HTML locally. Unmask never loads them.
- **Email content.** When you open an email in Gmail, Unmask downloads that email's raw source from Gmail (using your existing Gmail session in the same tab) and analyses it inside the extension. In Outlook on the web it reads the open email from the page instead. This happens whenever an email is opened, so the warnings inside Gmail and Outlook work without the panel. The email's headers, body and attachments are never sent to the Unmask developers or to any Unmask server.
- **Images and QR codes.** Images that are part of the email (attachments, inline and embedded images, images inside PDFs) are decoded on your computer to read QR codes and compare logos. Remote images are never downloaded.
- **Attachments.** PDFs, Office files, archives and HTML files are read as bytes to find links, macros and file lists. Nothing is opened or run.
- **Sender history.** To warn about first contact and impostors, Unmask keeps a list of the addresses and display names that have emailed you, with counts and dates, and for each sender how their emails are usually built (the signing domain, the mail service that delivered them, the Message-ID domain, the mail program and any Reply-To domain), in extension storage. It is never uploaded. Turn it off or press **Forget all** under Settings → Privacy. Emails opened from files and high-risk emails are not added.
- **Your protection list.** The companies, people and trusted senders you add are stored in extension storage and used only for checks on your computer. **Export list** saves them to a file on your computer; Unmask never sends the list anywhere.
- **Peek.** Clicking Peek, or "Check new emails before I open them" (on by default, up to 15 unread emails per list view), downloads that email's source from Gmail, using your Gmail session, exactly like opening the panel on an open email. The email is analyzed locally and only its text is shown; images and links in it are never loaded.
- **Recent verdicts.** The risk level of the last 1,000 conversations you opened is kept in extension storage so the inbox list can show badges.
- **Reports.** PDF, JSON and .eml exports are created in your browser and saved to your Downloads folder. Report buttons open Gmail's own report dialog, a compose window or a web form for you to send yourself; Unmask sends nothing.
- **Settings and API keys** you enter are stored in your browser's extension storage (`chrome.storage.local`) and never leave your device except as described below.

## What is sent, and only when

| Data | Sent to | When |
|---|---|---|
| The sender's domain name (e.g. `example.com`) | rdap.org and the domain's registry | Automatically when an email is analysed in the panel, unless you turn off "Check how old the sender's domain is" in Settings, or when you click **Check domain age** |
| The sender's domain name and up to three link domains | crt.sh (Certificate Transparency search) | Automatically when an email is analysed in the panel, unless you turn off "Check certificate history and mail records". Well-known brands and webmail providers are skipped |
| The sender's domain name | dns.google (Google Public DNS over HTTPS), to read its MX, SPF, DMARC and BIMI records | Same as above |
| The IP address of the server that delivered the email to your provider (read from the email's delivery path; never your own IP) | dns.google, for its reverse DNS name and its network owner (Team Cymru's public IP-to-ASN DNS zone) | Only if you turn on "Check who runs the sending server" in Settings. Off by default |
| The DNS name of each DKIM signing key in the email (e.g. `s1._domainkey.example.com`) | dns.google, to fetch the public key and verify the signature on your computer | Same as above |
| A request to the link itself (no cookies, never opened in a tab) | The link's website, and each site it redirects to | Only when you click **Trace redirects** (built-in tracing). The sites see your IP address, as with any visit |
| One link's URL | Your own trace server | Only if you chose **My own server** in Settings and click **Trace redirects** |
| Your API key, to check it works | VirusTotal or urlscan.io | When you click **Save & test** while setting up a key |
| One link's URL | urlscan.io, using your API key | Only when you click **Sandbox scan** on that link |
| One link's URL | VirusTotal, using your API key | Only when you click **VirusTotal** on that link |
| An attachment's SHA-256 hash | VirusTotal, using your API key | Only when you click **Check on VirusTotal** |
| An attachment file | VirusTotal, using your API key | Only when you click **Upload file…** and then confirm a warning. Files uploaded to VirusTotal may be shared with its customers. |

These third-party services have their own privacy policies:
[VirusTotal](https://docs.virustotal.com/docs/privacy-policy), [urlscan.io](https://urlscan.io/about/privacy/), [rdap.org](https://about.rdap.org/), [crt.sh](https://www.sectigo.com/privacy-policy), [Google Public DNS](https://developers.google.com/speed/public-dns/privacy).

## The redirect-trace backend

If you run or deploy the open-source backend in this repository, it receives one URL per request, follows its redirects, returns the result, and does not log or store the URL. If you point Unmask at someone else's backend, their policy applies.

## Permissions

- `https://mail.google.com/*`: to detect the open email, download its original source, show warnings inside Gmail, and outline the part of the email a finding refers to when you hover it.
- Outlook on the web (`outlook.live.com`, `outlook.office.com`, `outlook.office365.com`, `outlook.cloud.microsoft`): to read the open email from the page and show warnings inside Outlook.
- `https://crt.sh/*`, `https://dns.google/*`: for the certificate-history and mail-record checks above.
- `https://*.googleusercontent.com/*`: Gmail's "Download original" link redirects to this Google host.
- `https://www.virustotal.com/*`, `https://urlscan.io/*`: to call those services when you click their buttons.
- `storage`: to save your settings, the sender history and recent verdicts.
- `tabs`: to know whether the active tab is Gmail or Outlook, and to open report pages.
- `webRequest` and the **optional** permission to access all sites: used only by **Trace redirects**, to see each redirect step of Unmask's own background request. Chrome asks for it the first time you trace a link; Unmask never reads or changes your browsing.
- `sidePanel`: to show the Unmask panel (Firefox uses its sidebar instead).
- `offscreen` (Chrome, Edge): a hidden extension page that can read an email's HTML if Gmail ever blocks that inside the page. It only analyzes the email you opened, on your computer.

## No tracking

Unmask has no analytics, no advertising, and no accounts. It does not sell or share data.

## Contact

Open an issue at https://github.com/praneeth132006/Unmask/issues.
