# Unmask privacy policy

_Last updated: 19 October 2026_

Unmask is a browser extension that analyses emails for signs of phishing. It is designed so your email content stays on your computer.

## What stays on your device

- **Highlighting.** When you hover a finding, Unmask adds a temporary outline to the email in your Gmail tab and removes it when you move away. Nothing is sent anywhere.
- **Tracker detection.** Tracking pixels are found by reading the email's HTML locally. Unmask never loads them.
- **Email content.** When you open an email in Gmail, Unmask downloads that email's raw source from Gmail (using your existing Gmail session in the same tab) and analyses it inside the extension. The email's headers, body and attachments are never sent to the Unmask developers or to any Unmask server.
- **Settings and API keys** you enter are stored in your browser's extension storage (`chrome.storage.local`) and never leave your device except as described below.

## What is sent, and only when

| Data | Sent to | When |
|---|---|---|
| The sender's domain name (e.g. `example.com`) | rdap.org and the domain's registry | Automatically when an email is analysed, unless you turn off "Check how old the sender's domain is" in Settings, or when you click **Check domain age** |
| A request to the link itself (no cookies, never opened in a tab) | The link's website, and each site it redirects to | Only when you click **Trace redirects** (built-in tracing). The sites see your IP address, as with any visit |
| One link's URL | Your own trace server | Only if you chose **My own server** in Settings and click **Trace redirects** |
| Your API key, to check it works | VirusTotal or urlscan.io | When you click **Save & test** while setting up a key |
| One link's URL | urlscan.io, using your API key | Only when you click **Sandbox scan** on that link |
| One link's URL | VirusTotal, using your API key | Only when you click **VirusTotal** on that link |
| An attachment's SHA-256 hash | VirusTotal, using your API key | Only when you click **Check on VirusTotal** |
| An attachment file | VirusTotal, using your API key | Only when you click **Upload file…** and then confirm a warning. Files uploaded to VirusTotal may be shared with its customers. |

These third-party services have their own privacy policies:
[VirusTotal](https://docs.virustotal.com/docs/privacy-policy), [urlscan.io](https://urlscan.io/about/privacy/), [rdap.org](https://about.rdap.org/).

## The redirect-trace backend

If you run or deploy the open-source backend in this repository, it receives one URL per request, follows its redirects, returns the result, and does not log or store the URL. If you point Unmask at someone else's backend, their policy applies.

## Permissions

- `https://mail.google.com/*`: to detect the open email, download its original source, and outline the part of the email a finding refers to when you hover it.
- `https://*.googleusercontent.com/*`: Gmail's "Download original" link redirects to this Google host.
- `https://www.virustotal.com/*`, `https://urlscan.io/*`: to call those services when you click their buttons.
- `storage`: to save your settings.
- `tabs`: to know whether the active tab is Gmail.
- `webRequest` and the **optional** permission to access all sites: used only by **Trace redirects**, to see each redirect step of Unmask's own background request. Chrome asks for it the first time you trace a link; Unmask never reads or changes your browsing.
- `sidePanel`: to show the Unmask panel.

## No tracking

Unmask has no analytics, no advertising, and no accounts. It does not sell or share data.

## Contact

Open an issue at https://github.com/praneeth132006/Unmask/issues.
