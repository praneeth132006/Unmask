# Why Unmask asks for each permission

A security tool should be the easiest extension to audit. This page lists every permission in Unmask's manifest, what it is used for, what it would technically allow, and why nothing narrower works. The manifest is built from [`extension/wxt.config.ts`](../extension/wxt.config.ts); you can read the real one in any installed copy (see [Check it yourself](#check-it-yourself)).

## Always granted

| Permission | Used for | What it could technically allow | Why not narrower |
|---|---|---|---|
| `https://mail.google.com/*` | Seeing which email is open, downloading its original source (headers included) for the checks, showing banners, badges, Peek and the "Wait, this link goes to…" warning inside Gmail | Reading and changing Gmail pages | This is the narrowest scope that covers Gmail. Unmask's content script only reads the messages you open or that are listed in your inbox, and nothing leaves your computer |
| Outlook on the web: `outlook.live.com`, `outlook.office.com`, `outlook.office365.com`, `outlook.cloud.microsoft` | The same as Gmail, in Outlook on the web (declared through the content script's match list) | Reading and changing those Outlook pages | Microsoft serves Outlook from these four hosts; each is needed for a different kind of account |
| `https://*.googleusercontent.com/*` | Gmail's "Download original" redirects to this Google host, so the email's source can be read | Requests to Google's content host | Gmail picks the exact subdomain per download, so a wildcard on this one Google domain is needed |
| `https://crt.sh/*`, `https://dns.google/*` | Certificate history and mail DNS records for the sender's domain and up to three link domains (only domain names are sent; can be turned off in Settings) | Requests to those two services | Only the two services used are listed |
| `https://www.virustotal.com/*`, `https://urlscan.io/*` | The VirusTotal and urlscan.io buttons, with your own API key, only when you click them | Requests to those two services | Only the two services used are listed |
| `storage` | Your settings, the protection list, the sender history, recent verdicts and the weekly counts, all in this browser | Storing data in the extension's own storage | There is no narrower way to keep settings |
| `tabs` | Knowing whether the active tab is Gmail or Outlook so the panel can follow it, reloading that tab when you click **Reload Gmail**, and opening the welcome, practice and report pages | Seeing the address and title of your tabs | The side panel has to know which email tab is in front. Unmask never records your browsing |
| `webRequest` | **Trace redirects** only: watching the redirect steps of Unmask's own background request for the link you chose | Observing network requests (not changing them) | Browsers hide HTTP redirects from `fetch`; this is the only way to show each step. Without the optional all-sites access it sees nothing outside the hosts above; with it, every event that isn't Unmask's own trace request is ignored, and nothing is stored |
| `offscreen` (Chrome and Edge) | A hidden extension page that reads an email's HTML if Gmail ever blocks HTML parsing inside its own page | Running an extension page with no window | Chrome's background worker has no HTML parser. The page only analyses the email you opened, on your computer |
| `sidePanel` (Chrome and Edge; Firefox uses its sidebar) | Showing the Unmask panel next to your inbox | A side panel | Required to show a panel at all |

## Asked for only when you click

Each of these is optional: the browser shows its own prompt the first time, you can say no, and everything else keeps working.

| Asked for | When | Used for |
|---|---|---|
| Access to all sites (`<all_urls>`) | The first time you click **Trace redirects** with the built-in tracer | Contacting the link's own website and each site it redirects to, from the background, with no cookies and never in a tab. Not needed if you use your own trace server |
| `docs.google.com`, `drive.google.com` | **Look inside** a shared Google Doc, Sheet, Slides or Drive file | Downloading the public copy anonymously, to read it on your computer |
| `checkurl.phishtank.com`, `urlhaus-api.abuse.ch` | **Check phishing lists** on a link | Asking PhishTank and URLhaus about that one link |
| `www.hybrid-analysis.com`, `mb-api.abuse.ch` | A Hybrid Analysis or MalwareBazaar button on the Documents tab | Sending that file's SHA-256 hash (never the file) |

## What Unmask never asks for

- **Your history, bookmarks, downloads, cookies or passwords.**
- **`scripting` or broad content scripts.** Unmask runs only on Gmail and Outlook on the web.
- **`declarativeNetRequest` or request blocking.** Unmask never changes or redirects your traffic.
- **`identity`, `management`, `nativeMessaging`, `debugger`.**
- **Data collection.** Firefox's manifest declares `data_collection_permissions: none`: nothing is sent to the developer, and there is no Unmask server. What is sent to outside services, and when, is listed in the [privacy policy](../PRIVACY.md#what-is-sent-and-only-when).

## Check it yourself

- **Chrome or Edge:** open `chrome://extensions`, find Unmask and click **Details**: *Site access* and *Permissions* list exactly what is granted. To read the manifest, turn on Developer mode; the extension ID links to its files.
- **Firefox:** `about:addons` → Unmask → **Permissions**.
- **From the source:** `pnpm build` writes `build/unmask-chrome/manifest.json`, and the [reproducible-build check](../CONTRIBUTING.md#verify-a-release-yourself) shows that the published zip is built from this code.
