# Free limits and costs

**Short version: Unmask is free, and so is everything it uses by default.** The optional online checks use free accounts with daily limits. **A free key can never cost you money.** If you go over a limit, the service simply refuses the request until the quota resets, and Unmask tells you so.

_Prices and limits checked on 19 October 2026 against each provider's official page. Providers change them; follow the links for the current numbers._

| | Cost | Free limit | What happens if you go over |
|---|---|---|---|
| **Unmask itself** (all local checks) | Free, open source (MIT) | Unlimited | — |
| **Domain age** (rdap.org) | Free, no account | No published quota; 1 lookup per email you open | Rarely, a registry may refuse a lookup; Unmask shows "RDAP returned HTTP 429" and carries on |
| **VirusTotal** (files and links) | Free account | **4 lookups per minute, 500 per day** (about 15,500 per month) | "VirusTotal rate limit reached"; try again in a minute, or after 00:00 UTC for the daily limit. No charge. |
| **urlscan.io** (sandbox scans) | Free account | **5,000 public, 1,000 unlisted and 50 private scans per day**, 10,000 result lookups per day | "urlscan.io rate limit reached"; try again later. No charge. |
| **Redirect-trace server** (optional, self-hosted) | Free on your computer; free on Vercel Hobby | Vercel Hobby: 1M requests and 4 hours of active CPU per month | Hobby projects stop at the cap. They can't buy more, so there's no surprise bill. |

## How much will I actually use?

Every check except domain age runs **only when you click its button**.

| You check… | VirusTotal lookups | urlscan scans |
|---|---|---|
| One attachment | 1 | — |
| One link with **VirusTotal** | 1 | — |
| One link with **Sandbox scan** | — | 1 scan + a few result lookups |
| Saving a key with **Save & test** | 1 | 0 (uses the quota endpoint) |

Even checking 20 suspicious emails a day with every button stays far under the free limits. The one you might notice is VirusTotal's **4 per minute**: clicking five checks in a row will make the fifth wait a minute.

## VirusTotal

- **Free (Public API):** 4 requests/minute, 500/day; a VirusTotal staff member puts the monthly figure at about 15,500. Quotas reset daily at 00:00 UTC.
- **Rules for the free API:** it must not be used in commercial products or services, or in business workflows that don't contribute new files, and you may not register several accounts to get around the limits. Using **your own key, for yourself**, in a free open-source tool like Unmask is the intended personal use. **If you use Unmask at work** (for example, a security team checking reported emails), your organization needs a VirusTotal Premium licence.
- **Premium:** higher limits under a commercial licence. VirusTotal doesn't publish prices; you request a quote from their sales team.
- **Uploading files** counts against the same quota, and uploaded files become available to VirusTotal's Premium customers. Unmask asks before every upload.
- Official sources: [Public vs Premium API](https://docs.virustotal.com/reference/public-vs-premium-api), [API errors](https://docs.virustotal.com/reference/errors).

## urlscan.io

| Plan | Price | Private scans/day | Unlisted scans/day | Public scans/day | Result lookups/day |
|---|---|---|---|---|---|
| **Free** | $0 | 50 | 1,000 | 5,000 | 10,000 |
| Automate | $5,000/year (annual only) | 2,500 | 5,000 | 10,000 | 25,000 |
| Professional | $1,250/month or $12,500/year | 20,000 | 40,000 | 50,000 | 150,000 |
| Enterprise | $2,500/month or $25,000/year | 100,000 | 100,000 | 150,000 | 500,000 |
| Ultimate | $5,000/month or $50,000/year | 200,000 | 200,000 | 300,000 | 1,000,000 |

Prices exclude taxes. For personal use, **Free is all you need**.

**Visibility**, set in Unmask's Settings:
- **Unlisted** (Unmask's default): hidden from urlscan's public feed and search, visible to urlscan's vetted security partners. 1,000 per day free.
- **Private:** visible only to you. 50 per day free. Choose this if links might contain personal tokens, such as password-reset links.
- **Public:** anyone can find the scan. Don't use this for links from your own email.

Official source: [urlscan.io pricing](https://urlscan.io/pricing/).

## Domain age (RDAP)

rdap.org is a free public service that forwards each lookup to the official registry for that domain ending (for example Verisign for `.com`). There is no account and no published quota. Unmask makes **one lookup per email**, only for the sender's domain, and you can turn it off in **Settings → Privacy**.

## Redirect-trace server

Optional and for technical users ([BACKEND.md](BACKEND.md)).

- **On your own computer** (`pnpm backend`): free, no limits beyond your machine.
- **On Vercel Hobby:** free for personal, non-commercial use, including 1M function invocations, 4 hours of active CPU and 360 GB-hours of memory per month. Each trace is one invocation lasting a few seconds at most. Hobby accounts **can't buy extra usage**, so you're never billed; the project stops when it hits the cap.
- **On Vercel Pro:** $20/month including $20 of usage, then pay-as-you-go (for example $0.60 per extra million invocations, $0.128 per extra hour of active CPU). Only needed for a team or commercial deployment.
- The server has its own rate limit (30 traces per minute per IP by default, `UNMASK_RATE_LIMIT`).

Official source: [Vercel pricing](https://vercel.com/pricing).

## What Unmask does when a limit is hit

- The button shows a plain message such as *"VirusTotal rate limit reached (free keys allow 4 lookups per minute). Try again shortly."*
- Nothing is retried in a loop, so a hit limit can't snowball.
- All local checks keep working: the risk score never depends on an online service.
