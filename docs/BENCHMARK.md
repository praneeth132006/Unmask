# Benchmark: how often Unmask is right

A phishing checker is only useful if it catches phishing **and** stays quiet on real mail. Unmask is measured on both, with public corpora, on every change to `main`. The numbers below come from that run; every release attaches its own copy (`benchmark.md` and `benchmark.json`) to the [release page](https://github.com/praneeth132006/Unmask/releases).

## Latest result

| | Emails | Result |
|---|---|---|
| Real phishing ([phishing_pot](https://github.com/rf-peixoto/phishing_pot)) | 400 | **86.5% caught** (346), 286 rated High risk |
| Real legitimate email ([SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/)) | 4,150 | **6.0% false alarms** (248 rated Suspicious or High risk, 18 High risk, one of them a mailing-list post quoting a scam in full) |
| Speed | 4,550 | median 0.6 ms per email, slowest 457 ms, 0 errors |

A **false alarm** is a legitimate email rated *Suspicious* or *High risk*. A phishing email counts as **caught** when it is rated *Suspicious* or *High risk*.

## What it is measured on

- **Phishing:** the first 400 samples (by number) of [phishing_pot](https://github.com/rf-peixoto/phishing_pot), real phishing emails collected by honeypots: bank, crypto-wallet, tax-refund, prize and invoice scams in many languages. The exact commit is recorded with each run.
- **Legitimate email:** the SpamAssassin public corpus, `easy_ham`, `easy_ham_2` and `hard_ham`: 4,150 real emails from mailing lists, colleagues, newsletters and marketing. `hard_ham` is legitimate mail that looks like spam, the hardest part for any filter.
- **Modern samples:** the labelled corpus in [`extension/tests/fixtures/corpus`](../extension/tests/fixtures/corpus) (Google Docs shares, bank alerts, GitHub notifications, Zoom invites, job alerts…) must all come out *clear* in every test run, and every phishing sample there must be caught as the right kind of attack.

None of these emails are stored in this repository. `scripts/benchmark/fetch.mjs` downloads them into `.cache/benchmark`, which git ignores.

## Read the numbers with this in mind

- **The legitimate corpus is from 2002.** It has no DKIM or DMARC results and almost no `https://` links, so a few checks that matter today (unencrypted links, a bounce address on another domain) fire on it more than they would on mail you receive now. Most of the remaining false alarms are *Suspicious*, not *High risk*, and come from this. A modern public corpus of legitimate email with full headers doesn't exist, because real inboxes are private; if you can share anonymised legitimate emails, see [Contributing](../CONTRIBUTING.md).
- **phishing_pot is honeypot mail**, so it is heavy on mass phishing and light on targeted business email compromise. The labelled corpus covers those attacks instead.

## What the benchmark has changed

The first run found **13.9%** false alarms (578 emails, 72 rated High risk). Each cause was fixed, with a test, without lowering the detection rate:

- **Search and sign-up boxes** in newsletters were treated like phishing forms. Each form is now judged on its own; only password fields, account, card or identity fields, or an email box that sends your address to someone other than the sender, are high risk.
- **Mailing lists** send replies to the list. A Reply-To that is the list's own posting address is no longer a red flag, except when it points to free webmail, because anyone can add list headers.
- **A newsletter's own click tracker** (for example "Dilbert.com" sent through `unitedmedia.com/Click?…` by unitedmedia.com) is no longer "link text shows one site but goes to another", unless the text names a well-known brand the sender doesn't own.
- **Email addresses spelt in character codes** (`&#102;&#101;…`, the old trick to hide an address from spam harvesters) are no longer read as a disguised link.
- **JavaScript inside an email** is now a low-weight note: mail apps never run it, and it barely helped catch phishing.

Result: **6.0%** false alarms, 17 rated High risk, and still **86.5%** of phishing caught.

## Run it yourself

```bash
pnpm benchmark
```

It downloads the corpora (about 140 MB), analyses every email on your computer and writes `.cache/benchmark/result/benchmark.md` and `benchmark.json`, which lists each false alarm and each missed phish with the checks that fired. In CI the run fails if fewer than 85% of the phishing emails are caught or more than 7% of the legitimate ones raise an alarm.

## Report a mistake

Every panel has a **Was this right?** button. If Unmask got an email wrong, it opens a pre-filled GitHub issue with only what you choose to share: the verdict, the checks that fired and, if you allow it, the sender's domain. The email itself is never sent. Every confirmed mistake becomes a test in [`falsePositives.test.ts`](../extension/tests/falsePositives.test.ts).

## Precision of each check

How often each check fires on the 400 phishing emails and on the 4,150 legitimate ones. *Precision* is the chance a firing is on phishing if both kinds of mail were equally common, so it is not skewed by the corpora's different sizes. Checks near the top fire most on real mail and are where false alarms come from; a check at 0% never fired on phishing at all in this set. The legitimate corpus is from 2002–2005, so `link-no-https` and header checks fire more than they would on today's mail. Regenerated by the benchmark run (`checks.md` in its output); checks that fired fewer than 3 times are left out.

| Check | Fires on phishing | Fires on real mail | Precision |
|---|---|---|---|
| `link-no-https` | 69.5% (278) | 81.3% (3373) | 46.1% |
| `return-path-mismatch` | 20.3% (81) | 69.1% (2867) | 22.7% |
| `received-out-of-order` | 0% (0) | 11% (456) | 0% |
| `fake-reply` | 2.3% (9) | 5.3% (220) | 29.8% |
| `reply-to-mismatch` | 20% (80) | 3.9% (160) | 83.8% |
| `urgency` | 37.3% (149) | 3% (124) | 92.6% |
| `date-old` | 1% (4) | 2.4% (98) | 29.7% |
| `html-form` | 0% (0) | 2.1% (87) | 0% |
| `html-script` | 0.8% (3) | 1.5% (61) | 33.8% |
| `link-tracker-mismatch` | 0% (0) | 1.2% (49) | 0% |
| `webmail-forged` | 0.3% (1) | 0.7% (27) | 27.8% |
| `link-abused-host` | 2.8% (11) | 0.3% (13) | 89.8% |
| `link-odd-port` | 0% (0) | 0.3% (12) | 0% |
| `link-suspicious-tld` | 2.5% (10) | 0.2% (10) | 91.2% |
| `link-text-mismatch` | 2% (8) | 0.2% (9) | 90.2% |
| `entity-encoded-text` | 0% (0) | 0.2% (9) | 0% |
| `bec-pretext` | 0% (0) | 0.2% (7) | 0% |
| `fake-logo-google` | 0.3% (1) | 0.1% (6) | 63.4% |
| `link-ip-host` | 0% (0) | 0.1% (6) | 0% |
| `link-shortener` | 3.5% (14) | 0.1% (5) | 96.7% |
| `credential-request` | 0.5% (2) | 0.1% (4) | 83.8% |
| `link-brand-in-domain` | 0.5% (2) | 0.1% (4) | 83.8% |
| `bec-payment` | 0.3% (1) | 0.1% (4) | 72.2% |
| `date-future` | 0.3% (1) | 0.1% (4) | 72.2% |
| `display-name-email` | 0% (0) | 0.1% (4) | 0% |
| `hidden-text` | 65.5% (262) | 0% (2) | 99.9% |
| `money-lure` | 5.3% (21) | 0% (2) | 99.1% |
| `attachment-*` | 1% (4) | 0% (2) | 95.4% |
| `mailer-script` | 0.8% (3) | 0% (2) | 94% |
| `callback-phishing` | 0.3% (1) | 0% (2) | 83.8% |
| `link-userinfo` | 2.8% (11) | 0% (1) | 99.1% |
| `sender-lookalike` | 62.3% (249) | 0% (0) | 100% |
| `spf-fail` | 56.5% (226) | 0% (0) | 100% |
| `dkim-unaligned` | 48.3% (193) | 0% (0) | 100% |
| `spf-none` | 23.5% (94) | 0% (0) | 100% |
| `dkim-none` | 20% (80) | 0% (0) | 100% |
| `dkim-fail` | 16% (64) | 0% (0) | 100% |
| `arc-broken` | 15% (60) | 0% (0) | 100% |
| `brand-impersonation` | 5.5% (22) | 0% (0) | 100% |
| `dmarc-fail` | 3% (12) | 0% (0) | 100% |
| `link-encoded-email` | 2.5% (10) | 0% (0) | 100% |
| `disguised-from` | 2.3% (9) | 0% (0) | 100% |
| `spf-softfail` | 1.8% (7) | 0% (0) | 100% |
| `dkim-sha1` | 1.5% (6) | 0% (0) | 100% |
| `disguised-subject` | 1.3% (5) | 0% (0) | 100% |
| `image-only` | 1.3% (5) | 0% (0) | 100% |
| `link-many-subdomains` | 1% (4) | 0% (0) | 100% |
| `mixed-script-text` | 1% (4) | 0% (0) | 100% |
| `invisible-splitters` | 1% (4) | 0% (0) | 100% |
