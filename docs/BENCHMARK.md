# Benchmark: how often Unmask is right

A phishing checker is only useful if it catches phishing **and** stays quiet on real mail. Unmask is measured on both, with public corpora, on every change to `main`. The numbers below come from that run; every release attaches its own copy (`benchmark.md` and `benchmark.json`) to the [release page](https://github.com/praneeth132006/Unmask/releases).

## Latest result

| | Emails | Result |
|---|---|---|
| Real phishing ([phishing_pot](https://github.com/rf-peixoto/phishing_pot)) | 400 | **86.5% caught** (346), 285 rated High risk |
| Real legitimate email ([SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/)) | 4,150 | **6.0% false alarms** (248 rated Suspicious or High risk, 17 High risk) |
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
