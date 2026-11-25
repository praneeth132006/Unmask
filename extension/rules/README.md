# Detection rules

Each `.yml` file here is one scam pattern. You can add one without writing TypeScript: copy a file, change it, and run `pnpm rules` (from `extension/`) to check it and compile it. `pnpm test` then proves it fires on its phishing example and stays quiet on its legitimate one.

```yaml
id: tax-refund-lure            # lowercase-with-dashes; the finding is reported as rule-<id>
title: Promises a tax refund you have to claim     # shown in the red flags
plain: It promises a tax refund, a classic way to steal bank details.   # everyday words
severity: medium               # low, medium or high (never critical: rules are text patterns)
points: 12                     # low 3-8, medium 8-15, high 15-25
category: content              # content, links or sender
when:
  any: ["tax refund", "/refund of (your )?tax(es)?/"]   # at least one must appear (text or /regex/)
  also: ["claim", "verify", "submit"]                  # optional: and at least one of these too
  subject: []                  # optional: phrases that must appear in the subject
  needs_link: true             # optional: only when the email has a link, a QR code or an attachment
  not_from: ["gov.uk", "irs.gov", "canada.ca"]         # optional: skip mail verified (DMARC) from these
examples:
  phish: "Subject: HMRC tax refund\n\nYou are eligible for a tax refund. Claim it here: https://x.example/r"
  legit: "Subject: Your tax return\n\nYour return was received. No action is needed."
```

Text matching ignores case and runs on the subject and the visible text of the email. A phrase in slashes is a regular expression. Keep phrases specific: a rule must not fire on the real emails in the benchmark (see [docs/BENCHMARK.md](../../docs/BENCHMARK.md)).

CI also fuzzes every rule (`tests/rulesFuzz.test.ts`): it must still fire when its scam example is upper-cased, re-spaced, wrapped in HTML, padded or sent from another address, and must stay quiet on 300 generated ordinary emails that use the same everyday words.
