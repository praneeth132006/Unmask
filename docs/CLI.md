# Unmask on the command line

The same engine as the extension, for security teams, mail pipelines and scripts. One file, no dependencies, Node 20 or newer. Everything runs locally; only `domain` makes network requests (to Google Public DNS, with the domain name only).

```bash
pnpm cli                    # builds cli/dist/unmask.mjs and runs a smoke test
node cli/dist/unmask.mjs check suspicious.eml
```

| Command | What it does |
|---|---|
| `unmask check a.eml b.eml` | Verdict, plain-language reasons and the biggest score contributions for each email |
| `unmask check *.eml --json` | One JSON object per line (NDJSON): verdict, score, findings and defanged indicators |
| `cat mail.eml \| unmask check - --fail-on suspicious` | Reads stdin; exits 1 if the email is Suspicious or worse (for mail filters and CI) |
| `unmask report mail.eml -f stix -o case.json` | Writes a report: `html`, `pdf`, `docx` or `stix` (STIX 2.1 bundle) |
| `unmask domain example.com` | Is the domain spoofable? SPF, DMARC, DKIM, MX, MTA-STS, BIMI and the fix |

Exit codes: `0` fine, `1` an email reached `--fail-on`, `2` usage or read error. `NO_COLOR=1` turns colours off.

### In a mail pipeline

Postfix, procmail or any filter that can pipe a message can call it:

```bash
unmask check - --json --fail-on high < "$MESSAGE" >> /var/log/unmask.ndjson || echo "X-Unmask: high-risk"
```
