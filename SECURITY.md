# Security policy

Unmask analyzes untrusted, often malicious, email. Security reports are very welcome, and we'll credit you for them.

## Supported versions

| Version | Supported |
|---|---|
| Latest release (0.2.x) | ✅ |
| Older releases | ❌ Please update first |

## Reporting a vulnerability

**Please don't open a public issue for security problems.**

1. Go to **[Security → Report a vulnerability](https://github.com/praneeth132006/Unmask/security/advisories/new)** (GitHub's private reporting).
2. Describe what you found, how to reproduce it (a sanitized `.eml` sample helps a lot), and the impact.
3. You'll get an acknowledgement **within 3 days** and an assessment **within 7 days**.
4. Once a fix is released, we'll publish an advisory and credit you, unless you'd rather stay anonymous.

Please give us reasonable time to fix the issue before disclosing it publicly. We aim to fix critical issues within 14 days.

## Scope

**In scope:**

- Email content escaping the sandboxed Body view: script execution, network requests while remote images are off, navigation, or leaking that the email was opened
- Anything that sends email content, API keys or other data somewhere the user didn't choose
- Web pages abusing the content scripts, the MAIN-world script, or the background fetch
- SSRF, request smuggling or other abuse of the redirect-trace backend
- Denial of service through crafted emails or pages (for example, ReDoS that freezes the panel)
- Crafted emails that make clearly malicious messages score as clean (detection bypasses are welcome even when not strictly vulnerabilities)

**Out of scope:**

- Vulnerabilities in Gmail, Chrome, VirusTotal or urlscan.io themselves (report those to their vendors)
- Attacks that need malware already running on the user's computer or a malicious browser extension
- Missing hardening without a demonstrated impact
- Social engineering of maintainers

## Safe harbour

Good-faith research that follows this policy is welcome: we won't pursue legal action, and we'll work with you. Please use only your own accounts and test data, don't access other people's email, and don't run high-volume tests against third-party services.

## How Unmask is protected

The design is described in [docs/ARCHITECTURE.md → Security model](docs/ARCHITECTURE.md#security-model). In short:

- Analysis runs locally. The email never leaves the browser unless the user clicks an online check.
- Untrusted HTML is shown only in an `<iframe sandbox="">` with scripts off, links disarmed, prefetch hints removed and a deny-all CSP.
- Content scripts use no HTML-string sinks and tear themselves down when the extension reloads.
- Parsers that handle untrusted input avoid quadratic-time regexes; timing tests guard them.
- The trace backend blocks private and reserved addresses at connect time, caps hops, bytes and time, and rate-limits without trusting spoofable headers.
- Dependencies are monitored by Dependabot, and code is scanned by CodeQL on every push.
