# Security policy

Unmask handles untrusted email content, so security reports are very welcome.

## Reporting a vulnerability

Please **don't open a public GitHub issue** for security problems. Instead, use GitHub's private reporting: **Security → Report a vulnerability** on [the repository](https://github.com/praneeth132006/Unmask/security/advisories/new).

Include what you found, steps to reproduce (a sample `.eml` helps a lot), and the impact you think it has. You'll get a reply within a week.

## What's in scope

- Email content escaping the sandboxed Body view (script execution, network requests while remote images are off, navigation)
- Anything that sends email content, keys or other data somewhere the user didn't choose
- Abuse of the content scripts or the background fetch from a web page
- SSRF or other abuse of the redirect-trace backend
- Crafted emails that crash the panel or make a clearly malicious message score as clean (bypasses are useful even if not "vulnerabilities")

## Design notes

The security model is described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).
