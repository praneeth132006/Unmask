# Governance

## Who runs Unmask

Unmask is maintained by **Praneeth** ([@praneeth132006](https://github.com/praneeth132006)), who started it in October 2026. The maintainer reviews and merges changes, publishes releases to the browser stores, and handles security reports.

## How decisions are made

- Plans are discussed in public, in [issues](https://github.com/praneeth132006/Unmask/issues). Bigger changes are written up there before work starts. The [roadmap](ROADMAP.md) lists what comes next.
- Every change, including the maintainer's own, goes through CI: unit tests, end-to-end tests in a real browser, type checks and CodeQL. Nothing is released with failing checks.
- A report of a wrong verdict is treated as a bug. The fix comes with a test built from that email (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Principles that don't change

These hold whoever maintains the project:

1. **Email stays on the device.** No feature may send an email's content to the developers or to an Unmask server.
2. **Free for everyone, organisations included.** No ads, no accounts, no selling or sharing data.
3. **Outside services only on a click,** sending the minimum (a link, a domain, or a file's hash), and listed in [PRIVACY.md](PRIVACY.md).
4. **Honest verdicts.** Unmask never calls an email "safe", only says what it found.

## Contributors and maintainers

Anyone can contribute; see [CONTRIBUTING.md](CONTRIBUTING.md) and the [code of conduct](CODE_OF_CONDUCT.md). Someone who has made several good contributions can be invited as a co-maintainer with merge rights. The aim is at least two maintainers, so the project never depends on one person.

## Money

Unmask accepts donations through [GitHub Sponsors](https://github.com/sponsors/praneeth132006) and applies for grants for the milestones in the [roadmap](ROADMAP.md). Money pays for development time, reviews and audits. It never buys a feature that breaks the principles above. Larger grants will be reported in the changelog.

## Security

Report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).
