# Contributing to Unmask

Thanks for helping. This page covers setting up, the project's conventions, and the most common changes: adding a check, a brand or a tracker.

By participating you agree to the [code of conduct](CODE_OF_CONDUCT.md). Contributions are licensed under the project's [MIT licence](LICENSE): by opening a pull request you confirm you have the right to submit the code under it.

## Ways to help

- **Report a wrong verdict** with the *Wrong verdict* issue template. Missed phishing and false alarms are the most valuable reports.
- **Fix a bug or add a check:** issues labelled [`good first issue`](https://github.com/praneeth132006/Unmask/labels/good%20first%20issue) are a good start.
- **Add a brand or a tracking service.** These are one-line changes, see below.
- **Improve the docs or translations.**
- **Report security problems privately** ([SECURITY.md](SECURITY.md)).

## Setup

Requirements: Node.js 20+ and pnpm.

```bash
git clone https://github.com/praneeth132006/Unmask.git
cd Unmask
pnpm install
pnpm dev        # opens Chrome with the extension loaded and hot reload
```

Other scripts (run from the root):

| Command | What it does |
|---|---|
| `pnpm build` | Production build into `build/unmask-chrome` |
| `pnpm zip` | Zip for the Chrome Web Store |
| `pnpm test` | All unit tests (extension + backend) |
| `pnpm test:e2e` | Builds, then loads the real extension in Chromium against a Gmail test double (needs `pnpm --filter unmask-extension exec playwright install chromium` once) |
| `pnpm typecheck` | TypeScript in both packages |
| `pnpm backend` | Redirect-trace server on port 8787 |
| `pnpm --filter unmask-extension icons` | Re-render icons from `docs/brand/*.svg` |

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) first: it explains how the pieces connect.

## Ground rules

- **Never send email content off the device.** Local checks must not make network requests. Online checks must be opt-in, send the minimum, and be described in [PRIVACY.md](PRIVACY.md).
- **Explain findings in plain language.** A finding's `title` should make sense to someone who has never heard of SPF. Put technical detail in `detail`.
- **Never say "safe".** Use "No red flags found".
- **Prefer false negatives on weak signals.** Something that is common in legitimate mail should be *Low* or a *Note*. Test new checks against real, legitimate newsletters.
- **Gmail content-script code must work under Trusted Types:** no `innerHTML`, `outerHTML =`, `DOMParser` or `document.write` in `entrypoints/gmail*.ts` or `src/lib/highlight.ts` / `gmailRaw.ts`.
- Every finding should set a `target` so hover and click work.

## Adding a check

1. Pick the analyzer in `extension/src/analyzers/` (or create one and call it from `core/analyze.ts`).
2. Return a `Finding` with a stable `id`, `category`, `severity`, `points`, a plain-language `title`, an optional `detail`, and a `target`.
3. Add tests in `extension/tests/`: one email that should trigger it and one legitimate email that shouldn't. Sample `.eml` files live in `tests/fixtures/`.
4. Document it in [docs/CHECKS.md](docs/CHECKS.md) with its severity and points.

Point guide: Critical 30–35, High 18–25, Medium 8–15, Low 3–6, Note 0, Good −5 to −10.

## Adding a brand

Edit `extension/src/analyzers/brands.ts`:

```ts
{ name: 'Example Bank', keywords: ['examplebank', 'example bank'], domains: ['examplebank.com', 'examplebank.co.uk'] },
```

- `keywords` are matched in display names and domain labels. Avoid short dictionary words (they cause false matches).
- `domains` must list **every** domain the brand legitimately sends from or links to, including its mailing-service subdomains.
- Add a case to `tests/lookalike.test.ts`.

## Adding a tracker

Add `[hostSuffix, 'Service name']` to `SERVICES` in `extension/src/analyzers/trackers.ts` and a case to `tests/trackers.test.ts`.

## Tests

- Vitest with the `happy-dom` environment for the extension, Node for the backend.
- `extension/e2e/run.mjs` loads the built extension in Chromium with Playwright. `mail.google.com` is routed to `e2e/fake-gmail.html`, so no Google account is used. It checks the session token, message detection, raw download, highlighting, and that reloading the extension leaves no uncaught errors.
- Parsers that read untrusted input have timing tests. Keep regexes bounded: no `[^>]+` across a whole document.
- Analyzer tests use real-looking `.eml` fixtures. Don't commit real personal email.
- UI changes: check the panel in **both light and dark mode** before opening a PR.

## Commits and pull requests

- [Conventional commits](https://www.conventionalcommits.org): `feat(links): …`, `fix(gmail): …`, `docs: …`, `test: …`.
- One logical change per commit, with the *why* in the body.
- **Never push something CI would fail.** `pnpm install` turns on a `pre-push` hook that runs `pnpm ci:local`, the same steps as CI (tests, typecheck, Chrome/Firefox/Edge builds, both end-to-end runs), and stops the push if any fail. Maintainers push to a branch first and move `main` only after GitHub Actions is green there.
- Feature screenshots: after a UI change run `pnpm --filter unmask-extension screenshots` to refresh `docs/images` and `docs/store`.
- Update [CHANGELOG.md](CHANGELOG.md) under *Unreleased*.

## Releasing (maintainers)

1. Move *Unreleased* in CHANGELOG.md to a new version and set the same version in `extension/package.json`.
2. Commit, then tag and push: `git tag v0.2.1 && git push origin v0.2.1`.
3. The release workflow tests, builds the Chrome, Edge and Firefox zips (with licence notices) and publishes the GitHub Release.
4. To update the browser stores, follow [docs/PUBLISHING.md](docs/PUBLISHING.md).

## Reporting security issues

Please don't open a public issue. See [SECURITY.md](SECURITY.md).
