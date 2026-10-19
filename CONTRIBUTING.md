# Contributing to Unmask

Thanks for helping. This page covers setting up, the project's conventions, and the most common changes: adding a check, a brand or a tracker.

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
| `pnpm test` | All tests (extension + backend) |
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
- Analyzer tests use real-looking `.eml` fixtures. Don't commit real personal email.
- UI changes: check the panel in **both light and dark mode** before opening a PR.

## Commits and pull requests

- [Conventional commits](https://www.conventionalcommits.org): `feat(links): …`, `fix(gmail): …`, `docs: …`, `test: …`.
- One logical change per commit, with the *why* in the body.
- Run `pnpm test && pnpm typecheck && pnpm build` before pushing.
- Update [CHANGELOG.md](CHANGELOG.md) under *Unreleased*.

## Reporting security issues

Please don't open a public issue. See [SECURITY.md](SECURITY.md).
