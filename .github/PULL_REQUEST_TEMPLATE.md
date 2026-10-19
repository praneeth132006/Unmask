## What does this change?

<!-- A short description, and the issue it fixes if any: "Fixes #123". -->

## How was it tested?

<!-- Commands you ran, emails you checked, screenshots for UI changes (light and dark mode). -->

## Checklist

- [ ] `pnpm test`, `pnpm typecheck` and `pnpm build` pass
- [ ] New checks have a test that triggers them **and** a legitimate email that doesn't
- [ ] Email content still never leaves the device (or the new online check is opt-in and documented in PRIVACY.md)
- [ ] Gmail-side code avoids `innerHTML`/`DOMParser` (Trusted Types)
- [ ] Docs updated (docs/CHECKS.md, user guide, CHANGELOG under *Unreleased*)
- [ ] No real personal email data in tests or screenshots
