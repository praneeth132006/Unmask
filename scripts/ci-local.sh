#!/bin/sh
# Runs the same checks as .github/workflows/ci.yml, so a push never breaks CI.
# Used by the pre-push hook (.githooks/pre-push). Run by hand with: pnpm ci:local
set -e
cd "$(dirname "$0")/.."
step() { printf '\n\033[1m▶ %s\033[0m\n' "$1"; }
step "Unit tests";            pnpm test
step "Typecheck";             pnpm typecheck
step "Build: Chrome";         pnpm build >/dev/null
step "Build: Firefox";        pnpm build:firefox >/dev/null
step "Build: Edge";           pnpm build:edge >/dev/null
step "End-to-end (Chromium)"; pnpm test:e2e
step "End-to-end (offscreen fallback)"; pnpm --filter unmask-extension test:e2e:offscreen
printf '\n\033[32m✔ Everything CI checks passed locally.\033[0m\n'
