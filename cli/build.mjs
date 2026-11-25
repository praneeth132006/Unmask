// Bundles the CLI into one file with no runtime dependencies: cli/dist/unmask.mjs
import { execFileSync } from 'node:child_process';
import { chmodSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
const version = JSON.parse(readFileSync(join(here, 'package.json'), 'utf8')).version;
const out = join(here, 'dist', 'unmask.mjs');
execFileSync(join(here, '..', 'extension', 'node_modules', '.bin', 'esbuild'), [
  join(here, 'src', 'main.ts'), '--bundle', '--platform=node', '--format=esm', '--target=node20', '--minify',
  '--banner:js=#!/usr/bin/env node\nimport { createRequire as __cr } from "node:module"; const require = __cr(import.meta.url);',
  `--define:process.env.UNMASK_VERSION="${version}"`, `--outfile=${out}`, '--log-level=warning',
], { stdio: 'inherit' });
chmodSync(out, 0o755);
console.log(`built ${out}`);
