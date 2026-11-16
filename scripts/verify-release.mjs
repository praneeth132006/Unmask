#!/usr/bin/env node
// Proves a published release was built from this source: downloads the
// release's Chrome, Edge and Firefox zips and compares every file inside with
// the zips `pnpm zip` just built from the checked-out tag.
//
//   git checkout v0.5.1 && pnpm install --frozen-lockfile && pnpm zip:all
//   node scripts/verify-release.mjs v0.5.1
//
// Zip archives store timestamps, so the archives themselves differ; the files
// in them must be byte-for-byte identical. Needs `unzip` on the PATH.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const tag = process.argv[2];
const repo = process.env.UNMASK_REPO ?? 'praneeth132006/Unmask';
if (!/^v\d+\.\d+\.\d+$/.test(tag ?? '')) {
  console.error('Usage: node scripts/verify-release.mjs v1.2.3');
  process.exit(2);
}
const version = tag.slice(1);
const work = mkdtempSync(join(tmpdir(), 'unmask-verify-'));

function files(dir) {
  const out = new Map();
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else out.set(relative(dir, p), createHash('sha256').update(readFileSync(p)).digest('hex'));
    }
  };
  walk(dir);
  return out;
}

function unzip(zip, name) {
  const to = join(work, name);
  execFileSync('unzip', ['-q', '-o', zip, '-d', to]);
  return files(to);
}

let failed = 0;
for (const browser of ['chrome', 'edge', 'firefox']) {
  const zipName = `unmask-${browser}-${version}.zip`;
  const local = join(root, 'build', zipName);
  if (!existsSync(local)) {
    console.error(`✘ ${zipName}: build it first with pnpm zip:all on ${tag}`);
    failed++;
    continue;
  }
  const res = await fetch(`https://github.com/${repo}/releases/download/${tag}/${zipName}`, { redirect: 'follow' });
  if (!res.ok) {
    console.error(`✘ ${zipName}: release asset not found (HTTP ${res.status})`);
    failed++;
    continue;
  }
  const published = join(work, `published-${zipName}`);
  writeFileSync(published, Buffer.from(await res.arrayBuffer()));
  const a = unzip(published, `published-${browser}`);
  const b = unzip(local, `built-${browser}`);
  const diffs = [...new Set([...a.keys(), ...b.keys()])].filter((f) => a.get(f) !== b.get(f)).sort();
  if (diffs.length) {
    failed++;
    console.error(`✘ ${zipName}: ${diffs.length} file(s) differ: ${diffs.slice(0, 10).join(', ')}`);
  } else console.log(`✔ ${zipName}: all ${a.size} files identical to the source build`);
}
process.exit(failed ? 1 : 0);
