// Writes public/LICENSE.txt (Unmask's licence) and public/THIRD_PARTY_LICENSES.txt with the licence of every package bundled
// into the extension (production dependencies plus WXT's small runtime), so the
// zip users download carries the notices those licences require.
import { readFileSync, writeFileSync, readdirSync, realpathSync, existsSync, copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

const seen = new Map();
/** Node's lookup: walk up from `fromDir` through node_modules folders (works for packages without a package.json export). */
function findPackage(name, fromDir) {
  for (let dir = fromDir; ; dir = dirname(dir)) {
    const candidate = join(dir, 'node_modules', name);
    if (existsSync(join(candidate, 'package.json'))) return realpathSync(candidate);
    if (dirname(dir) === dir) return null;
  }
}

function visit(name, fromDir) {
  if (seen.has(name) || name.startsWith('@types/')) return; // type definitions are not bundled
  const dir = findPackage(name, fromDir);
  if (!dir) return; // optional or platform-specific dependency not installed
  const meta = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  const licenseFile = readdirSync(dir).find((f) => /^(licen[cs]e|copying)(\.|$)/i.test(f));
  seen.set(name, { version: meta.version, license: meta.license ?? 'see package', text: licenseFile ? readFileSync(join(dir, licenseFile), 'utf8').trim() : null });
  for (const dep of Object.keys(meta.dependencies ?? {})) visit(dep, dir);
}

for (const name of Object.keys(pkg.dependencies ?? {})) visit(name, root);
// Runtime helpers from WXT end up in the content scripts and background worker.
for (const name of ['@wxt-dev/browser']) visit(name, findPackage('wxt', root) ?? root);

const parts = [
  'Unmask includes the following open-source software. Each package is listed with its licence.',
  '',
  ...[...seen.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, info]) => `${'='.repeat(78)}\n${name}@${info.version} (${info.license})\n${'='.repeat(78)}\n\n${info.text ?? `Licensed under ${info.license}.`}\n`),
];
writeFileSync(join(root, 'public', 'THIRD_PARTY_LICENSES.txt'), parts.join('\n'));
// Unmask's own licence ships in the zip too.
copyFileSync(join(root, '..', 'LICENSE'), join(root, 'public', 'LICENSE.txt'));
console.log(`LICENSE.txt + THIRD_PARTY_LICENSES.txt: ${[...seen.keys()].join(', ')}`);
