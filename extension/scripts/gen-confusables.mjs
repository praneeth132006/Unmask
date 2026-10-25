// Builds src/analyzers/confusables.json from Unicode's confusables.txt (UTS #39):
// every single non-ASCII character that Unicode lists as confusable with one
// ASCII letter or digit, mapped to that letter. Used to read look-alike domains.
//
//   curl -o confusables.txt https://www.unicode.org/Public/security/latest/confusables.txt
//   node scripts/gen-confusables.mjs confusables.txt
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const src = process.argv[2];
if (!src) throw new Error('Usage: node scripts/gen-confusables.mjs path/to/confusables.txt');
const text = readFileSync(src, 'utf8');
const version = text.match(/^# Version: (.+)$/m)?.[1] ?? 'unknown';
const map = {};
for (const line of text.split('\n')) {
  const m = line.match(/^([0-9A-F]+)\s*;\s*([0-9A-F ]+?)\s*;\s*MA/);
  if (!m) continue;
  const from = parseInt(m[1], 16);
  if (from < 0x80) continue; // ASCII stays itself (Unicode maps l to I, which would break real names)
  const to = String.fromCodePoint(...m[2].split(' ').map((h) => parseInt(h, 16)));
  if (!/^[A-Za-z0-9]$/.test(to)) continue;
  map[String.fromCodePoint(from)] = to.toLowerCase();
}
const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'analyzers', 'confusables.json');
writeFileSync(out, `${JSON.stringify({ source: `Unicode confusables.txt ${version}, © Unicode, Inc., Unicode License v3`, map })}\n`);
console.log(`Wrote ${Object.keys(map).length} confusables (Unicode ${version}) to ${out}`);
