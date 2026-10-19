// Renders the extension icons from the SVG sources in docs/brand.
// Sizes up to 32px use a simplified drawing so the mark stays readable in the toolbar.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Resvg } from '@resvg/resvg-js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const outDir = join(root, 'extension', 'public', 'icon');
mkdirSync(outDir, { recursive: true });

const full = readFileSync(join(root, 'docs', 'brand', 'logo.svg'), 'utf8');
const small = readFileSync(join(root, 'docs', 'brand', 'logo-small.svg'), 'utf8');

for (const size of [16, 32, 48, 96, 128]) {
  const svg = size <= 32 ? small : full;
  const png = new Resvg(svg, { fitTo: { mode: 'width', value: size } }).render().asPng();
  writeFileSync(join(outDir, `${size}.png`), png);
}
// A large copy for the README and the store listing.
writeFileSync(join(root, 'docs', 'brand', 'logo-512.png'), new Resvg(full, { fitTo: { mode: 'width', value: 512 } }).render().asPng());
console.log(`icons written to ${outDir}`);
