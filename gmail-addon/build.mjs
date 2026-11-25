// Builds the Gmail add-on into gmail-addon/dist: Engine.js (the engine as a
// global "Unmask"), Code.js and appsscript.json, ready for `clasp push`.
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, 'dist');
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist);
execFileSync(join(here, '..', 'extension', 'node_modules', '.bin', 'esbuild'), [
  join(here, 'src', 'engine.ts'), '--bundle', '--format=iife', '--global-name=Unmask', '--target=es2019', '--minify',
  `--outfile=${join(dist, 'Engine.js')}`, '--log-level=warning',
], { stdio: 'inherit' });
cpSync(join(here, 'src', 'Code.js'), join(dist, 'Code.js'));
cpSync(join(here, 'appsscript.json'), join(dist, 'appsscript.json'));
console.log('gmail-addon/dist ready: Engine.js, Code.js, appsscript.json');
