// Runs the built add-on (node gmail-addon/build.mjs first) in a bare V8 context (no browser or Node APIs), with a fake Utilities, like Apps Script.
import vm from 'node:vm'; import { readFileSync } from 'node:fs'; import { createHash } from 'node:crypto';
const dist = new URL('./dist', import.meta.url).pathname;
const root = new URL('..', import.meta.url).pathname;
const signed = (b) => Array.from(b, (x) => (x > 127 ? x - 256 : x));
const Utilities = {
  newBlob: (bytes) => ({ getDataAsString: (cs = 'UTF-8') => Buffer.from(bytes.map((b) => b & 255)).toString(/utf-?8/i.test(cs) ? 'utf8' : 'latin1') }),
  base64Decode: (s) => signed(Buffer.from(s, 'base64')), base64Encode: (a) => Buffer.from(typeof a === 'string' ? a : a.map((b) => b & 255)).toString('base64'),
  computeDigest: (alg, bytes) => signed(createHash(alg === 'SHA_1' ? 'sha1' : 'sha256').update(Buffer.from(bytes.map((b) => b & 255))).digest()),
  DigestAlgorithm: { SHA_1: 'SHA_1', SHA_256: 'SHA_256' },
};
const ctx = vm.createContext({ Utilities, console });
for (const k of ['TextDecoder', 'TextEncoder', 'atob', 'btoa', 'crypto', 'DOMParser', 'setTimeout', 'fetch', 'Buffer']) if (k in ctx) throw new Error('leak ' + k);
vm.runInContext(readFileSync(`${dist}/Engine.js`, 'utf8'), ctx);
const check = vm.runInContext('Unmask.check', ctx);
const cases = [['extension/e2e/demo.eml', 'high'], ['extension/tests/fixtures/phishing-paypal.eml', 'high'], ['extension/tests/fixtures/legit-newsletter.eml', 'clear']];
let failed = 0;
for (const [file, want] of cases) {
  const r = await check(readFileSync(root + file, 'utf8'));
  const ok = r.verdict === want;
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${file}: ${r.verdict} ${r.score} (want ${want})`);
}
process.exit(failed ? 1 : 0);
