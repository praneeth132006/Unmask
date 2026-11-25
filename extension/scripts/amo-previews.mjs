#!/usr/bin/env node
// Replaces the Firefox Add-ons listing screenshots with docs/store/*.png, through
// addons.mozilla.org's API (v5). New ones are uploaded first; old ones are removed
// only after every upload succeeded, so a re-run after a failure also clears
// partial uploads from the failed run. Needs FIREFOX_JWT_ISSUER, FIREFOX_JWT_SECRET
// and FIREFOX_EXTENSION_ID. DRY_RUN=true lists what would change.
import { createHmac, randomUUID } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const { FIREFOX_JWT_ISSUER: iss, FIREFOX_JWT_SECRET: secret, FIREFOX_EXTENSION_ID: guid, DRY_RUN } = process.env;
if (!iss || !secret || !guid) throw new Error('FIREFOX_JWT_ISSUER, FIREFOX_JWT_SECRET and FIREFOX_EXTENSION_ID are required');
const dir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'docs', 'store');
const files = readdirSync(dir).filter((f) => f.endsWith('.png')).sort();
const API = `https://addons.mozilla.org/api/v5/addons/addon/${encodeURIComponent(guid)}`;

const b64 = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
function jwt() {
  const now = Math.floor(Date.now() / 1000);
  const body = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ iss, jti: randomUUID(), iat: now, exp: now + 60 })}`;
  return `${body}.${createHmac('sha256', secret).update(body).digest('base64url')}`;
}
async function api(path, init = {}, tries = 6) {
  const r = await fetch(`${API}${path}`, { ...init, headers: { Authorization: `JWT ${jwt()}`, ...(init.headers ?? {}) } });
  // AMO throttles uploads ("Expected available in 58 seconds"): wait as told, then try again.
  if (r.status === 429 && tries > 1) {
    const wait = Number((await r.text()).match(/in (\d+) second/)?.[1] ?? 60) + 2;
    console.log(`throttled; waiting ${wait}s`);
    await new Promise((res) => setTimeout(res, wait * 1000));
    return api(path, init, tries - 1);
  }
  if (!r.ok) throw new Error(`${init.method ?? 'GET'} ${path} → HTTP ${r.status}: ${(await r.text()).slice(0, 300)}`);
  return r.status === 204 ? null : r.json();
}

const addon = await api('/');
const old = (addon.previews ?? []).map((p) => p.id);
console.log(`${addon.name?.['en-US'] ?? guid}: ${old.length} current screenshots, ${files.length} new`);
if (DRY_RUN === 'true') {
  for (const f of files) console.log('would upload', f);
  console.log('would remove', old.length, 'old screenshots');
  process.exit(0);
}
for (const [i, f] of files.entries()) {
  const form = new FormData();
  form.append('image', new Blob([readFileSync(join(dir, f))], { type: 'image/png' }), f);
  form.append('position', String(i));
  await api('/previews/', { method: 'POST', body: form });
  console.log('uploaded', f);
}
for (const id of old) {
  await api(`/previews/${id}/`, { method: 'DELETE' });
  console.log('removed old screenshot', id);
}
