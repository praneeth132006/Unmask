#!/usr/bin/env node
// Downloads the public corpora Unmask is measured against, into .cache/benchmark
// (ignored by git). Nothing here is ever committed or redistributed.
//
//   node scripts/benchmark/fetch.mjs [--phish 400]
//
// phish/  The first N samples (by number) of rf-peixoto/phishing_pot: real
//         phishing emails sent to honeypots, many languages and lures.
// ham/    The SpamAssassin public corpus (easy_ham, easy_ham_2, hard_ham):
//         real legitimate email, including marketing and newsletters that
//         are hard to tell from spam.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const out = join(root, '.cache', 'benchmark');
const arg = (name, dflt) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : dflt; };
const PHISH = Number(arg('phish', 400));
const HAM_SETS = ['20030228_easy_ham', '20030228_easy_ham_2', '20030228_hard_ham'];
const UA = { 'user-agent': 'unmask-benchmark (https://github.com/praneeth132006/Unmask)' };

async function get(url, init = {}) {
  for (let attempt = 1; ; attempt++) {
    const res = await fetch(url, { ...init, headers: { ...UA, ...(init.headers ?? {}) } });
    if (res.ok) return res;
    if (attempt >= 3) throw new Error(`${url}: HTTP ${res.status}`);
    await new Promise((r) => setTimeout(r, 1000 * attempt));
  }
}

async function fetchHam() {
  const dir = join(out, 'ham');
  if (existsSync(dir) && readdirSync(dir).length > 3000) return console.log(`ham: already have ${readdirSync(dir).length}`);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  for (const set of HAM_SETS) {
    const tmp = join(out, `${set}.tar.bz2`);
    writeFileSync(tmp, Buffer.from(await (await get(`https://spamassassin.apache.org/old/publiccorpus/${set}.tar.bz2`)).arrayBuffer()));
    const unpack = join(out, `${set}-x`);
    mkdirSync(unpack, { recursive: true });
    execFileSync('tar', ['-xjf', tmp, '-C', unpack]);
    for (const sub of readdirSync(unpack)) for (const f of readdirSync(join(unpack, sub))) if (!f.startsWith('cmds')) renameSync(join(unpack, sub, f), join(dir, `${set.replace('20030228_', '')}-${f.split('.')[0]}.eml`));
    rmSync(unpack, { recursive: true, force: true });
    rmSync(tmp, { force: true });
  }
  console.log(`ham: ${readdirSync(dir).length} emails`);
}

async function fetchPhish() {
  const dir = join(out, 'phish');
  mkdirSync(dir, { recursive: true });
  const token = process.env.GITHUB_TOKEN;
  const tree = await (await get('https://api.github.com/repos/rf-peixoto/phishing_pot/git/trees/main?recursive=1', token ? { headers: { authorization: `Bearer ${token}` } } : {})).json();
  const names = tree.tree.map((t) => t.path).filter((p) => /^email\/sample-\d+\.eml$/.test(p)).sort((a, b) => Number(a.match(/\d+/)[0]) - Number(b.match(/\d+/)[0])).slice(0, PHISH);
  const todo = names.filter((p) => !existsSync(join(dir, p.slice(6))));
  let next = 0;
  await Promise.all(Array.from({ length: 8 }, async () => {
    while (next < todo.length) {
      const p = todo[next++];
      writeFileSync(join(dir, p.slice(6)), Buffer.from(await (await get(`https://raw.githubusercontent.com/rf-peixoto/phishing_pot/${tree.sha}/${p}`)).arrayBuffer()));
    }
  }));
  console.log(`phish: ${names.length} emails (phishing_pot @ ${tree.sha.slice(0, 7)})`);
  writeFileSync(join(out, 'phish-source.txt'), `rf-peixoto/phishing_pot@${tree.sha} first ${names.length} samples\n`);
}

mkdirSync(out, { recursive: true });
await fetchHam();
await fetchPhish();
