#!/usr/bin/env node
// Checks every rules/*.yml and compiles them into src/rules/rules.json, which
// the extension loads. Run with `pnpm rules`. `--check` only verifies that
// rules.json is up to date (used by the tests and CI).
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const dir = join(here, '..', 'rules');
const out = join(here, '..', 'src', 'rules', 'rules.json');

const SEVERITIES = { low: [1, 8], medium: [6, 15], high: [12, 25] };
const CATEGORIES = ['content', 'links', 'sender'];
const KEYS = new Set(['id', 'title', 'plain', 'severity', 'points', 'category', 'when', 'examples']);
const WHEN = new Set(['any', 'also', 'subject', 'needs_link', 'not_from']);

export function compileRule(file, text) {
  const fail = (msg) => { throw new Error(`${file}: ${msg}`); };
  let r;
  try {
    r = parse(text, { prettyErrors: true });
  } catch (e) {
    fail(`not valid YAML: ${e.message}`);
  }
  if (!r || typeof r !== 'object') fail('empty rule');
  for (const k of Object.keys(r)) if (!KEYS.has(k)) fail(`unknown key "${k}"`);
  if (!/^[a-z0-9]+(-[a-z0-9]+)*$/.test(r.id ?? '')) fail('id must be lowercase-with-dashes');
  if (`${r.id}.yml` !== file) fail(`file must be named ${r.id}.yml`);
  for (const k of ['title', 'plain']) if (typeof r[k] !== 'string' || r[k].length < 10 || r[k].length > 160) fail(`${k} must be 10-160 characters`);
  if (!SEVERITIES[r.severity]) fail('severity must be low, medium or high');
  const [lo, hi] = SEVERITIES[r.severity];
  if (!Number.isInteger(r.points) || r.points < lo || r.points > hi) fail(`points for ${r.severity} must be ${lo}-${hi}`);
  if (!CATEGORIES.includes(r.category ?? 'content')) fail(`category must be one of ${CATEGORIES.join(', ')}`);
  const w = r.when ?? fail('missing "when"');
  for (const k of Object.keys(w)) if (!WHEN.has(k)) fail(`unknown key "when.${k}"`);
  const phrases = (k) => {
    const v = w[k] ?? [];
    if (!Array.isArray(v) || v.some((p) => typeof p !== 'string' || !p.trim())) fail(`when.${k} must be a list of phrases`);
    for (const p of v) {
      if (p.length > 2 && p.startsWith('/') && p.endsWith('/')) {
        try { new RegExp(p.slice(1, -1), 'i'); } catch (e) { fail(`when.${k}: bad regular expression ${p}: ${e.message}`); }
      } else if (p.length < 3) fail(`when.${k}: "${p}" is too short to be specific`);
    }
    return v;
  };
  const any = phrases('any');
  if (!any.length) fail('when.any needs at least one phrase');
  const notFrom = w.not_from ?? [];
  if (!Array.isArray(notFrom) || notFrom.some((d) => !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d))) fail('when.not_from must be a list of domains');
  const ex = r.examples ?? fail('missing "examples" (a phish and a legit one)');
  for (const k of Object.keys(ex)) if (k !== 'phish' && k !== 'legit') fail(`unknown key "examples.${k}"`);
  if (typeof ex.phish !== 'string' || typeof ex.legit !== 'string') fail('examples need "phish" and "legit" text');
  return {
    id: r.id, title: r.title, plain: r.plain, severity: r.severity, points: r.points, category: r.category ?? 'content',
    any, also: phrases('also'), subject: phrases('subject'), needsLink: w.needs_link === true, notFrom,
    examples: { phish: ex.phish, legit: ex.legit },
  };
}

export function compileAll() {
  const files = readdirSync(dir).filter((f) => f.endsWith('.yml')).sort();
  return files.map((f) => compileRule(f, readFileSync(join(dir, f), 'utf8')));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const json = `${JSON.stringify(compileAll(), null, 2)}\n`;
    if (process.argv.includes('--check')) {
      if (readFileSync(out, 'utf8') !== json) throw new Error('src/rules/rules.json is out of date: run `pnpm rules`');
      console.log('rules.json is up to date');
    } else {
      writeFileSync(out, json);
      console.log(`compiled ${JSON.parse(json).length} rules into src/rules/rules.json`);
    }
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
