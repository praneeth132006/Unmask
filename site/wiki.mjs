// Generates GitHub Wiki pages from the docs: the user guide is split into one
// page per section, plus the checks and limits references, a Home page and a
// sidebar. Links and images are rewritten to work inside the wiki.
//
//   node site/wiki.mjs <wiki-checkout-dir>
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = process.argv[2];
if (!outDir) {
  console.error('usage: node site/wiki.mjs <wiki-checkout-dir>');
  process.exit(1);
}
const REPO = 'https://github.com/praneeth132006/Unmask';
const RAW = 'https://raw.githubusercontent.com/praneeth132006/Unmask/main';
const SITE = 'https://praneeth132006.github.io/Unmask';

/** User-guide section number → wiki page name. */
const GUIDE_PAGES = {
  1: 'Install',
  2: 'Your-first-check',
  3: 'Reading-the-report',
  4: 'Hover-to-see-it-in-the-email',
  5: 'Setting-up-VirusTotal',
  6: 'Setting-up-urlscan.io',
  7: 'Tracing-redirects',
  8: 'Emails-from-Outlook-and-other-apps',
  9: 'Settings',
  10: 'Troubleshooting',
  11: 'FAQ',
};
const DOC_PAGES = { 'CHECKS.md': 'What-Unmask-checks', 'LIMITS_AND_COSTS.md': 'Free-limits-and-costs' };

function slug(text) {
  return text.toLowerCase().replace(/<[^>]+>/g, '').replace(/[^\p{L}\p{N}\s-]/gu, '').trim().replace(/\s/g, '-');
}

/** Maps a user-guide anchor (#5-setting-up-virustotal) to the page holding it. */
const guide = readFileSync(join(root, 'docs', 'USER_GUIDE.md'), 'utf8');
const sections = guide.split(/^(?=## \d+\. )/m);
const anchorPage = new Map();
for (const sec of sections.slice(1)) {
  const n = Number(sec.match(/^## (\d+)\./)[1]);
  for (const h of sec.matchAll(/^#{2,4} (.+)$/gm)) anchorPage.set(slug(h[1]), GUIDE_PAGES[n]);
}

function rewrite(md) {
  return md
    .replace(/(src="|\]\()images\//g, `$1${RAW}/docs/images/`)
    .replace(/\]\(([^)\s]+)\)/g, (m, href) => {
      if (/^(https?:|mailto:)/.test(href)) return m;
      const [path, hash] = href.split('#');
      const file = path.split('/').pop();
      if (!path && hash) return `](${anchorPage.has(hash) ? `${anchorPage.get(hash)}#${hash}` : `#${hash}`})`;
      if (file === 'USER_GUIDE.md') return `](${hash && anchorPage.has(hash) ? `${anchorPage.get(hash)}#${hash}` : 'Home'})`;
      if (DOC_PAGES[file]) return `](${DOC_PAGES[file]}${hash ? `#${hash}` : ''})`;
      const clean = path.replace(/^(\.\.\/)+/, '');
      const repoPath = path.startsWith('../') || ['PRIVACY.md', 'SECURITY.md', 'CONTRIBUTING.md'].includes(clean) ? clean : `docs/${clean}`;
      return `](${REPO}/blob/main/${repoPath}${hash ? `#${hash}` : ''})`;
    });
}

const note = (src) => `\n\n---\n_This page is generated from [\`${src}\`](${REPO}/blob/main/${src}). Edit it there, not in the wiki._\n`;

// Fresh output, keeping the wiki's .git folder.
mkdirSync(outDir, { recursive: true });
for (const f of readdirSync(outDir)) if (f !== '.git') rmSync(join(outDir, f), { recursive: true, force: true });

const pages = [];
for (const sec of sections.slice(1)) {
  const n = Number(sec.match(/^## (\d+)\./)[1]);
  const name = GUIDE_PAGES[n];
  // Drop the "N. " number and the trailing --- separator; promote ### to ## for the page.
  const body = sec
    .replace(/^## \d+\. (.+)\n/, '')
    .replace(/\n---\s*$/, '')
    .replace(/^### /gm, '## ')
    .replace(/^#### /gm, '### ');
  writeFileSync(join(outDir, `${name}.md`), rewrite(body.trim()) + note('docs/USER_GUIDE.md'));
  pages.push(name);
}
for (const [file, name] of Object.entries(DOC_PAGES)) {
  const md = readFileSync(join(root, 'docs', file), 'utf8').replace(/^# .+\n/, '');
  writeFileSync(join(outDir, `${name}.md`), rewrite(md.trim()) + note(`docs/${file}`));
}

const intro = guide.split(/^- \[1\./m)[0].replace(/^# .+\n/, '').trim();
writeFileSync(
  join(outDir, 'Home.md'),
  `<p align="center"><img src="${RAW}/docs/brand/logo-512.png" width="96" alt="Unmask logo"></p>

**Unmask** is a free Chrome extension that shows what a suspicious email is really hiding: the real sender, where every link goes, hidden text, trackers and risky attachments, explained in plain language.

${intro}

## Quick start

1. **Download** \`unmask-chrome-<version>.zip\` from the [latest release](${REPO}/releases/latest) (under *Assets*) and unzip it.
2. **Load it:** open \`chrome://extensions\`, switch on **Developer mode**, click **Load unpacked**, and pick the unzipped folder (the one containing \`manifest.json\`).
3. **Use it:** reload Gmail, open an email and click the Unmask icon.

Full steps and common errors: **[[Install]]**.

## User guide

${pages.map((p, i) => `${i + 1}. [[${p.replace(/-/g, ' ')}|${p}]]`).join('\n')}

## Reference

- [[What Unmask checks|What-Unmask-checks]]: every check and its points
- [[Free limits and costs|Free-limits-and-costs]]: VirusTotal, urlscan.io and more; free keys are never charged
- [Privacy policy](${REPO}/blob/main/PRIVACY.md) · [Security policy](${REPO}/blob/main/SECURITY.md) · [Contributing](${REPO}/blob/main/CONTRIBUTING.md)

Also on the website: **[${SITE.replace('https://', '')}](${SITE}/)**.
` + note('docs/USER_GUIDE.md'),
);

writeFileSync(
  join(outDir, '_Sidebar.md'),
  `**[[Home]]**

**Get started**
${pages.slice(0, 4).map((p) => `- [[${p.replace(/-/g, ' ')}|${p}]]`).join('\n')}

**Optional checks**
${pages.slice(4, 7).map((p) => `- [[${p.replace(/-/g, ' ')}|${p}]]`).join('\n')}

**More**
${pages.slice(7).map((p) => `- [[${p.replace(/-/g, ' ')}|${p}]]`).join('\n')}

**Reference**
- [[What Unmask checks|What-Unmask-checks]]
- [[Free limits and costs|Free-limits-and-costs]]

[⬇ Download](${REPO}/releases/latest) · [Website](${SITE}/)
`,
);
writeFileSync(join(outDir, '_Footer.md'), `[Unmask](${REPO}) · MIT licence · [Report a problem](${REPO}/issues/new/choose)\n`);
console.log(`wiki pages: Home, ${pages.join(', ')}, ${Object.values(DOC_PAGES).join(', ')}`);
