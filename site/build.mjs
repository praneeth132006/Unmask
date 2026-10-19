// Builds the GitHub Pages site into _site/: the hand-written home page plus
// pages rendered from the markdown docs, so the site never drifts from the repo.
//
//   node site/build.mjs
import { readFileSync, writeFileSync, mkdirSync, cpSync, rmSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Marked } from 'marked';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, '_site');
const REPO = 'https://github.com/praneeth132006/Unmask';

/** Markdown files that become pages, and the doc links that should point at them. */
const PAGES = [
  { md: 'docs/USER_GUIDE.md', out: 'guide.html', title: 'User guide', nav: 'Guide' },
  { md: 'docs/CHECKS.md', out: 'checks.html', title: 'What Unmask checks', nav: 'Checks' },
  { md: 'docs/LIMITS_AND_COSTS.md', out: 'limits.html', title: 'Free limits and costs', nav: 'Limits' },
  { md: 'PRIVACY.md', out: 'privacy.html', title: 'Privacy policy', nav: 'Privacy' },
];
const LINK_MAP = {
  'USER_GUIDE.md': 'guide.html',
  'CHECKS.md': 'checks.html',
  'LIMITS_AND_COSTS.md': 'limits.html',
  'PRIVACY.md': 'privacy.html',
};

/** GitHub-style heading ids so the docs' own anchor links (#1-install) keep working. */
function slug(text) {
  return text
    .toLowerCase()
    .replace(/<[^>]+>/g, '')
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .trim()
    .replace(/\s/g, '-');
}

function rewriteLink(href) {
  if (/^(https?:|mailto:|#)/.test(href)) return href;
  const [path, hash] = href.split('#');
  const file = path.split('/').pop();
  if (LINK_MAP[file]) return LINK_MAP[file] + (hash ? `#${hash}` : '');
  if (path.startsWith('images/')) return path;
  // Anything else (BACKEND.md, ../SECURITY.md, source files) opens on GitHub.
  const clean = path.replace(/^(\.\.\/)+/, '').replace(/^\.\//, '');
  const inDocs = !path.startsWith('../') && !['PRIVACY.md', 'SECURITY.md', 'CONTRIBUTING.md', 'LICENSE', 'CHANGELOG.md'].includes(clean);
  const repoPath = path.startsWith('../') ? clean : inDocs && !clean.startsWith('docs/') ? `docs/${clean}` : clean;
  return `${REPO}/blob/main/${repoPath}${hash ? `#${hash}` : ''}`;
}

function render(markdown) {
  const marked = new Marked({ gfm: true });
  const seen = new Map();
  marked.use({
    renderer: {
      heading({ tokens, depth }) {
        const html = this.parser.parseInline(tokens);
        let id = slug(html);
        const n = seen.get(id) ?? 0;
        seen.set(id, n + 1);
        if (n) id = `${id}-${n}`;
        const anchor = depth > 1 && depth < 4 ? `<a class="anchor" href="#${id}" aria-label="Link to this section">#</a>` : '';
        return `<h${depth} id="${id}">${html}${anchor}</h${depth}>\n`;
      },
      link({ href, title, tokens }) {
        const text = this.parser.parseInline(tokens);
        const target = rewriteLink(href);
        const ext = /^https?:/.test(target) ? ' target="_blank" rel="noopener"' : '';
        return `<a href="${target}"${title ? ` title="${title}"` : ''}${ext}>${text}</a>`;
      },
    },
  });
  // Inline <img src="images/…"> in the markdown already points at the copied images folder.
  return marked.parse(markdown);
}

function layout({ title, body, current, description }) {
  const nav = [
    ['index.html', 'Home'],
    ...PAGES.map((p) => [p.out, p.nav]),
  ]
    .map(([href, label]) => `<a href="${href}"${href === current ? ' aria-current="page"' : ''}${label === 'Privacy' || label === 'Limits' ? ' class="hide-sm"' : ''}>${label}</a>`)
    .join('');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<meta name="description" content="${description}">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
<meta property="og:image" content="https://praneeth132006.github.io/Unmask/logo-512.png">
<meta name="theme-color" content="#222629">
<link rel="icon" href="icon-48.png">
<link rel="stylesheet" href="style.css">
<script>try{var t=localStorage.getItem('unmask-site-theme');if(t)document.documentElement.setAttribute('data-theme',t)}catch(e){}</script>
</head>
<body>
<header class="top"><div class="wrap">
  <a class="brand" href="index.html"><img src="icon-48.png" alt="" width="28" height="28">Unmask</a>
  <nav class="nav">${nav}<a href="${REPO}">GitHub</a>
    <button class="theme-btn" type="button" id="theme" title="Switch light / dark" aria-label="Switch light or dark theme">◐</button>
  </nav>
</div></header>
<main>${body}</main>
<footer><div class="wrap">
  <span>Unmask · MIT licence · Not affiliated with Google</span>
  <span><a href="${REPO}">Source</a> · <a href="${REPO}/releases/latest">Download</a> · <a href="${REPO}/wiki">Wiki</a> · <a href="${REPO}/blob/main/SECURITY.md">Security</a> · <a href="${REPO}/issues/new/choose">Report a problem</a></span>
</div></footer>
<script>
document.getElementById('theme').addEventListener('click', function () {
  var root = document.documentElement;
  var dark = root.getAttribute('data-theme') ? root.getAttribute('data-theme') === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  var next = dark ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  try { localStorage.setItem('unmask-site-theme', next); } catch (e) {}
});
</script>
</body>
</html>
`;
}

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
cpSync(join(root, 'docs', 'images'), join(out, 'images'), { recursive: true });
cpSync(join(root, 'docs', 'brand', 'logo-512.png'), join(out, 'logo-512.png'));
cpSync(join(root, 'extension', 'public', 'icon', '48.png'), join(out, 'icon-48.png'));
cpSync(join(root, 'site', 'style.css'), join(out, 'style.css'));
writeFileSync(join(out, '.nojekyll'), '');

writeFileSync(
  join(out, 'index.html'),
  layout({
    title: 'Unmask: see what a suspicious email is really hiding',
    description: 'Free, open-source Chrome extension that checks Gmail emails for phishing: real sender, real links, hidden text, trackers and risky attachments.',
    current: 'index.html',
    body: readFileSync(join(root, 'site', 'index.html'), 'utf8'),
  }),
);

for (const page of PAGES) {
  const md = readFileSync(join(root, page.md), 'utf8');
  writeFileSync(
    join(out, page.out),
    layout({ title: `${page.title} · Unmask`, description: `Unmask ${page.title.toLowerCase()}.`, current: page.out, body: `<article class="doc">${render(md)}</article>` }),
  );
}
console.log(`site built: ${['index.html', ...PAGES.map((p) => p.out)].join(', ')}`);
