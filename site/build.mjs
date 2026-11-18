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
  { md: 'docs/USER_GUIDE.md', out: 'guide.html', title: 'User guide', nav: 'Guide', main: true },
  { md: 'docs/ANALYSIS.md', out: 'analysis.html', title: 'How Unmask analyses an email', nav: 'How it works', main: true },
  { md: 'docs/CHECKS.md', out: 'checks.html', title: 'What Unmask checks', nav: 'Checks', main: true },
  { md: 'docs/BENCHMARK.md', out: 'benchmark.html', title: 'Benchmark: how often Unmask is right', nav: 'Benchmark', main: true },
  { md: 'docs/TEAMS.md', out: 'teams.html', title: 'Unmask for teams, schools and families', nav: 'Teams', main: true },
  { md: 'docs/FILE_FORENSICS.md', out: 'files.html', title: 'Looking inside attachments', nav: 'Inside attachments' },
  { md: 'docs/REPORTS.md', out: 'reports.html', title: 'Investigation reports', nav: 'Reports' },
  { md: 'docs/PERMISSIONS.md', out: 'permissions.html', title: 'Why Unmask asks for each permission', nav: 'Permissions' },
  { md: 'PRIVACY.md', out: 'privacy.html', title: 'Privacy policy', nav: 'Privacy' },
  { md: 'docs/LIMITS_AND_COSTS.md', out: 'limits.html', title: 'Free limits and costs', nav: 'Limits and costs' },
  { md: 'CHANGELOG.md', out: 'changelog.html', title: 'Changelog', nav: 'Changelog' },
];
const LINK_MAP = {
  'USER_GUIDE.md': 'guide.html',
  'ANALYSIS.md': 'analysis.html',
  'CHECKS.md': 'checks.html',
  'FILE_FORENSICS.md': 'files.html',
  'REPORTS.md': 'reports.html',
  'TEAMS.md': 'teams.html',
  'BENCHMARK.md': 'benchmark.html',
  'LIMITS_AND_COSTS.md': 'limits.html',
  'PERMISSIONS.md': 'permissions.html',
  'PRIVACY.md': 'privacy.html',
  'CHANGELOG.md': 'changelog.html',
};

/** Removes HTML tags, repeating until none are left (one pass can leave a new tag behind). */
function stripTags(text) {
  let prev;
  do {
    prev = text;
    text = text.replace(/<[^>]*>/g, '');
  } while (text !== prev);
  return text;
}

/** GitHub-style heading ids so the docs' own anchor links (#1-install) keep working. */
function slug(text) {
  return stripTags(text.toLowerCase())
    // marked escapes ' and " as entities; GitHub drops them, so drop the whole entity.
    .replace(/&(#\d+|#x[0-9a-f]+|[a-z]+);/gi, '')
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .trim()
    .replace(/\s/g, '-');
}

function rewriteLink(href) {
  if (/^(https?:|mailto:|#)/.test(href)) return href;
  const [path, hash] = href.split('#');
  const file = path.split('/').pop();
  if (LINK_MAP[file]) return LINK_MAP[file] + (hash ? `#${hash}` : '');
  if (path.startsWith('images/') || path.startsWith('examples/')) return path;
  // Anything else (BACKEND.md, ../SECURITY.md, source files) opens on GitHub.
  const clean = path.replace(/^(\.\.\/)+/, '').replace(/^\.\//, '');
  const inDocs = !path.startsWith('../') && !['PRIVACY.md', 'SECURITY.md', 'CONTRIBUTING.md', 'LICENSE', 'CHANGELOG.md', 'README.md'].includes(clean);
  const repoPath = path.startsWith('../') ? clean : inDocs && !clean.startsWith('docs/') ? `docs/${clean}` : clean;
  return `${REPO}/blob/main/${repoPath}${hash ? `#${hash}` : ''}`;
}

const esc = (t) => t.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
const attr = (tag, name) => tag.match(new RegExp(`\\s${name}\\s*=\\s*"([^"]*)"`, 'i'))?.[1] ?? '';

/** One screenshot: captioned (from its alt text), opens full size on click. */
function figure(tag, cls = 'fig') {
  const src = attr(tag, 'src');
  const alt = attr(tag, 'alt');
  const width = Number(attr(tag, 'width')) || 0;
  const style = width ? ` style="max-width:${width}px"` : '';
  return `<figure class="${cls}"${style}><a class="zoom" href="${src}" aria-label="Open full size: ${esc(alt)}"><img src="${src}" alt="${esc(alt)}" loading="lazy"></a>${alt ? `<figcaption>${alt}</figcaption>` : ''}</figure>`;
}

/**
 * Screenshots in the markdown are bare <img> tags, alone or several in a
 * centred paragraph. On the site they become captioned figures; a row of them
 * becomes a gallery, and a right-aligned one sits beside the text.
 */
export function figures(html) {
  html = html.replace(/<p[^>]*>\s*((?:<img\b[^>]*>\s*(?:&nbsp;|\s)*)+)<\/p>/gi, (_, imgs) => {
    const tags = imgs.match(/<img\b[^>]*>/gi) ?? [];
    if (tags.length === 1) return figure(tags[0], 'fig center');
    return `<div class="figs figs-${Math.min(tags.length, 3)}">${tags.map((t) => figure(t)).join('')}</div>`;
  });
  // A tall screenshot floated beside a short paragraph leaves a gap; centre it instead.
  html = html.replace(/<img\b[^>]*align\s*=\s*"right"[^>]*>/gi, (t) => figure(t, 'fig center'));
  // Any image still loose (inside a table cell, a list) still gets a caption and zoom.
  return html.replace(/(<a class="zoom"[^>]*>)?<img\b(?![^>]*loading="lazy")[^>]*>/gi, (t, inZoom) => (inZoom ? t : figure(t)));
}

/** A leading list of links to the page's own sections: the sidebar replaces it on the site. */
function dropOwnContents(html) {
  return html.replace(/^([\s\S]*?)(<ul>\s*(?:<li>\s*<a href="#[^"]+">[^<]*(?:<[^/][^>]*>[^<]*<\/[^>]+>[^<]*)*<\/a>\s*(?:<ul>[\s\S]*?<\/ul>)?\s*<\/li>\s*)+<\/ul>)/, (all, before, list) => (/<h2\b/.test(before) ? all : before));
}

/** "On this page": every h2 of the rendered page. */
function sidebar(html) {
  const items = [...html.matchAll(/<h2 id="([^"]+)">([\s\S]*?)<a class="anchor"/g)].map(([, id, text]) => `<li><a href="#${id}">${stripTags(text).trim()}</a></li>`);
  if (items.length < 3) return '';
  return `<aside class="toc" aria-label="On this page"><details open><summary>On this page</summary><ul>${items.join('')}</ul></details></aside>`;
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
  return figures(dropOwnContents(marked.parse(markdown)));
}

function layout({ title, body, current, description }) {
  const link = ([href, label]) => `<a href="${href}"${href === current ? ' aria-current="page"' : ''}>${label}</a>`;
  const main = [['index.html', 'Home'], ...PAGES.filter((p) => p.main).map((p) => [p.out, p.nav])].map(link).join('');
  const moreList = PAGES.filter((p) => !p.main);
  const more = moreList.map((p) => link([p.out, p.nav])).join('');
  const moreCurrent = moreList.some((p) => p.out === current);
  const all = [['index.html', 'Home'], ...PAGES.map((p) => [p.out, p.nav]), [REPO, 'GitHub']].map(link).join('');
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
<a class="skip" href="#content">Skip to content</a>
<header class="top"><div class="wrap">
  <a class="brand" href="index.html"><img src="icon-48.png" alt="" width="28" height="28">Unmask</a>
  <nav class="nav" aria-label="Main">${main}
    <details class="more"><summary${moreCurrent ? ' aria-current="page"' : ''}>More</summary><div class="menu">${more}</div></details>
    <a class="gh" href="${REPO}">GitHub</a>
  </nav>
  <button class="theme-btn" type="button" id="theme" title="Switch light / dark" aria-label="Switch light or dark theme">◐</button>
  <details class="burger"><summary aria-label="Menu">☰</summary><nav class="menu" aria-label="All pages">${all}</nav></details>
</div></header>
<main id="content">${body}</main>
<dialog class="lightbox" id="lightbox" aria-label="Screenshot"><button type="button" class="close" aria-label="Close">×</button><img alt=""><p></p></dialog>
<footer><div class="wrap">
  <span>Unmask · MIT licence · Not affiliated with Google</span>
  <span><a href="${REPO}">Source</a> · <a href="${REPO}/releases/latest">Download</a> · <a href="${REPO}/wiki">Wiki</a> · <a href="${REPO}/blob/main/SECURITY.md">Security</a> · <a href="${REPO}/issues/new/choose">Report a problem</a> · <a href="https://github.com/sponsors/praneeth132006">Support Unmask</a></span>
</div></footer>
<script>
// Menus close when you click elsewhere or press Escape.
document.addEventListener('click', function (e) {
  document.querySelectorAll('details.more[open], details.burger[open]').forEach(function (d) { if (!d.contains(e.target)) d.removeAttribute('open'); });
});
document.addEventListener('keydown', function (e) {
  if (e.key === 'Escape') document.querySelectorAll('details.more[open], details.burger[open]').forEach(function (d) { d.removeAttribute('open'); });
});
// Screenshots open full size in a lightbox; without JavaScript the link opens the image.
var box = document.getElementById('lightbox');
document.addEventListener('click', function (e) {
  var a = e.target.closest && e.target.closest('a.zoom');
  if (!a || !box.showModal) return;
  e.preventDefault();
  var img = a.querySelector('img');
  box.querySelector('img').src = a.getAttribute('href');
  box.querySelector('img').alt = img ? img.alt : '';
  box.querySelector('p').textContent = img ? img.alt : '';
  box.showModal();
});
box.addEventListener('click', function (e) { if (e.target === box || e.target.classList.contains('close')) box.close(); });
// On narrow screens "On this page" starts folded so the page itself comes first.
if (matchMedia('(max-width: 960px)').matches) document.querySelectorAll('.toc details').forEach(function (d) { d.removeAttribute('open'); });
document.querySelectorAll('.toc a').forEach(function (a) {
  a.addEventListener('click', function () { if (matchMedia('(max-width: 960px)').matches) a.closest('details').removeAttribute('open'); });
});
// The sidebar marks the section you are reading.
var tocLinks = document.querySelectorAll('.toc a');
if (tocLinks.length && 'IntersectionObserver' in window) {
  var byId = {};
  tocLinks.forEach(function (a) { byId[a.getAttribute('href').slice(1)] = a; });
  var spy = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) {
      if (!en.isIntersecting) return;
      tocLinks.forEach(function (a) { a.removeAttribute('aria-current'); });
      var a = byId[en.target.id];
      if (a) a.setAttribute('aria-current', 'true');
    });
  }, { rootMargin: '-80px 0px -70% 0px' });
  document.querySelectorAll('.doc h2[id]').forEach(function (h) { spy.observe(h); });
}
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
// Example reports built from real phishing emails (HTML and PDF).
cpSync(join(root, 'docs', 'examples'), join(out, 'examples'), { recursive: true });
writeFileSync(join(out, '.nojekyll'), '');

writeFileSync(
  join(out, 'index.html'),
  layout({
    title: 'Unmask: see what a suspicious email is really hiding',
    description: 'Free, open-source Chrome extension that checks Gmail emails for phishing: real sender, real links, hidden text, trackers and risky attachments.',
    current: 'index.html',
    // Screenshots on the home page open full size too.
    body: readFileSync(join(root, 'site', 'index.html'), 'utf8').replace(/<img class="shot" src="([^"]+)"([^>]*)>/g, '<a class="zoom" href="$1"><img class="shot" src="$1"$2></a>'),
  }),
);

function docPage(html) {
  const side = sidebar(html);
  return side ? `<div class="doc-layout">${side}<article class="doc">${html}</article></div>` : `<article class="doc">${html}</article>`;
}

for (const page of PAGES) {
  const md = readFileSync(join(root, page.md), 'utf8');
  writeFileSync(
    join(out, page.out),
    layout({ title: `${page.title} · Unmask`, description: `Unmask ${page.title.toLowerCase()}.`, current: page.out, body: docPage(render(md)) }),
  );
}
// GitHub Pages serves 404.html for any unknown path. <base> keeps its relative links working from nested paths.
writeFileSync(
  join(out, '404.html'),
  layout({
    title: 'Page not found · Unmask',
    description: 'This page does not exist.',
    current: '',
    body: '<article class="doc"><h1>Page not found</h1><p>That page does not exist. Try the <a href="index.html">home page</a> or the <a href="guide.html">user guide</a>.</p></article>',
  }).replace('<head>\n', '<head>\n<base href="/Unmask/">\n'),
);
console.log(`site built: ${['index.html', ...PAGES.map((p) => p.out), '404.html'].join(', ')}`);
