// Builds the GitHub Pages site into _site/: the hand-written home page plus
// pages rendered from the markdown docs, so the site never drifts from the repo.
//
//   node site/build.mjs
import { readFileSync, writeFileSync, mkdirSync, cpSync, rmSync, readdirSync, existsSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Marked } from 'marked';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, '_site');
const REPO = 'https://github.com/praneeth132006/Unmask';
const STORE = {
  chrome: 'https://chromewebstore.google.com/detail/unmask-%E2%80%94-phishing-email-i/bcogajaabcenbcbfbcgfjmccjdlfklcc',
  firefox: 'https://addons.mozilla.org/en-US/firefox/addon/unmask-phishing-inspector/',
};

/** Markdown files that become pages, and the doc links that should point at them. */
const PAGES = [
  { md: 'docs/USER_GUIDE.md', out: 'guide.html', title: 'User guide', nav: 'Guide', main: true, groups: [[1, 'Get started'], [4, 'Everyday protection'], [11, 'Deeper checks'], [17, 'Reports, settings and help']] },
  { md: 'docs/ANALYSIS.md', out: 'analysis.html', title: 'How Unmask analyses an email', nav: 'How it works', main: true },
  { md: 'docs/CHECKS.md', out: 'checks.html', title: 'What Unmask checks', nav: 'Checks', main: true },
  { md: 'docs/BENCHMARK.md', out: 'benchmark.html', title: 'Benchmark: how often Unmask is right', nav: 'Benchmark', main: true },
  { md: 'docs/TEAMS.md', out: 'teams.html', title: 'Unmask for teams, schools and families', nav: 'Teams', main: true },
  { md: 'docs/SAFARI.md', out: 'safari.html', title: 'Unmask for Safari', nav: 'Safari' },
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
  'SAFARI.md': 'safari.html',
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

/** "On this page": every h2 of the rendered page, in groups when the page has them, with a filter box. */
function sidebar(html, groups = []) {
  const heads = [...html.matchAll(/<h2 id="([^"]+)">([\s\S]*?)<a class="anchor"/g)].map(([, id, text]) => ({ id, text: stripTags(text).trim() }));
  if (heads.length < 3) return '';
  const item = (h) => `<li><a href="#${h.id}">${h.text}</a></li>`;
  let body;
  if (groups.length) {
    const num = (h) => Number(h.text.match(/^(\d+)\./)?.[1] ?? 0);
    body = groups
      .map(([from, label], i) => {
        const to = groups[i + 1]?.[0] ?? Infinity;
        const inGroup = heads.filter((h) => num(h) >= from && num(h) < to);
        return inGroup.length ? `<p class="group">${label}</p><ul>${inGroup.map(item).join('')}</ul>` : '';
      })
      .join('');
  } else body = `<ul>${heads.map(item).join('')}</ul>`;
  const search = heads.length >= 8 ? '<input class="toc-search" type="search" placeholder="Filter sections" aria-label="Filter sections" data-toc-filter>' : '';
  return `<aside class="toc" aria-label="On this page"><details open><summary>On this page</summary>${search}${body}</details></aside>`;
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
  const main = [['index.html#features', 'Features'], ['analysis.html', 'How it works'], ['benchmark.html', 'Benchmark'], ['teams.html', 'Teams'], ['guide.html', 'Guide']].map(link).join('');
  const group = (label, items) => `<p class="menu-label">${label}</p>${items.map(link).join('')}`;
  const burger = [
    group('Product', [['index.html', 'Home'], ['index.html#try', 'Try it live'], ['scams.html', 'Scam watch'], ['benchmark.html', 'Benchmark'], ['changelog.html', 'Changelog']]),
    group('Learn', [['guide.html', 'User guide'], ['analysis.html', 'How it works'], ['checks.html', 'What it checks'], ['files.html', 'Inside attachments'], ['reports.html', 'Reports'], ['teams.html', 'Teams and families'], ['safari.html', 'Safari']]),
    group('Trust', [['privacy.html', 'Privacy'], ['permissions.html', 'Permissions'], ['limits.html', 'Limits and costs'], [REPO, 'GitHub']]),
  ].join('');
  const col = (h, items) => `<div><h4>${h}</h4><ul>${items.map(([href, label]) => `<li><a href="${href}">${label}</a></li>`).join('')}</ul></div>`;
  const year = new Date().getFullYear();
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
<meta name="twitter:card" content="summary">
<meta name="theme-color" content="#0c0e0f" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f6f7f4" media="(prefers-color-scheme: light)">
<link rel="icon" href="icon-48.png">
<link rel="preload" href="fonts/inter-latin-opsz-normal.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="style.css">
<script>document.documentElement.classList.add('js');try{var t=localStorage.getItem('unmask-site-theme');if(t)document.documentElement.setAttribute('data-theme',t)}catch(e){}</script>
</head>
<body>
<a class="skip" href="#content">Skip to content</a>
<header class="top"><div class="wrap">
  <a class="brand" href="index.html"><img src="icon-48.png" alt="" width="28" height="28">Unmask</a>
  <nav class="nav" aria-label="Main">${main}</nav>
  <div class="top-actions">
    <button class="theme-btn" type="button" id="theme" aria-label="Switch between light and dark theme"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M12 4a8 8 0 0 0 0 16z" fill="currentColor"/></svg><span class="theme-label" data-theme-label>Theme</span></button>
    <a class="btn btn-primary top-cta" data-install href="${STORE.chrome}"><span data-install-label>Add to Chrome</span></a>
    <details class="burger"><summary aria-label="Menu"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg></summary><nav class="menu" aria-label="All pages">${burger}</nav></details>
  </div>
</div></header>
<main id="content">${body}</main>
<dialog class="lightbox" id="lightbox" aria-label="Screenshot"><button type="button" class="close" aria-label="Close">×</button><img alt=""><p></p></dialog>
<footer><div class="wrap">
  <div class="foot">
    <div class="foot-brand"><a class="brand" href="index.html"><img src="icon-48.png" alt="" width="28" height="28">Unmask</a><p>A free, open-source browser extension that shows what a suspicious email is really hiding. Your email never leaves your device.</p></div>
    ${col('Product', [[STORE.chrome, 'Chrome, Edge, Brave'], [STORE.firefox, 'Firefox'], ['safari.html', 'Safari (preview)'], ['index.html#try', 'Try it live'], ['scams.html', 'Scam watch'], ['changelog.html', 'Changelog']])}
    ${col('Learn', [['guide.html', 'User guide'], ['analysis.html', 'How it works'], ['checks.html', 'What it checks'], ['files.html', 'Inside attachments'], ['reports.html', 'Reports'], ['teams.html', 'Teams and families']])}
    ${col('Trust', [['privacy.html', 'Privacy'], ['permissions.html', 'Permissions'], ['benchmark.html', 'Benchmark'], ['limits.html', 'Limits and costs'], [`${REPO}/blob/main/SECURITY.md`, 'Security']])}
    ${col('Project', [[REPO, 'GitHub'], [`${REPO}/wiki`, 'Wiki'], [`${REPO}/issues/new/choose`, 'Report a problem'], [`${REPO}/blob/main/CONTRIBUTING.md`, 'Contribute'], ['https://github.com/sponsors/praneeth132006', 'Support Unmask']])}
  </div>
  <div class="foot-legal"><span>© ${year} Unmask contributors · MIT licence</span><span>Not affiliated with Google, Microsoft or any brand named here.</span></div>
</div></footer>
<script>
(function () {
  var doc = document, root = doc.documentElement;
  // The install button names the visitor's browser.
  var ua = navigator.userAgent, label = 'Add to Chrome', href = ${JSON.stringify(STORE.chrome)};
  var has = function (t) { return ua.indexOf(t) >= 0; };
  if (has('Firefox/')) { label = 'Add to Firefox'; href = ${JSON.stringify(STORE.firefox)}; }
  else if (has('Edg/')) label = 'Add to Edge';
  else if (navigator.brave) label = 'Add to Brave';
  else if (has('Safari/') && !has('Chrome/')) { label = 'Get it for Safari'; href = 'safari.html'; }
  doc.querySelectorAll('[data-install]').forEach(function (a) { a.href = href; var l = a.querySelector('[data-install-label]'); if (l) l.textContent = label; });

  // Sections fade in as they arrive.
  // Content is never left hidden: whatever is on screen shows at once, a scroll check backs up
  // the observer, and without either everything simply shows.
  var items = [].slice.call(doc.querySelectorAll('.reveal'));
  var show = function () {
    var limit = innerHeight * 0.94;
    items = items.filter(function (el) { if (el.getBoundingClientRect().top < limit) { el.classList.add('in'); return false; } return true; });
    if (!items.length) removeEventListener('scroll', onScroll);
  };
  var ticking = false;
  var onScroll = function () { if (!ticking) { ticking = true; requestAnimationFrame(function () { ticking = false; show(); }); } };
  if (matchMedia('(prefers-reduced-motion: reduce)').matches || !('requestAnimationFrame' in window)) items.forEach(function (el) { el.classList.add('in'); });
  else {
    show();
    addEventListener('scroll', onScroll, { passive: true });
    addEventListener('resize', onScroll);
    if ('IntersectionObserver' in window) {
      var io = new IntersectionObserver(function (es) { es.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } }); }, { rootMargin: '0px 0px -6% 0px' });
      items.forEach(function (el) { io.observe(el); });
    }
  }

  // "Try it live" loads the analysis engine only when it comes near.
  var demo = doc.querySelector('[data-demo]');
  if (demo) {
    var load = function () { if (demo.dataset.loaded) return; demo.dataset.loaded = '1'; var s = doc.createElement('script'); s.type = 'module'; s.src = 'demo.js'; doc.body.appendChild(s); };
    if ('IntersectionObserver' in window) new IntersectionObserver(function (es, o) { if (es[0].isIntersecting) { load(); o.disconnect(); } }, { rootMargin: '600px' }).observe(demo); else load();
    demo.addEventListener('focusin', load);
  }

  // Menus close when you click elsewhere or press Escape.
  doc.addEventListener('click', function (e) { doc.querySelectorAll('details.burger[open]').forEach(function (d) { if (!d.contains(e.target)) d.removeAttribute('open'); }); });
  doc.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') doc.querySelectorAll('details.burger[open]').forEach(function (d) { d.removeAttribute('open'); });
    // Cmd/Ctrl+K or / jumps to the section filter on docs pages.
    var f = doc.querySelector('[data-toc-filter]');
    if (f && ((e.key === 'k' && (e.metaKey || e.ctrlKey)) || (e.key === '/' && !/INPUT|TEXTAREA/.test(doc.activeElement.tagName)))) { e.preventDefault(); var d = f.closest('details'); if (d) d.open = true; f.focus(); }
  });
  var filter = doc.querySelector('[data-toc-filter]');
  if (filter) filter.addEventListener('input', function () {
    var q = filter.value.trim().toLowerCase();
    doc.querySelectorAll('.toc li').forEach(function (li) { li.hidden = q && li.textContent.toLowerCase().indexOf(q) < 0; });
    doc.querySelectorAll('.toc .group').forEach(function (g) { var ul = g.nextElementSibling; g.hidden = !!ul && !ul.querySelector('li:not([hidden])'); });
  });

  // Screenshots open full size in a lightbox; without JavaScript the link opens the image.
  var box = doc.getElementById('lightbox');
  doc.addEventListener('click', function (e) {
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
  if (matchMedia('(max-width: 960px)').matches) doc.querySelectorAll('.toc details').forEach(function (d) { d.removeAttribute('open'); });
  var tocLinks = doc.querySelectorAll('.toc a');
  tocLinks.forEach(function (a) { a.addEventListener('click', function () { if (matchMedia('(max-width: 960px)').matches) a.closest('details').removeAttribute('open'); }); });
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
    doc.querySelectorAll('.doc h2[id]').forEach(function (h) { spy.observe(h); });
  }

  // Theme: follows the system until you choose; the button says what it will switch to.
  var btn = doc.getElementById('theme'), lab = doc.querySelector('[data-theme-label]');
  var isDark = function () { var t = root.getAttribute('data-theme'); return t ? t === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches; };
  var sync = function () { var next = isDark() ? 'Light' : 'Dark'; if (lab) lab.textContent = next; btn.setAttribute('aria-label', 'Switch to ' + next.toLowerCase() + ' theme'); btn.title = 'Switch to ' + next.toLowerCase() + ' theme'; };
  sync();
  btn.addEventListener('click', function () {
    var next = isDark() ? 'light' : 'dark';
    root.setAttribute('data-theme', next);
    try { localStorage.setItem('unmask-site-theme', next); } catch (e) {}
    sync();
  });
})();
</script>
</body>
</html>
`;
}

/** Defanged text stays defanged; everything else is escaped. */
const html = (t) => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function scamCard(c) {
  return `<article class="case reveal"><div class="case-top"><span>${html(c.brand)} · ${html(c.date)}</span><span class="case-risk">High risk ${c.score}</span></div><h3>${html(c.title)}</h3><p class="lure">${html(c.lure)}</p><ul>${c.tells.map((t) => `<li>${html(t)}</li>`).join('')}</ul><p class="lesson">${html(c.lesson)}</p><a href="${c.report}">Read the full report →</a></article>`;
}

/**
 * Screenshots as WebP where cwebp is installed (about a fifth of the PNG size),
 * served with a <picture> so any browser without WebP still gets the PNG.
 */
function webpImages(dir) {
  try {
    execFileSync('cwebp', ['-version'], { stdio: 'ignore' });
  } catch {
    console.warn('cwebp not found: screenshots are served as PNG only');
    return new Set();
  }
  const made = new Set();
  const walk = (d) => {
    for (const f of readdirSync(d)) {
      const p = join(d, f);
      if (statSync(p).isDirectory()) walk(p);
      else if (f.endsWith('.png')) {
        execFileSync('cwebp', ['-quiet', '-q', '80', '-m', '6', p, '-o', p.replace(/\.png$/, '.webp')]);
        made.add(p.slice(out.length + 1).replace(/\\/g, '/'));
      }
    }
  };
  walk(dir);
  return made;
}

let WEBP = new Set();
/** <img src="images/x.png"> → <picture> with the WebP first; lazy images decode off the main thread. */
function pictures(page) {
  return page.replace(/<img\b([^>]*?)\ssrc="(images\/[^"]+\.png)"([^>]*)>/g, (tag, before, src, after) => {
    const img = `<img${before} src="${src}"${after.includes('decoding=') ? '' : ' decoding="async"'}${after}>`;
    return WEBP.has(src) ? `<picture><source srcset="${src.replace(/\.png$/, '.webp')}" type="image/webp">${img}</picture>` : img;
  });
}

function write(file, page) {
  writeFileSync(join(out, file), pictures(page));
}

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
cpSync(join(root, 'docs', 'images'), join(out, 'images'), { recursive: true });
cpSync(join(root, 'docs', 'brand', 'logo-512.png'), join(out, 'logo-512.png'));
cpSync(join(root, 'extension', 'public', 'icon', '48.png'), join(out, 'icon-48.png'));
cpSync(join(root, 'site', 'style.css'), join(out, 'style.css'));
mkdirSync(join(out, 'fonts'));
cpSync(join(root, 'node_modules', '@fontsource-variable', 'inter', 'files', 'inter-latin-opsz-normal.woff2'), join(out, 'fonts', 'inter-latin-opsz-normal.woff2'));
WEBP = webpImages(join(out, 'images'));
// "Try it live": the extension's own engine, bundled for the browser.
execFileSync(join(root, 'extension', 'node_modules', '.bin', 'esbuild'), [join(root, 'site', 'demo.ts'), '--bundle', '--format=esm', '--minify', '--target=es2020', `--outfile=${join(out, 'demo.js')}`, '--log-level=warning']);
const SCAMS = JSON.parse(readFileSync(join(root, 'docs', 'scams.json'), 'utf8')).items;
// Example reports built from real phishing emails (HTML and PDF).
cpSync(join(root, 'docs', 'examples'), join(out, 'examples'), { recursive: true });
writeFileSync(join(out, '.nojekyll'), '');

write(
  'index.html',
  layout({
    title: 'Unmask: see what a suspicious email is really hiding',
    description: 'Free, open-source Chrome extension that checks Gmail emails for phishing: real sender, real links, hidden text, trackers and risky attachments.',
    current: 'index.html',
    // Screenshots on the home page open full size too.
    body: readFileSync(join(root, 'site', 'index.html'), 'utf8')
      .replace(/<img class="(shot[^"]*)" src="([^"]+)"([^>]*)>/g, '<a class="zoom" href="$2"><img class="$1" src="$2"$3></a>')
      .replace('<div class="watch-grid" data-scam-watch></div>', `<div class="watch-grid">${SCAMS.slice(0, 3).map(scamCard).join('')}</div>`),
  }),
);

function docPage(html, groups) {
  const side = sidebar(html, groups);
  return side ? `<div class="doc-layout">${side}<article class="doc">${html}</article></div>` : `<article class="doc">${html}</article>`;
}

for (const page of PAGES) {
  const md = readFileSync(join(root, page.md), 'utf8');
  write(
    page.out,
    layout({ title: `${page.title} · Unmask`, description: `Unmask ${page.title.toLowerCase()}.`, current: page.out, body: docPage(render(md), page.groups) }),
  );
}
write(
  'scams.html',
  layout({
    title: 'Scam watch · Unmask',
    description: 'Real phishing emails taken apart by Unmask, with the tells to look for.',
    current: 'scams.html',
    body: `<section class="page-head"><div class="wrap"><p class="kicker">Scam watch</p><h1>Real scams, taken apart.</h1><p>Real phishing emails Unmask analysed, newest first, with the tells that give each away. Only real cases from public research collections or reports whose senders agreed to publish them. Every address is defanged so nothing here can be clicked by mistake.</p></div></section><section class="page-body"><div class="wrap"><div class="watch-grid">${SCAMS.map(scamCard).join('')}</div><p class="callout">Got one Unmask missed, or got wrong? Press <strong>Was this right?</strong> in the panel. You choose exactly what is shared, and nothing is sent without you pressing Send. <a href="${REPO}/blob/main/CONTRIBUTING.md">How cases are added</a>.</p></div></section>`,
  }),
);
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
console.log(`site built: ${['index.html', 'scams.html', ...PAGES.map((p) => p.out), '404.html'].join(', ')} (${WEBP.size} WebP images)`);
