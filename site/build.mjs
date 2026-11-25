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
    group('Learn', [['guide.html', 'User guide'], ['analysis.html', 'How it works'], ['checks.html', 'What it checks'], ['files.html', 'Inside attachments'], ['reports.html', 'Reports'], ['teams.html', 'Teams and families']]),
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
<meta property="og:image" content="https://praneeth132006.github.io/Unmask/media/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Unmask: see what a suspicious email is really hiding">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
<meta name="theme-color" content="#0c0e0f" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f6f7f4" media="(prefers-color-scheme: light)">
<link rel="icon" href="icon-48.png">
<link rel="apple-touch-icon" href="logo-512.png">
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
<footer class="site-foot">
  <div class="wrap">
    <div class="foot-cta">
      <p class="foot-status"><span class="pulse" aria-hidden="true"></span>Every check runs on your device. Nothing is sent to us, ever.</p>
      <a class="btn btn-primary" data-install href="${STORE.chrome}"><span data-install-label>Add to Chrome</span></a>
    </div>
    <div class="foot">
      <div class="foot-brand"><a class="brand" href="index.html"><img src="icon-48.png" alt="" width="28" height="28">Unmask</a><p>A free, open-source browser extension that shows what a suspicious email is really hiding.</p></div>
      ${col('Get it', [[STORE.chrome, 'Chrome Web Store'], [STORE.firefox, 'Firefox Add-ons'], [`${REPO}/releases/latest`, 'Latest zip (other browsers)'], ['index.html#try', 'Try it live'], ['scams.html', 'Scam watch'], ['changelog.html', 'Changelog']])}
      ${col('Learn', [['guide.html', 'User guide'], ['analysis.html', 'How it works'], ['checks.html', 'What it checks'], ['lessons.html', 'How scams work'], ['rules.html', 'Community rules'], ['teams.html', 'Teams and families']])}
      ${col('Tools', [['domain.html', 'Is your domain spoofable?'], ['check.html', 'Check a text message'], ['outlook.html', 'Outlook add-in'], ['reports.html', 'Reports'], ['files.html', 'Inside attachments']])}
      ${col('Trust', [['privacy.html', 'Privacy'], ['permissions.html', 'Permissions'], ['benchmark.html', 'Benchmark'], ['limits.html', 'Limits and costs'], [`${REPO}/blob/main/SECURITY.md`, 'Security'], [REPO, 'Source on GitHub']])}
    </div>
  </div>
  <div class="foot-mark" aria-hidden="true" data-text="UNMASK">UNMASK</div>
  <div class="wrap foot-legal"><span>© ${year} Unmask contributors · MIT licence · <a href="${REPO}/issues/new/choose">Report a problem</a> · <a href="https://github.com/sponsors/praneeth132006">Support Unmask</a></span><span>Not affiliated with Google, Microsoft or any brand named here.</span></div>
</footer>
<script>
(function () {
  var doc = document, root = doc.documentElement;
  // The install button names the visitor's browser.
  var ua = navigator.userAgent, label = 'Add to Chrome', href = ${JSON.stringify(STORE.chrome)};
  var has = function (t) { return ua.indexOf(t) >= 0; };
  if (has('Firefox/')) { label = 'Add to Firefox'; href = ${JSON.stringify(STORE.firefox)}; }
  // Published only on the Chrome Web Store and Firefox Add-ons; any other browser gets the latest release zip.
  else if (has('Edg/') || has('OPR/') || navigator.brave || (has('Safari/') && !has('Chrome/'))) { label = 'Download the latest zip'; href = ${JSON.stringify(REPO + '/releases/latest')}; }
  doc.querySelectorAll('[data-install]').forEach(function (a) { a.href = href; a.target = '_blank'; a.rel = 'noopener'; var l = a.querySelector('[data-install-label]'); if (l) l.textContent = label; });

  // Coming back to a page puts you where you left it, even if the browser forgot.
  var key = 'unmask-scroll:' + location.pathname;
  addEventListener('pagehide', function () { try { sessionStorage.setItem(key, String(scrollY)); } catch (e) {} });
  var nav = performance.getEntriesByType && performance.getEntriesByType('navigation')[0];
  if (nav && (nav.type === 'back_forward' || nav.type === 'reload') && !location.hash) {
    try { var y = Number(sessionStorage.getItem(key)); if (y) addEventListener('load', function () { if (scrollY < 10) scrollTo(0, y); }); } catch (e) {}
  }

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

  // The footer wordmark: a spotlight that "unmasks" the letters under the pointer.
  var mark = doc.querySelector('.foot-mark');
  if (mark) mark.parentElement.addEventListener('pointermove', function (e) {
    if (e.pointerType !== 'mouse') return;
    var r = mark.getBoundingClientRect();
    mark.style.setProperty('--mx', ((e.clientX - r.left) / r.width * 100) + '%');
    mark.style.setProperty('--my', ((e.clientY - r.top) / r.height * 100) + '%');
    mark.classList.add('tracking');
  });

  // The video loads from YouTube only when asked.
  doc.querySelectorAll('[data-youtube]').forEach(function (b) {
    b.addEventListener('click', function () {
      var f = doc.createElement('iframe');
      f.src = 'https://www.youtube-nocookie.com/embed/' + b.dataset.youtube + '?autoplay=1&rel=0&modestbranding=1';
      f.title = b.getAttribute('aria-label');
      f.allow = 'autoplay; encrypted-media; picture-in-picture; fullscreen';
      f.allowFullscreen = true;
      b.replaceWith(f);
    });
  });

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

/**
 * The promo video. Nothing loads from YouTube until the visitor presses play, and then
 * only from youtube-nocookie.com. Until the video is published, the poster says "Coming soon".
 */
function videoSection(v) {
  const id = /^[A-Za-z0-9_-]{6,20}$/.test(v.youtubeId ?? '') ? v.youtubeId : '';
  const label = id ? `Play the video: ${html(v.title)} (${html(v.duration)})` : 'Video coming soon';
  return `<section class="film" id="video"><div class="wrap">
  <header class="section-head reveal"><p class="kicker">Watch</p><h2>What a phishing email is really hiding, in ${html(v.duration)}.</h2></header>
  <div class="film-frame reveal">
    <button type="button" class="film-play" ${id ? `data-youtube="${id}"` : 'disabled'} aria-label="${label}">
      <img src="media/video-poster.webp" alt="" width="1600" height="900" loading="lazy" decoding="async">
      <span class="film-badge">${id ? `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>Play · ${html(v.duration)}` : 'Coming soon'}</span>
    </button>
  </div>
  ${id ? '<p class="film-note reveal">Plays from youtube-nocookie.com, only once you press play.</p>' : ''}
</div></section>`;
}

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

/** Links that leave the site open in a new tab, so the visitor's place here is kept. */
const newTab = (page) => page.replace(/<a\b(?![^>]*\btarget=)([^>]*\bhref="https?:\/\/[^"]*"[^>]*)>/g, '<a$1 target="_blank" rel="noopener">');

function write(file, page) {
  writeFileSync(join(out, file), newTab(pictures(page)));
}

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
cpSync(join(root, 'docs', 'images'), join(out, 'images'), { recursive: true });
cpSync(join(root, 'docs', 'brand', 'logo-512.png'), join(out, 'logo-512.png'));
cpSync(join(root, 'extension', 'public', 'icon', '48.png'), join(out, 'icon-48.png'));
cpSync(join(root, 'site', 'style.css'), join(out, 'style.css'));
mkdirSync(join(out, 'fonts'));
mkdirSync(join(out, 'outlook'));
cpSync(join(root, 'node_modules', '@fontsource-variable', 'inter', 'files', 'inter-latin-opsz-normal.woff2'), join(out, 'fonts', 'inter-latin-opsz-normal.woff2'));
WEBP = webpImages(join(out, 'images'));
// "Try it live", the domain checker and the Outlook add-in: the extension's own code, bundled for the browser.
const bundle = (entry, file) => execFileSync(join(root, 'extension', 'node_modules', '.bin', 'esbuild'), [join(root, 'site', entry), '--bundle', '--format=esm', '--minify', '--target=es2020', `--outfile=${join(out, file)}`, '--log-level=warning']);
bundle('demo.ts', 'demo.js');
bundle('domain.ts', 'domain.js');
bundle('outlook.ts', 'outlook/taskpane.js');
const { LESSONS } = await import('../extension/src/core/lessons.ts');
const RULES = JSON.parse(readFileSync(join(root, 'extension', 'src', 'rules', 'rules.json'), 'utf8'));
cpSync(join(root, 'site', 'media'), join(out, 'media'), { recursive: true });
const VIDEO = JSON.parse(readFileSync(join(root, 'site', 'video.json'), 'utf8'));
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
      .replace('<div data-video></div>', videoSection(VIDEO))
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

// ---- Tools and learning pages ----------------------------------------------------------
const head = (kicker, title, lead) => `<section class="page-head"><div class="wrap"><p class="kicker">${kicker}</p><h1>${title}</h1><p>${lead}</p></div></section>`;

write('lessons.html', layout({
  title: 'How scams work · Unmask',
  description: 'Short lessons on every trick Unmask looks for: how it works, how to spot it, what to do.',
  current: 'lessons.html',
  body: `${head('How scams work', 'Every trick, explained in a minute.', 'Each red flag in Unmask links here. How the trick works, how to spot it yourself, and what to do. No jargon.')}
<section class="page-body"><div class="wrap lessons">
<nav class="lesson-index" aria-label="Lessons">${LESSONS.map((l) => `<a href="#${l.id}">${html(l.title)}</a>`).join('')}</nav>
${LESSONS.map((l) => `<article class="lesson reveal" id="${l.id}"><h2>${html(l.title)}</h2><p class="lesson-sum">${html(l.summary)}</p>
<div class="lesson-grid"><div><h3>How it works</h3><p>${html(l.how)}</p></div><div><h3>How to spot it</h3><ul>${l.spot.map((x) => `<li>${html(x)}</li>`).join('')}</ul></div></div>
<p class="lesson-do"><b>What to do:</b> ${html(l.todo)}</p></article>`).join('')}
</div></section>`,
}));

write('rules.html', layout({
  title: 'Community rules · Unmask',
  description: 'Scam patterns anyone can add as a small YAML file, each tested on a real-looking scam and a real email.',
  current: 'rules.html',
  body: `${head('Community rules', 'Scam patterns anyone can add.', 'Each rule is a small YAML file. It must fire on its scam example and stay quiet on its real one, and on the 4,150 real emails of the benchmark, before it ships. <a href="${REPO}/blob/main/extension/rules/README.md">Write one</a>.')}
<section class="page-body"><div class="wrap rules-grid">${RULES.map((r) => `<article class="rule reveal"><div class="case-top"><code>rule-${html(r.id)}</code><span class="sev sev-${r.severity}">${html(r.severity)} · ${r.points} pts</span></div>
<h3>${html(r.title)}</h3><p>${html(r.plain)}</p>
<details><summary>Its tests</summary><p class="ex-label">Must fire on</p><pre>${html(r.examples.phish)}</pre><p class="ex-label">Must stay quiet on</p><pre>${html(r.examples.legit)}</pre></details>
<a href="${REPO}/blob/main/extension/rules/${r.id}.yml">View the rule →</a></article>`).join('')}</div>
<div class="wrap"><p class="callout">Seen a scam pattern Unmask misses? Copy a rule, change its phrases and examples, and open a pull request. CI proves it on the benchmark for you.</p></div></section>`,
}));

write('domain.html', layout({
  title: 'Is your domain spoofable? · Unmask',
  description: 'Check whether scammers can send email that looks like it came from your domain, and how to fix it.',
  current: 'domain.html',
  body: `${head('Free tool for businesses and schools', 'Is your domain spoofable?', 'Check whether anyone can send email that looks like it comes from your company, and get the exact records to fix it. Only the domain name is looked up, through Google Public DNS.')}
<section class="page-body"><div class="wrap dom">
<form class="dom-form" data-domain-form><label class="sr-only" for="dom-in">Your domain</label><input id="dom-in" name="domain" placeholder="yourcompany.com" autocomplete="off" autocapitalize="off" spellcheck="false" required><button class="btn btn-primary" type="submit">Check it</button></form>
<div class="dom-result" data-domain-result hidden aria-live="polite"></div>
<p class="dom-note">Reads public DNS only: SPF, DMARC, MX, DKIM at ${'common'} selector names, MTA-STS and BIMI. Nothing is stored.</p>
</div></section><script type="module" src="domain.js"></script>`,
}));

write('check.html', layout({
  title: 'Check a message · Unmask',
  description: 'Paste or share a text message, WhatsApp message or link and check it on your device.',
  current: 'check.html',
  body: `${head('Check a message', 'Got a strange text? Check it here.', 'Paste a text message, a WhatsApp message, a link or a whole email. It is checked on your device by the same engine as the extension. On Android, add this page to your home screen and you can <b>share</b> any message straight to Unmask.')}
<section class="page-body"><div class="wrap"><div class="demo" data-demo data-demo-empty>
<div class="demo-input"><div class="demo-samples" role="group" aria-label="Examples"><button type="button" data-sample="sms" aria-pressed="false">Parcel-fee text</button><button type="button" data-sample="link" aria-pressed="false">Look-alike link</button><button type="button" data-sample="email" aria-pressed="false">Fake PayPal email</button></div>
<label class="sr-only" for="demo-text">Message to check</label><textarea id="demo-text" spellcheck="false" placeholder="Paste the message or link here"></textarea>
<div class="demo-bar"><button type="button" class="btn btn-primary" data-demo-check>Check it</button><button type="button" class="btn btn-ghost" data-install-app hidden>Add to home screen</button></div></div>
<div class="demo-result" data-demo-result hidden aria-live="polite"></div></div>
<div class="steps-row"><div><span class="step-n">1</span><p>Open this page on your phone and choose <b>Add to Home screen</b>.</p></div><div><span class="step-n">2</span><p>In Messages or WhatsApp, long-press a message and tap <b>Share</b>.</p></div><div><span class="step-n">3</span><p>Pick <b>Unmask</b>. The message is checked right away, on your phone.</p></div></div>
</div></section>
<link rel="manifest" href="manifest.webmanifest"><script>
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(function () {});
var deferred; addEventListener('beforeinstallprompt', function (e) { e.preventDefault(); deferred = e; var b = document.querySelector('[data-install-app]'); b.hidden = false; b.onclick = function () { deferred.prompt(); b.hidden = true; }; });
</script><script type="module" src="demo.js"></script>`,
}));

write('outlook.html', layout({
  title: 'Unmask for Outlook · Unmask',
  description: 'An Outlook add-in that checks the open email, on Outlook on the web, Windows, Mac, iPhone and Android.',
  current: 'outlook.html',
  body: `${head('Outlook add-in · preview', 'Unmask inside Outlook, on every device.', 'A <b>Check with Unmask</b> button in Outlook on the web, Windows, Mac and the Outlook mobile apps. The email is read by Outlook’s add-in API and checked in the add-in pane; nothing is sent to any server.')}
<section class="page-body"><div class="wrap prose-narrow">
<h2>Install it</h2>
<ol class="install-steps"><li>Open <a href="https://aka.ms/olksideload">Outlook’s add-in settings</a> (Outlook on the web: <b>Get add-ins → My add-ins → Add a custom add-in → Add from URL</b>).</li><li>Paste this address: <code>https://praneeth132006.github.io/Unmask/outlook/manifest.xml</code></li><li>Open any email and press <b>Check with Unmask</b>. On a phone, it is under the email’s <b>⋯</b> menu, once installed on the web.</li></ol>
<h2>What it checks</h2><p>The sender and its authentication results, look-alike and impersonated brands, where every link really goes, wording and pressure tricks, and hidden text. Attachments are not checked in the add-in yet; the browser extension does that.</p>
<p class="note">Preview: the add-in is being prepared for Microsoft AppSource. Until it is listed there, install it from the address above. Work accounts may need an administrator to allow custom add-ins.</p>
</div></section>`,
}));

const pane = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Unmask</title>
<link rel="stylesheet" href="../style.css"><script src="https://appsforoffice.microsoft.com/lib/1/hosted/office.js"></script>
<style>body{padding:14px}.demo-result{display:block}</style></head><body>
<div class="brand" style="margin-bottom:12px"><img src="../icon-48.png" alt="" width="24" height="24">Unmask</div>
<div class="demo-result" data-outlook-result aria-live="polite"><p class="dom-wait">Loading…</p></div>
<script type="module" src="taskpane.js"></script></body></html>`;
writeFileSync(join(out, 'outlook', 'taskpane.html'), pane);
cpSync(join(root, 'site', 'outlook', 'manifest.xml'), join(out, 'outlook', 'manifest.xml'));

// The "Check a message" web app: installable, and a share target on Android.
writeFileSync(join(out, 'manifest.webmanifest'), JSON.stringify({
  name: 'Unmask: check a message', short_name: 'Unmask', start_url: 'check.html', scope: './', display: 'standalone',
  background_color: '#0c0e0f', theme_color: '#0c0e0f', description: 'Check a text message, WhatsApp message or link for scams, on your device.',
  icons: [{ src: 'media/icon-192.png', sizes: '192x192', type: 'image/png' }, { src: 'logo-512.png', sizes: '512x512', type: 'image/png', purpose: 'any maskable' }],
  share_target: { action: 'check.html', method: 'GET', params: { title: 'title', text: 'text', url: 'url' } },
}, null, 2));
writeFileSync(join(out, 'sw.js'), `// Keeps the check page working offline. Only this site's own files are cached.
const CACHE = 'unmask-check-v1';
const FILES = ['check.html', 'demo.js', 'style.css', 'fonts/inter-latin-opsz-normal.woff2', 'icon-48.png', 'media/icon-192.png'];
self.addEventListener('install', (e) => e.waitUntil(caches.open(CACHE).then((c) => c.addAll(FILES)).then(() => self.skipWaiting())));
self.addEventListener('activate', (e) => e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  const path = url.pathname.split('/').pop() || 'index.html';
  if (!FILES.includes(path) && !url.pathname.endsWith('/fonts/inter-latin-opsz-normal.woff2')) return;
  e.respondWith(fetch(e.request).then((r) => { const copy = r.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)); return r; }).catch(() => caches.match(e.request, { ignoreSearch: true })));
});
`);

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
console.log(`site built: ${['index.html', 'scams.html', 'lessons.html', 'rules.html', 'domain.html', 'check.html', 'outlook.html', ...PAGES.map((p) => p.out), '404.html'].join(', ')} (${WEBP.size} WebP images)`);
