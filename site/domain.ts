/** "Is your domain spoofable?" on the website. Only the domain name is sent, to Google Public DNS. */
import { cleanDomain, lookupPosture, type Posture } from '../extension/src/lib/domainPosture';

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
const ICON = { good: '✓', warn: '!', bad: '✕', info: 'i' } as const;

function render(p: Posture): string {
  return `<div class="dom-grade dom-${p.grade}"><p class="dom-kicker">${p.grade === 'protected' ? 'Protected' : p.grade === 'partial' ? 'Partly protected' : 'Spoofable'}</p><p class="dom-head">${esc(p.headline)}</p></div>
  <ul class="dom-checks">${p.checks
    .map((c) => `<li class="dom-${c.status}"><span class="dom-ic" aria-hidden="true">${ICON[c.status]}</span><div><p class="dom-label">${esc(c.label)}</p><p>${esc(c.says)}</p>${c.found ? `<code>${esc(c.found)}</code>` : ''}${c.fix ? `<p class="dom-fix"><b>Fix:</b> ${esc(c.fix)}</p>` : ''}</div></li>`)
    .join('')}</ul>`;
}

const form = document.querySelector<HTMLFormElement>('[data-domain-form]');
const out = document.querySelector<HTMLElement>('[data-domain-result]');
if (form && out) {
  const run = async (value: string) => {
    const d = cleanDomain(value);
    if (!d) { out.hidden = false; out.innerHTML = '<p class="dom-err">That doesn’t look like a domain. Try something like yourcompany.com.</p>'; return; }
    out.hidden = false;
    out.setAttribute('aria-busy', 'true');
    out.innerHTML = `<p class="dom-wait">Reading the public mail records of ${esc(d)}…</p>`;
    try { out.innerHTML = render(await lookupPosture(d)); history.replaceState(null, '', `?d=${encodeURIComponent(d)}`); }
    catch (e) { out.innerHTML = `<p class="dom-err">${esc(e instanceof Error ? e.message : String(e))}</p>`; }
    out.removeAttribute('aria-busy');
  };
  form.addEventListener('submit', (e) => { e.preventDefault(); void run((form.elements.namedItem('domain') as HTMLInputElement).value); });
  const pre = new URLSearchParams(location.search).get('d');
  if (pre) { (form.elements.namedItem('domain') as HTMLInputElement).value = pre; void run(pre); }
}
