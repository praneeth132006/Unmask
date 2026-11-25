/**
 * "Try it live" on the website: the extension's own analysis engine, running
 * in the visitor's browser. Nothing typed here is sent anywhere.
 * Bundled by site/build.mjs into _site/demo.js and loaded only when needed.
 */
import { analyzePasted } from '../extension/src/core/pasted';
import { scoreBreakdown } from '../extension/src/core/breakdown';
import { plainSummary } from '../extension/src/core/plain';
import { verdictLabel } from '../extension/src/core/facts';
import { EXAMPLE_EMAIL } from '../extension/src/demo/example';
import { PRACTICE } from '../extension/src/demo/practice';

const realOne = PRACTICE.find((p) => !p.scam)?.raw ?? '';
const SAMPLES: Record<string, string> = {
  email: EXAMPLE_EMAIL,
  sms: 'USPS: Your package is on hold due to an unpaid $1.99 fee. Pay within 24 hours or it will be returned: https://usps-redelivery-fee.top/pay',
  link: 'paypa1-secure.top/signin',
  real: realOne,
};

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);

async function run(root: HTMLElement, text: string) {
  const out = root.querySelector<HTMLElement>('[data-demo-result]')!;
  if (!text.trim()) {
    out.hidden = true;
    return;
  }
  out.hidden = false;
  out.setAttribute('aria-busy', 'true');
  const report = await analyzePasted(text);
  const raw = plainSummary(report);
  // A pasted text isn't an email: say "message" so the words match what the person pasted.
  const word = (t: string) => (report.kind === 'email' ? t : t.replace(/\bemails?\b/g, (w) => (w.endsWith('s') ? 'messages' : 'message')));
  const s = { headline: word(raw.headline), reasons: raw.reasons.map(word), action: word(raw.action) };
  const b = scoreBreakdown(report);
  const max = Math.max(1, ...[...b.raised, ...b.lowered].map((p) => Math.abs(p.points)));
  const label = verdictLabel(report);
  const from = report.kind === 'email' && report.email.from ? `<p class="demo-from">${esc(report.email.from.name ? `${report.email.from.name} · ` : '')}<code>${esc(report.email.from.address)}</code></p>` : '';
  out.dataset.verdict = report.verdict;
  out.innerHTML = `
    <div class="demo-head">
      <div class="demo-ring" style="--p:${report.score}"><span>${report.score}</span></div>
      <div><p class="demo-verdict">${esc(label)}</p><p class="demo-headline">${esc(s.headline)}</p>${from}</div>
    </div>
    ${s.reasons.length ? `<ul class="demo-reasons">${s.reasons.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
    <p class="demo-action">${esc(s.action)}</p>
    ${b.raised.length || b.lowered.length ? `<details class="demo-why"><summary>Why the score is ${report.score}</summary><ul>${[...b.raised, ...b.lowered]
      .map((p) => `<li><span>${esc(p.title)}</span><b class="${p.points > 0 ? 'up' : 'down'}">${p.points > 0 ? '+' : '−'}${Math.abs(p.points)}</b><i style="width:${Math.max(4, (Math.abs(p.points) / max) * 100)}%" class="${p.points > 0 ? 'up' : 'down'}"></i></li>`)
      .join('')}</ul></details>` : ''}
    <p class="demo-note">${report.kind === 'email' ? 'Checked with the same engine as the extension, in this tab.' : 'A message has no sender to check, so only its links and wording count.'} Nothing was sent anywhere.</p>`;
  out.removeAttribute('aria-busy');
}

export function mount(root: HTMLElement) {
  const input = root.querySelector<HTMLTextAreaElement>('textarea')!;
  const go = () => void run(root, input.value);
  root.querySelectorAll<HTMLButtonElement>('[data-sample]').forEach((btn) =>
    btn.addEventListener('click', () => {
      root.querySelectorAll('[data-sample]').forEach((b) => b.setAttribute('aria-pressed', String(b === btn)));
      input.value = SAMPLES[btn.dataset.sample!] ?? '';
      go();
    }),
  );
  root.querySelector('[data-demo-check]')!.addEventListener('click', go);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) go(); });
  // Shared from another app (Android share sheet) or linked with ?text=: check that instead of an example.
  const q = new URLSearchParams(location.search);
  const shared = [q.get('title'), q.get('text'), q.get('url')].filter(Boolean).join('\n').trim();
  if (shared) {
    input.value = shared;
    go();
  } else if (!root.hasAttribute('data-demo-empty')) root.querySelector<HTMLButtonElement>('[data-sample="email"]')?.click();
}

const el = document.querySelector<HTMLElement>('[data-demo]');
if (el) mount(el);
