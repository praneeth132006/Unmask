/**
 * The Outlook add-in's task pane: reads the open message through Office.js
 * (headers and body, never sent anywhere) and runs Unmask's engine on it.
 */
import { analyzeRawEmail } from '../extension/src/core/analyze';
import { plainSummary } from '../extension/src/core/plain';
import { verdictLabel } from '../extension/src/core/facts';
import { scoreBreakdown } from '../extension/src/core/breakdown';

declare const Office: any;
const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]!);
const call = <T,>(fn: (cb: (r: { status: string; value: T; error?: { message: string } }) => void) => void) =>
  new Promise<T>((res, rej) => fn((r) => (r.status === 'succeeded' ? res(r.value) : rej(new Error(r.error?.message ?? 'Outlook did not answer')))));

async function check(out: HTMLElement) {
  const item = Office.context.mailbox.item;
  if (!item) { out.innerHTML = '<p>Open an email to check it.</p>'; return; }
  out.innerHTML = '<p class="dom-wait">Checking this email on your device…</p>';
  const headers = item.getAllInternetHeadersAsync ? await call<string>((cb) => item.getAllInternetHeadersAsync(cb)).catch(() => '') : '';
  const html = await call<string>((cb) => item.body.getAsync(Office.CoercionType.Html, cb));
  const head = headers.trim() || [`From: ${item.from?.displayName ?? ''} <${item.from?.emailAddress ?? ''}>`, `Subject: ${item.subject ?? ''}`].join('\r\n');
  const stripped = head.split(/\r?\n(?=\S)/).filter((h) => !/^(content-type|content-transfer-encoding|mime-version):/i.test(h)).join('\r\n');
  const raw = `${stripped}\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n${html}`;
  const r = await analyzeRawEmail(raw);
  const s = plainSummary(r);
  const b = scoreBreakdown(r);
  out.dataset.verdict = r.verdict;
  out.innerHTML = `<div class="demo-head"><div class="demo-ring" style="--p:${r.score}"><span>${r.score}</span></div><div><p class="demo-verdict">${esc(verdictLabel(r))}</p><p class="demo-headline">${esc(s.headline)}</p></div></div>
    ${s.reasons.length ? `<ul class="demo-reasons">${s.reasons.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
    <p class="demo-action">${esc(s.action)}</p>
    ${b.raised.length ? `<details class="demo-why"><summary>Why the score is ${r.score}</summary><ul>${b.raised.map((p) => `<li><span>${esc(p.title)}</span><b class="up">+${p.points}</b></li>`).join('')}</ul></details>` : ''}
    <p class="demo-note">${headers ? '' : 'Outlook didn’t share this email’s headers, so sender checks are limited. '}Attachments aren’t checked in the add-in yet. Nothing was sent anywhere.</p>`;
}

Office.onReady(() => {
  const out = document.querySelector<HTMLElement>('[data-outlook-result]')!;
  const run = () => void check(out).catch((e) => { out.innerHTML = `<p class="dom-err">${esc(String(e?.message ?? e))}</p>`; });
  run();
  Office.context.mailbox.addHandlerAsync?.(Office.EventType.ItemChanged, run);
});
