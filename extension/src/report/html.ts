/**
 * Self-contained HTML report: one file, no scripts, no network, prints
 * cleanly to PDF from any browser. Every value is escaped.
 */
import type { Block, CaseDoc, Section, Tone } from './model';

const esc = (s: string): string => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const PART_TITLE: Record<Section['part'], string> = { executive: 'Part A: Executive summary', technical: 'Part B: Technical analysis', appendix: 'Appendices' };
const PART_LEAD: Record<Section['part'], string> = { executive: 'For leaders, managers and non-technical staff. Plain language.', technical: 'For security analysts, incident responders and investigators. Full evidence and detail.', appendix: 'Reference material.' };

const CSS = `
:root{--bad:#b3261e;--bad-bg:#fdecea;--warn:#8a5300;--warn-bg:#fff4e0;--good:#1b6e3c;--good-bg:#e8f6ee;--info:#2a4a8a;--info-bg:#eaf0fb;--ink:#1d2024;--mute:#5d6470;--line:#d9dde3;--soft:#f5f6f8;--accent:#3d6b1f}
*{box-sizing:border-box}
body{margin:0;font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:#fff}
main{max-width:920px;margin:0 auto;padding:28px 24px 60px}
.cover{border-radius:14px;background:#22272b;color:#fff;padding:30px 32px;margin-bottom:22px}
.cover small{opacity:.75;letter-spacing:.08em;text-transform:uppercase;font-size:11px}
.cover h1{margin:6px 0 4px;font-size:30px;line-height:1.15}
.cover p{margin:0;opacity:.9;overflow-wrap:anywhere}
.badge{display:inline-block;margin-top:16px;padding:6px 14px;border-radius:999px;font-weight:700;font-size:14px}
.badge.bad{background:var(--bad);color:#fff}.badge.warn{background:#f2b34c;color:#3a2500}.badge.good{background:#58b97c;color:#06240f}.badge.info{background:#8ab0ff;color:#0a1f4d}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px 18px;margin-top:18px;font-size:13px}
.meta b{display:block;font-size:10.5px;opacity:.65;text-transform:uppercase;letter-spacing:.06em;font-weight:600}
nav.toc{border:1px solid var(--line);border-radius:12px;padding:14px 18px;margin-bottom:26px;background:var(--soft)}
nav.toc h2{margin:0 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.07em;color:var(--mute)}
nav.toc ol{margin:0;padding-left:20px;columns:2;column-gap:28px}
nav.toc a{color:var(--ink);text-decoration:none}nav.toc a:hover{text-decoration:underline}
.part{margin:44px 0 6px;padding:16px 20px;border-radius:12px;background:var(--accent);color:#fff}
.part h2{margin:0;font-size:22px}.part p{margin:2px 0 0;opacity:.9;font-size:13px}
section{margin-top:30px;break-inside:auto}
section>h2{margin:0 0 4px;font-size:21px;border-bottom:2px solid var(--line);padding-bottom:6px}
.lead{margin:2px 0 12px;color:var(--mute);font-size:13px}
h3{margin:18px 0 6px;font-size:15px}
p{margin:8px 0;overflow-wrap:anywhere}p.small{font-size:12px;color:var(--mute)}
ul{margin:6px 0 6px;padding-left:22px}li{margin:3px 0;overflow-wrap:anywhere}
ul.check{list-style:none;padding-left:4px}ul.check li:before{content:"\\2610  ";font-size:15px}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:12.5px}
th{background:#2e353b;color:#fff;text-align:left;padding:6px 8px;font-weight:600}
td{padding:6px 8px;border:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
tr:nth-child(even) td{background:#fafbfc}
td.mono,.code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11.5px}
td.bad{color:var(--bad);font-weight:700}td.warn{color:var(--warn);font-weight:700}td.good{color:var(--good);font-weight:700}td.info{color:var(--info);font-weight:700}
dl.kv{display:grid;grid-template-columns:minmax(150px,230px) 1fr;gap:0;margin:10px 0;border:1px solid var(--line);border-radius:10px;overflow:hidden}
dl.kv dt{background:var(--soft);padding:7px 10px;font-weight:600;border-bottom:1px solid var(--line)}dl.kv dd{margin:0;padding:7px 10px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
dl.kv dt:last-of-type,dl.kv dd:last-of-type{border-bottom:0}
pre.code{background:#1f2429;color:#e6e9ee;padding:12px 14px;border-radius:10px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;margin:10px 0}
.callout{border-left:6px solid;border-radius:8px;padding:12px 16px;margin:12px 0}
.callout b{display:block;font-size:15.5px;margin-bottom:3px}
.callout.bad{border-color:var(--bad);background:var(--bad-bg)}.callout.warn{border-color:#d98a00;background:var(--warn-bg)}.callout.good{border-color:var(--good);background:var(--good-bg)}.callout.info{border-color:var(--info);background:var(--info-bg)}
footer{margin-top:50px;padding-top:12px;border-top:1px solid var(--line);color:var(--mute);font-size:12px}
@media print{main{max-width:none;padding:0}.part{break-before:page}table,pre,.callout,dl.kv{break-inside:avoid}tr{break-inside:avoid}body{font-size:12px}nav.toc ol{columns:1}}
`;

function block(b: Block): string {
  switch (b.t) {
    case 'h3':
      return `<h3>${esc(b.text)}</h3>`;
    case 'p':
      return `<p${b.small ? ' class="small"' : ''}>${esc(b.text)}</p>`;
    case 'ul':
      return `<ul>${b.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>`;
    case 'checklist':
      return `<ul class="check">${b.items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>`;
    case 'kv':
      return `<dl class="kv">${b.rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>`;
    case 'code':
      return `<pre class="code">${esc(b.text)}</pre>`;
    case 'callout':
      return `<div class="callout ${b.tone}" role="note"><b>${esc(b.title)}</b>${esc(b.text)}</div>`;
    case 'table': {
      const head = `<tr>${b.head.map((h, i) => `<th${b.widths?.[i] ? ` style="width:${b.widths[i]}%"` : ''}>${esc(h)}</th>`).join('')}</tr>`;
      const rows = b.rows.map((r, ri) => `<tr>${r.map((c, ci) => `<td class="${[b.mono?.[ci] ? 'mono' : '', ci === 0 || b.head[ci] === 'Level' ? (b.tones?.[ri] ?? '') : ''].filter(Boolean).join(' ')}">${esc(c)}</td>`).join('')}</tr>`);
      return `<table><thead>${head}</thead><tbody>${rows.join('')}</tbody></table>`;
    }
  }
}

export function renderHtml(doc: CaseDoc): string {
  const tone: Tone = doc.verdict.tone;
  const parts: Section['part'][] = [];
  for (const s of doc.sections) if (!parts.includes(s.part)) parts.push(s.part);
  let lastPart: Section['part'] | null = null;
  const body: string[] = [];
  for (const s of doc.sections) {
    if (s.part !== lastPart) {
      body.push(`<div class="part"><h2>${esc(PART_TITLE[s.part])}</h2><p>${esc(PART_LEAD[s.part])}</p></div>`);
      lastPart = s.part;
    }
    body.push(`<section id="${esc(s.id)}"><h2>${esc(s.title)}</h2>${s.lead ? `<p class="lead">${esc(s.lead)}</p>` : ''}${s.blocks.map(block).join('')}</section>`);
  }
  const toc = doc.sections.map((s) => `<li><a href="#${esc(s.id)}">${esc(s.title)}</a></li>`).join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:"><title>${esc(doc.title)}: ${esc(doc.subtitle.slice(0, 80))}</title><style>${CSS}</style></head><body><main>
<header class="cover"><small>TLP:${esc(doc.tlp)} · ${esc(doc.meta[0]?.[1] ?? '')}</small><h1>${esc(doc.title)}</h1><p>${esc(doc.subtitle)}</p><span class="badge ${tone}">${esc(doc.verdict.label)} · risk score ${doc.verdict.score}/100</span><div class="meta">${doc.meta.map(([k, v]) => `<div><b>${esc(k)}</b>${esc(v)}</div>`).join('')}</div></header>
<nav class="toc" aria-label="Contents"><h2>Contents</h2><ol>${toc}</ol></nav>
${body.join('\n')}
<footer>Generated by ${esc(doc.tool)} ${esc(doc.version)} on ${esc(doc.generatedAt)}. All analysis ran on the analyst’s own computer. This report contains defanged indicators: it is safe to open and print.</footer>
</main></body></html>`;
}
