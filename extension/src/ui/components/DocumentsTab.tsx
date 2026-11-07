import { useState, type ReactNode } from 'react';
import type { AttachmentInfo, Finding, LinkInfo, Report, Severity } from '../../core/types';
import type { Anomaly, ExtractedLink, FileForensics, MacroReport } from '../../forensics/types';
import { defang } from '../../forensics/util';
import { ABUSE_CH_ORIGINS, HYBRID_ORIGINS, PHISHTANK_ORIGINS, ensureOrigins, intelFindings, lookupHybridAnalysis, lookupMalwareBazaar, lookupPhishTank, lookupUrlhaus, type IntelHit } from '../../integrations/intel';
import { lookupFileHash, lookupUrl, vtFindings, type VtResult } from '../../integrations/virustotal';
import { GOOGLE_DOC_ORIGINS, fetchGoogleFile, googleDocLinks, type GoogleDocRef } from '../../integrations/googleDocs';
import { analyzeFile } from '../../forensics';
import { ensureOrigins as askOrigins } from '../../integrations/intel';
import type { Settings } from '../../lib/settings';
import { Icon } from './Icon';
import { ServiceSetup, type Service } from './ServiceSetup';
import { Button, Card, CopyButton, ErrorText, Label, Mono, Pill, Spinner, formatBytes, type Async } from './ui';

const RANK: Record<Severity, number> = { good: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };
const KIND_NAME: Record<FileForensics['kind'], string> = { pdf: 'PDF', ooxml: 'Office document', ole: 'Legacy Office file', rtf: 'RTF document', zip: 'Archive', html: 'Web page', script: 'Script', image: 'Image', executable: 'Program', shortcut: 'Shortcut', text: 'Text', other: 'File' };
const HOW: Record<ExtractedLink['how'], string> = { link: 'clickable link', template: 'remote template', resource: 'loaded automatically', action: 'runs on an action', form: 'form target', text: 'written in the text', macro: 'in macro or script code', decoded: 'found after decoding' };

export function worst(f: FileForensics): Severity {
  return f.anomalies.reduce<Severity>((w, a) => (RANK[a.severity] > RANK[w] ? a.severity : w), 'good');
}

function Section({ title, count, children, open = false }: { title: string; count?: number | string; children: ReactNode; open?: boolean }) {
  return (
    <details className="mt-2.5 rounded-lg bg-[var(--surface-2)] px-2.5 py-2 text-xs" open={open}>
      <summary className="cursor-pointer select-none font-medium text-[var(--text)]">
        {title}
        {count !== undefined && <span className="ml-1 font-normal text-[var(--text-3)]">({count})</span>}
      </summary>
      <div className="mt-2">{children}</div>
    </details>
  );
}

function KeyValues({ rows }: { rows: [string, string | undefined][] }) {
  const shown = rows.filter(([, v]) => v);
  if (!shown.length) return <p className="text-[var(--text-3)]">Nothing recorded.</p>;
  return (
    <dl className="grid grid-cols-[auto,1fr] gap-x-3 gap-y-1">
      {shown.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-[var(--text-3)]">{k}</dt>
          <dd className="break-words text-[var(--text-2)]">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function AnomalyList({ items }: { items: Anomaly[] }) {
  if (!items.length) return <p className="mt-2 text-xs text-[var(--good)]">No suspicious structure found. That does not prove the file is safe.</p>;
  return (
    <ul className="mt-2.5 space-y-2">
      {items.map((a) => (
        <li key={a.id} className="text-xs">
          <div className="flex items-start gap-1.5">
            <Pill severity={a.severity}>{a.severity}</Pill>
            <div className="min-w-0">
              <div className="font-medium text-[var(--text)]">{a.title}</div>
              <div className="text-[var(--text-2)]">{a.plain}</div>
              {(a.detail || a.where || a.attack) && (
                <div className="mt-0.5 break-words text-[11px] text-[var(--text-3)]">
                  {a.detail}
                  {a.where ? ` · ${a.where}` : ''}
                  {a.attack ? ` · MITRE ${a.attack}` : ''}
                </div>
              )}
            </div>
          </div>
        </li>
      ))}
    </ul>
  );
}

function MacroView({ macros }: { macros: MacroReport }) {
  return (
    <>
      {macros.autoExec.length > 0 && <p className="text-[var(--bad)]">Runs by itself: {macros.autoExec.join(', ')}</p>}
      {macros.suspicious.length > 0 && <p className="text-[var(--text-2)]">Uses: {macros.suspicious.join('; ')}</p>}
      {macros.xlmSheets.length > 0 && <p className="text-[var(--text-2)]">Excel 4.0 macro sheets: {macros.xlmSheets.map((s) => `${s.name}${s.hidden !== 'visible' ? ` (${s.hidden})` : ''}`).join(', ')}</p>}
      {macros.modules.map((m) => (
        <details key={m.name} className="mt-1.5">
          <summary className="cursor-pointer text-[var(--text)]">
            Module {m.name} <span className="text-[var(--text-3)]">({m.length} characters)</span>
          </summary>
          <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-[var(--surface)] p-2 font-mono text-[11px] text-[var(--text-2)]">{m.preview}{m.truncated ? '\n…' : ''}</pre>
        </details>
      ))}
      <p className="mt-1.5 text-[11px] text-[var(--text-3)]">
        Obfuscation hints: {macros.obfuscation.chrCalls} Chr() calls · {macros.obfuscation.longStrings} very long strings · {macros.obfuscation.base64Blobs} base64-like blobs
      </p>
    </>
  );
}

function FormatDetails({ f }: { f: FileForensics }) {
  if (f.pdf) {
    const p = f.pdf;
    return (
      <>
        <Section title="PDF structure (pdfid-style)" count={`${p.objects} objects`} open={p.id.some((r) => r.risk === 'danger' && (r.count || r.hiddenInStreams))}>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[11px]">
              <thead className="text-[var(--text-3)]">
                <tr>
                  <th className="pr-2 font-medium">Keyword</th>
                  <th className="pr-2 font-medium">Count</th>
                  <th className="pr-2 font-medium">Hidden</th>
                  <th className="pr-2 font-medium">Disguised</th>
                </tr>
              </thead>
              <tbody>
                {p.id.map((r) => (
                  <tr key={r.keyword} title={r.note} className={r.risk === 'danger' && (r.count || r.hiddenInStreams) ? 'font-semibold text-[var(--bad)]' : r.risk === 'watch' && r.count ? 'text-[var(--warn)]' : 'text-[var(--text-2)]'}>
                    <td className="pr-2 font-mono">{r.keyword}</td>
                    <td className="pr-2">{r.count}</td>
                    <td className="pr-2">{r.hiddenInStreams || '·'}</td>
                    <td className="pr-2">{r.obfuscated || '·'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="mt-1.5 text-[11px] text-[var(--text-3)]">
            Hidden = found only after unpacking {p.objectStreamsUnpacked} compressed object stream{p.objectStreamsUnpacked === 1 ? '' : 's'}. Disguised = spelled with #xx escapes. Hover a row for what it means. Entropy {p.entropy.total}/8 · %%EOF markers {p.eofCount} · bytes after the end {p.bytesAfterEof}.
          </p>
        </Section>
        {p.javascript.length > 0 && (
          <Section title="JavaScript in this PDF" count={p.javascript.length} open>
            {p.javascript.map((j, i) => (
              <div key={i} className="mb-2">
                <div className="text-[var(--text-2)]">
                  {j.obj} · runs {j.trigger} · {j.length} characters
                </div>
                {j.indicators.length > 0 && <div className="text-[var(--bad)]">{j.indicators.join('; ')}</div>}
                <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-[var(--surface)] p-2 font-mono text-[11px] text-[var(--text-2)]">{j.preview}</pre>
              </div>
            ))}
          </Section>
        )}
        {p.actions.length > 0 && (
          <Section title="Actions" count={p.actions.length}>
            <ul className="space-y-1">
              {p.actions.map((a, i) => (
                <li key={i} className="text-[var(--text-2)]">
                  <strong className="text-[var(--text)]">{a.type}</strong> {a.trigger} ({a.obj}){a.target ? <> → <Mono>{a.target}</Mono></> : null}
                </li>
              ))}
            </ul>
          </Section>
        )}
        {p.embedded.length > 0 && (
          <Section title="Files hidden inside" count={p.embedded.length} open>
            <ul className="space-y-1">
              {p.embedded.map((e) => (
                <li key={e.sha256} className="text-[var(--text-2)]">
                  <strong className="text-[var(--text)]">{e.name}</strong> · {e.type} · {formatBytes(e.size)} · <Mono>{e.sha256.slice(0, 16)}…</Mono>
                </li>
              ))}
            </ul>
          </Section>
        )}
        <Section title="About this PDF">
          <KeyValues rows={[['Version', p.version ?? undefined], ['Pages', String(p.pages || '')], ['Encrypted', p.encrypted ? 'yes' : ''], ...Object.entries(p.metadata).map(([k, v]): [string, string] => [k, v]), ['Page text (approximate)', p.textPreview]]} />
        </Section>
      </>
    );
  }
  if (f.ooxml) {
    const o = f.ooxml;
    return (
      <>
        {o.macros.present && <Section title="Macros" count={o.macros.modules.length} open><MacroView macros={o.macros} /></Section>}
        {o.fields.length > 0 && (
          <Section title="Fields, formulas and actions" count={o.fields.length}>
            <ul className="space-y-1">
              {o.fields.map((x, i) => (
                <li key={i} className="text-[var(--text-2)]">
                  <strong className="text-[var(--text)]">{x.type}</strong> <Mono>{x.instr}</Mono>
                </li>
              ))}
            </ul>
          </Section>
        )}
        {o.externalRefs.length > 0 && (
          <Section title="Things loaded from outside the file" count={o.externalRefs.length}>
            <ul className="space-y-1">
              {o.externalRefs.map((r, i) => (
                <li key={i} className="text-[var(--text-2)]">
                  {r.type}: <Mono>{r.target}</Mono>
                </li>
              ))}
            </ul>
          </Section>
        )}
        {o.embedded.length > 0 && (
          <Section title="Embedded objects" count={o.embedded.length}>
            <ul className="space-y-1">
              {o.embedded.map((e, i) => (
                <li key={i} className="text-[var(--text-2)]">
                  {e.part.split('/').pop()} · {e.type} · {formatBytes(e.size)}
                </li>
              ))}
            </ul>
          </Section>
        )}
        <Section title={`About this ${o.app === 'unknown' ? 'document' : o.app} file`}>
          <KeyValues rows={[...Object.entries(o.metadata).map(([k, v]): [string, string] => [k, v]), ['Parts in the package', String(o.parts)], ['Hidden sheets', o.hiddenSheets.join(', ')], ['Hidden slides', o.hiddenSlides ? String(o.hiddenSlides) : ''], ['Text (start)', o.textPreview]]} />
        </Section>
      </>
    );
  }
  if (f.ole) {
    const o = f.ole;
    return (
      <>
        {o.macros.present && <Section title="Macros" count={o.macros.modules.length} open><MacroView macros={o.macros} /></Section>}
        <Section title="Streams in the container (oledump-style)" count={o.streams.length}>
          <ul className="space-y-0.5">
            {o.streams.map((s) => (
              <li key={s.path} className="flex justify-between gap-2">
                <Mono>{s.path.replace(/[\x00-\x1f]/g, (c) => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`)}</Mono>
                <span className="shrink-0 text-[var(--text-3)]">{formatBytes(s.size)}</span>
              </li>
            ))}
          </ul>
        </Section>
        <Section title="About this file">
          <KeyValues rows={Object.entries(o.metadata).map(([k, v]): [string, string] => [k, v])} />
        </Section>
      </>
    );
  }
  if (f.rtf) {
    const r = f.rtf;
    return (
      <>
        {r.objects.length > 0 && (
          <Section title="Embedded objects" count={r.objects.length} open>
            <ul className="space-y-1">
              {r.objects.map((o, i) => (
                <li key={i} className="text-[var(--text-2)]">
                  {o.cls || 'object'} · {o.type} · {formatBytes(o.hexBytes)}
                </li>
              ))}
            </ul>
          </Section>
        )}
        {r.fields.length > 0 && (
          <Section title="Fields" count={r.fields.length}>
            <ul className="space-y-1">
              {r.fields.map((x, i) => (
                <li key={i}>
                  <Mono>{x.instr}</Mono>
                </li>
              ))}
            </ul>
          </Section>
        )}
      </>
    );
  }
  if (f.zip) {
    return (
      <Section title="Files in this archive" count={f.zip.files.length} open={f.zip.files.length <= 8}>
        <ul className="space-y-0.5">
          {f.zip.files.map((x, i) => (
            <li key={i} className="flex justify-between gap-2">
              <Mono>{x.name}</Mono>
              <span className="shrink-0 text-[11px] text-[var(--text-3)]">
                {x.encrypted ? 'encrypted · ' : ''}
                {x.type ? `${x.type} · ` : ''}
                {formatBytes(x.size)}
              </span>
            </li>
          ))}
        </ul>
      </Section>
    );
  }
  return null;
}

type IntelKey = 'vt' | 'ha' | 'mb';

function Intel({ att, settings, onSettingsChange, onFindings }: { att: AttachmentInfo; settings: Settings; onSettingsChange: (s: Settings) => void; onFindings: (f: Finding[]) => void }) {
  const [vt, setVt] = useState<Async<VtResult>>({ status: 'idle' });
  const [ha, setHa] = useState<Async<IntelHit>>({ status: 'idle' });
  const [mb, setMb] = useState<Async<IntelHit>>({ status: 'idle' });
  const [setup, setSetup] = useState<Service | null>(null);
  const target = (sha: string) => ({ kind: 'attachment', sha256: sha }) as const;
  const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

  const run = async (which: IntelKey, s: Settings = settings) => {
    setSetup(null);
    if (which === 'vt') {
      if (!s.vtApiKey) return setSetup('virustotal');
      setVt({ status: 'loading' });
      try {
        const v = await lookupFileHash(s.vtApiKey, att.sha256);
        setVt({ status: 'done', value: v });
        onFindings(vtFindings(`vt-file-${att.sha256.slice(0, 12)}`, att.filename, v, 'attachments').map((x) => ({ ...x, target: target(att.sha256) })));
      } catch (e) {
        setVt({ status: 'error', error: msg(e) });
      }
    } else if (which === 'ha') {
      if (!s.hybridApiKey) return setSetup('hybrid');
      if (!(await ensureOrigins(HYBRID_ORIGINS))) return setHa({ status: 'error', error: 'Permission not granted. Unmask needs it to ask Hybrid Analysis about the fingerprint.' });
      setHa({ status: 'loading' });
      try {
        const h = await lookupHybridAnalysis(s.hybridApiKey, att.sha256);
        setHa({ status: 'done', value: h });
        onFindings(intelFindings(`ha-${att.sha256.slice(0, 12)}`, att.filename, h, 'attachments').map((x) => ({ ...x, target: target(att.sha256) })));
      } catch (e) {
        setHa({ status: 'error', error: msg(e) });
      }
    } else {
      if (!s.abuseChKey) return setSetup('abusech');
      if (!(await ensureOrigins(ABUSE_CH_ORIGINS))) return setMb({ status: 'error', error: 'Permission not granted. Unmask needs it to ask abuse.ch about the fingerprint.' });
      setMb({ status: 'loading' });
      try {
        const h = await lookupMalwareBazaar(s.abuseChKey, att.sha256);
        setMb({ status: 'done', value: h });
        onFindings(intelFindings(`mb-${att.sha256.slice(0, 12)}`, att.filename, h, 'attachments').map((x) => ({ ...x, target: target(att.sha256) })));
      } catch (e) {
        setMb({ status: 'error', error: msg(e) });
      }
    }
  };

  const hit = (state: Async<IntelHit>) =>
    state.status === 'done' ? (
      <div className="mt-1.5 rounded-lg bg-[var(--surface-2)] px-2.5 py-2 text-xs">
        <div className="flex items-center justify-between gap-2">
          <span className={state.value.verdict === 'malicious' ? 'font-semibold text-[var(--bad)]' : state.value.verdict === 'clean' ? 'text-[var(--good)]' : 'text-[var(--text-2)]'}>{state.value.summary}</span>
          <a className="shrink-0 font-medium text-[var(--accent)] hover:underline" href={state.value.permalink} target="_blank" rel="noreferrer">
            Report
          </a>
        </div>
        {Object.keys(state.value.details).length > 0 && (
          <div className="mt-1.5">
            <KeyValues rows={Object.entries(state.value.details).map(([k, v]): [string, string] => [k, v])} />
          </div>
        )}
      </div>
    ) : state.status === 'error' ? (
      <ErrorText>{state.error}</ErrorText>
    ) : null;

  return (
    <div className="mt-3">
      <Label>Look this file up by its fingerprint</Label>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        <Button onClick={() => void run('vt')} disabled={vt.status === 'loading'} title="Sends only the SHA-256 hash, never the file">
          {vt.status === 'loading' ? <Spinner /> : <Icon name="shield" className="h-3.5 w-3.5" />} VirusTotal
        </Button>
        <Button onClick={() => void run('ha')} disabled={ha.status === 'loading'} title="Sends only the SHA-256 hash, never the file">
          {ha.status === 'loading' ? <Spinner /> : <Icon name="shield" className="h-3.5 w-3.5" />} Hybrid Analysis
        </Button>
        <Button onClick={() => void run('mb')} disabled={mb.status === 'loading'} title="Sends only the SHA-256 hash, never the file">
          {mb.status === 'loading' ? <Spinner /> : <Icon name="shield" className="h-3.5 w-3.5" />} MalwareBazaar
        </Button>
      </div>
      <p className="mt-1 text-[11px] text-[var(--text-3)]">Only the fingerprint is sent. The file itself never leaves your computer, so nobody else can ever see your document.</p>
      {setup && (
        <div className="mt-2">
          <ServiceSetup
            compact
            service={setup}
            settings={settings}
            onCancel={() => setSetup(null)}
            onSaved={(s) => {
              onSettingsChange(s);
              void run(setup === 'virustotal' ? 'vt' : setup === 'hybrid' ? 'ha' : 'mb', s);
            }}
          />
        </div>
      )}
      {vt.status === 'done' && (
        <div className="mt-1.5 flex items-center justify-between gap-2 rounded-lg bg-[var(--surface-2)] px-2.5 py-2 text-xs">
          <span className={vt.value.stats && vt.value.stats.malicious + vt.value.stats.suspicious > 0 ? 'font-semibold text-[var(--bad)]' : 'text-[var(--text-2)]'}>
            {vt.value.found && vt.value.stats ? `VirusTotal: ${vt.value.stats.malicious + vt.value.stats.suspicious}/${vt.value.stats.malicious + vt.value.stats.suspicious + vt.value.stats.harmless + vt.value.stats.undetected} vendors flag this file` : 'VirusTotal has never seen this file. Unknown is not the same as safe.'}
          </span>
          <a className="shrink-0 font-medium text-[var(--accent)] hover:underline" href={vt.value.permalink} target="_blank" rel="noreferrer">
            Report
          </a>
        </div>
      )}
      {vt.status === 'error' && <ErrorText>{vt.error}</ErrorText>}
      {hit(ha)}
      {hit(mb)}
    </div>
  );
}

function Links({ att, f, reportLinks, settings, onSettingsChange, onFindings, onOpenLinks }: { att: AttachmentInfo; f: FileForensics; reportLinks: LinkInfo[]; settings: Settings; onSettingsChange: (s: Settings) => void; onFindings: (f: Finding[]) => void; onOpenLinks?: () => void }) {
  const [results, setResults] = useState<Record<string, Async<VtResult>>>({});
  const [lists, setLists] = useState<Record<string, Async<IntelHit[]>>>({});
  const [running, setRunning] = useState(false);
  const [listRunning, setListRunning] = useState(false);
  const [setup, setSetup] = useState(false);
  const flagsOf = (url: string) => reportLinks.find((l) => l.href === url || l.resolved === url)?.flags ?? [];
  const testable = f.links.filter((l) => /^https?:/i.test(l.url)).slice(0, 10);

  /** PhishTank (no key) and URLhaus (free key): is any link a known phishing or malware page? */
  const checkLists = async () => {
    const origins = settings.abuseChKey ? [...PHISHTANK_ORIGINS, ...ABUSE_CH_ORIGINS] : PHISHTANK_ORIGINS;
    if (!(await ensureOrigins(origins))) return;
    setListRunning(true);
    for (const [i, l] of testable.entries()) {
      setLists((r) => ({ ...r, [l.url]: { status: 'loading' } }));
      const hits: IntelHit[] = [];
      try { hits.push(await lookupPhishTank(l.url)); } catch (e) { setLists((r) => ({ ...r, [l.url]: { status: 'error', error: e instanceof Error ? e.message : String(e) } })); if (/rate limit/i.test(String(e))) break; continue; }
      if (settings.abuseChKey) { try { hits.push(await lookupUrlhaus(settings.abuseChKey, l.url)); } catch { /* the PhishTank answer still stands */ } }
      setLists((r) => ({ ...r, [l.url]: { status: 'done', value: hits } }));
      onFindings(hits.flatMap((h) => intelFindings(`feed-${att.sha256.slice(0, 8)}-${i}-${h.source}`, new URL(l.url).hostname, h, 'links')).filter((x) => x.points > 0));
      await new Promise((res) => setTimeout(res, 1200));
    }
    setListRunning(false);
  };

  const testAll = async (s: Settings = settings) => {
    if (!s.vtApiKey) return setSetup(true);
    setSetup(false);
    setRunning(true);
    for (const [i, l] of testable.entries()) {
      setResults((r) => ({ ...r, [l.url]: { status: 'loading' } }));
      try {
        const v = await lookupUrl(s.vtApiKey, l.url);
        setResults((r) => ({ ...r, [l.url]: { status: 'done', value: v } }));
        onFindings(vtFindings(`vt-doc-${att.sha256.slice(0, 8)}-${i}`, new URL(l.url).hostname, v, 'links').filter((x) => x.points > 0));
      } catch (e) {
        setResults((r) => ({ ...r, [l.url]: { status: 'error', error: e instanceof Error ? e.message : String(e) } }));
        if (/limit/i.test(String(e))) break;
      }
      // Free VirusTotal keys allow 4 lookups a minute.
      if (i < testable.length - 1) await new Promise((res) => setTimeout(res, 15_500));
    }
    setRunning(false);
  };

  if (!f.links.length) return <Section title="Links found inside this file" count={0}><p className="text-[var(--text-3)]">No links found.</p></Section>;
  return (
    <Section title="Links found inside this file" count={f.links.length} open>
      <ul className="space-y-2">
        {f.links.map((l) => {
          const fl = flagsOf(l.url);
          const r = results[l.url];
          return (
            <li key={l.url} className="text-xs">
              <div className="flex items-start gap-1.5">
                {fl[0] && <Pill severity={fl[0].severity}>{fl[0].severity}</Pill>}
                <div className="min-w-0">
                  <Mono className="text-[var(--text)]">{l.url}</Mono>
                  <div className="text-[11px] text-[var(--text-3)]">
                    {HOW[l.how]} · {l.where}
                    {l.label ? ` · shown as “${l.label}”` : ''}
                    {l.coversPage ? ' · covers the whole page' : ''}
                  </div>
                  {fl.length > 0 && <div className="text-[11px] text-[var(--text-2)]">{fl.map((x) => x.label).join('; ')}</div>}
                  {r?.status === 'loading' && <div className="text-[11px] text-[var(--text-3)]">Checking on VirusTotal…</div>}
                  {r?.status === 'done' && (
                    <div className={`text-[11px] ${r.value.stats && r.value.stats.malicious + r.value.stats.suspicious > 0 ? 'font-semibold text-[var(--bad)]' : 'text-[var(--text-2)]'}`}>
                      {r.value.found && r.value.stats ? `VirusTotal: ${r.value.stats.malicious + r.value.stats.suspicious} vendors flag this link` : 'VirusTotal has not seen this link'} ·{' '}
                      <a className="text-[var(--accent)] hover:underline" href={r.value.permalink} target="_blank" rel="noreferrer">
                        report
                      </a>
                    </div>
                  )}
                  {r?.status === 'error' && <div className="text-[11px] text-[var(--bad)]">{r.error}</div>}
                  {lists[l.url]?.status === 'loading' && <div className="text-[11px] text-[var(--text-3)]">Checking phishing lists…</div>}
                  {(() => {
                    const ls = lists[l.url];
                    return ls?.status === 'done' ? ls.value.map((h) => (
                      <div key={h.source} className={`text-[11px] ${h.verdict === 'malicious' ? 'font-semibold text-[var(--bad)]' : 'text-[var(--text-2)]'}`}>
                        {h.summary} ·{' '}
                        <a className="text-[var(--accent)] hover:underline" href={h.permalink} target="_blank" rel="noreferrer">report</a>
                      </div>
                    )) : ls?.status === 'error' ? <div className="text-[11px] text-[var(--bad)]">{ls.error}</div> : null;
                  })()}
                </div>
              </div>
            </li>
          );
        })}
      </ul>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {testable.length > 0 && (
          <Button onClick={() => void testAll()} disabled={running} title="Looks each web link up on VirusTotal. Only the link is sent, never the file.">
            {running ? <Spinner /> : <Icon name="shield" className="h-3.5 w-3.5" />} Test these links ({testable.length})
          </Button>
        )}
        {testable.length > 0 && (
          <Button onClick={() => void checkLists()} disabled={listRunning} title="Look each link up on PhishTank, and URLhaus if you added a free abuse.ch key. Only the link is sent.">
            {listRunning ? <Spinner /> : <Icon name="flag" className="h-3.5 w-3.5" />} Check phishing lists
          </Button>
        )}
        {onOpenLinks && <Button variant="ghost" onClick={onOpenLinks}>Open on the Links tab</Button>}
        <CopyButton value={f.links.map((l) => defang(l.url)).join('\n')} label="Copy defanged list" />
      </div>
      {setup && (
        <div className="mt-2">
          <ServiceSetup compact service="virustotal" settings={settings} onCancel={() => setSetup(false)} onSaved={(s) => { onSettingsChange(s); void testAll(s); }} />
        </div>
      )}
      <p className="mt-1 text-[11px] text-[var(--text-3)]">Checks run on a free VirusTotal key, about 4 a minute, so a long list takes a little while. These links also appear on the Links tab with the usual checks.</p>
    </Section>
  );
}

function Indicators({ f }: { f: FileForensics }) {
  const rows: [string, string[]][] = [['Addresses (IP)', f.iocs.ips], ['Email addresses', f.iocs.emails], ['Domains', f.iocs.domains], ['Programs and scripts named', f.iocs.executables], ['Commands', f.iocs.commands]];
  const total = rows.reduce((n, [, v]) => n + v.length, 0);
  if (!total) return null;
  return (
    <Section title="Indicators of compromise" count={total}>
      {rows.filter(([, v]) => v.length).map(([k, v]) => (
        <div key={k} className="mb-1.5">
          <Label>{k}</Label>
          <ul className="mt-0.5 space-y-0.5">
            {v.slice(0, 20).map((x) => (
              <li key={x}>
                <Mono>{k === 'Domains' ? defang(x) : x}</Mono>
              </li>
            ))}
          </ul>
        </div>
      ))}
      <CopyButton value={rows.flatMap(([, v]) => v.map(defang)).join('\n')} label="Copy all (defanged)" />
    </Section>
  );
}

function Children({ f }: { f: FileForensics }) {
  if (!f.children.length) return null;
  return (
    <Section title="Files found inside, analysed the same way" count={f.children.length} open>
      <ul className="space-y-2">
        {f.children.map((c) => (
          <li key={c.path} className="text-xs">
            <div className="flex items-center gap-1.5">
              <Pill severity={worst(c.forensics)}>{worst(c.forensics) === 'good' ? 'clean' : worst(c.forensics)}</Pill>
              <span className="font-medium text-[var(--text)]">{c.path}</span>
              <span className="text-[var(--text-3)]">{KIND_NAME[c.forensics.kind]} · {formatBytes(c.forensics.size)}</span>
            </div>
            {c.forensics.anomalies.slice(0, 4).map((a) => (
              <div key={a.id} className="ml-1 mt-0.5 text-[11px] text-[var(--text-2)]">
                · {a.title}
              </div>
            ))}
          </li>
        ))}
      </ul>
    </Section>
  );
}

function DocCard({ att, report, settings, onSettingsChange, onFindings, focused, onOpenLinks, showIntel = true }: { att: AttachmentInfo; report: Report; settings: Settings; onSettingsChange: (s: Settings) => void; onFindings: (f: Finding[]) => void; focused: boolean; onOpenLinks?: () => void; showIntel?: boolean }) {
  const f = att.forensics!;
  const w = worst(f);
  return (
    <Card id={`unmask-doc-${att.sha256.slice(0, 12)}`} className={`${RANK[w] >= RANK.high ? 'border-l-[3px] !border-l-[var(--bad)]' : ''} ${focused ? 'unmask-flash' : ''}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="break-all text-[13px] font-medium">{att.filename}</div>
          <div className="text-[11px] text-[var(--text-3)]">
            {KIND_NAME[f.kind]} · {formatBytes(f.size)} · looks like: {f.magic.label}
          </div>
        </div>
        <Pill severity={w === 'good' ? 'good' : w}>{w === 'good' ? 'nothing found' : `${f.anomalies.length} finding${f.anomalies.length === 1 ? '' : 's'}`}</Pill>
      </div>
      <p className="mt-1 text-[11px] text-[var(--text-3)]">Read on this computer, byte by byte. Nothing was opened, run or uploaded.</p>
      {f.truncated && <p className="mt-1 text-[11px] text-[var(--warn)]">This file is very large, so only the first part was analysed.</p>}

      <AnomalyList items={f.anomalies} />

      <Section title="Fingerprints">
        <KeyValues rows={[['Entropy', `${f.entropy} / 8${f.entropy >= 7.5 ? ' (looks packed or encrypted)' : ''}`]]} />
        {([['SHA-256', f.hashes.sha256], ['SHA-1', f.hashes.sha1], ['MD5', f.hashes.md5]] as const).filter(([, v]) => v).map(([k, v]) => (
          <div key={k} className="mt-1 flex items-center gap-1">
            <span className="w-14 shrink-0 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-3)]">{k}</span>
            <Mono className="truncate">{v}</Mono>
            <CopyButton value={v} />
          </div>
        ))}
      </Section>

      <FormatDetails f={f} />
      <Links att={att} f={f} reportLinks={report.links.filter((l) => l.source === 'attachment' && l.origin === att.filename)} settings={settings} onSettingsChange={onSettingsChange} onFindings={onFindings} onOpenLinks={onOpenLinks} />
      <Indicators f={f} />
      <Children f={f} />
      {showIntel && <Intel att={att} settings={settings} onSettingsChange={onSettingsChange} onFindings={onFindings} />}
    </Card>
  );
}

/** Shared Google files linked from the email: read the public copy without opening it. */
function GoogleDocsPanel({ refs, report, settings, onSettingsChange, onFindings, onOpenLinks }: { refs: GoogleDocRef[]; report: Report; settings: Settings; onSettingsChange: (s: Settings) => void; onFindings: (f: Finding[]) => void; onOpenLinks?: () => void }) {
  const [state, setState] = useState<Record<string, Async<AttachmentInfo>>>({});
  const inspect = async (ref: GoogleDocRef) => {
    if (!(await askOrigins(GOOGLE_DOC_ORIGINS))) return setState((s) => ({ ...s, [ref.id]: { status: 'error', error: 'Permission not granted. Unmask needs it to download the shared copy from Google, anonymously and without your login.' } }));
    setState((s) => ({ ...s, [ref.id]: { status: 'loading', message: 'Downloading the public copy from Google…' } }));
    try {
      const bytes = await fetchGoogleFile(ref);
      const forensics = await analyzeFile(bytes, ref.fileName);
      const att: AttachmentInfo = { filename: `${ref.label} (${ref.id.slice(0, 8)}…) as ${ref.fileName.split('.').pop() ?? 'file'}`, mimeType: forensics.magic.mime ?? 'application/octet-stream', size: bytes.length, sha256: forensics.hashes.sha256, extension: ref.fileName.split('.').pop() ?? '', inline: false, flags: [], forensics };
      setState((s) => ({ ...s, [ref.id]: { status: 'done', value: att } }));
      const top = forensics.anomalies.filter((a) => RANK[a.severity] >= RANK.medium).slice(0, 3);
      onFindings(top.map((a) => ({ id: `gdoc-${ref.id.slice(0, 8)}-${a.id}`, category: 'links' as const, severity: a.severity, points: a.severity === 'critical' ? 25 : a.severity === 'high' ? 15 : 6, title: `Inside the linked ${ref.label}: ${a.title}`, detail: a.plain })));
    } catch (e) {
      setState((s) => ({ ...s, [ref.id]: { status: 'error', error: e instanceof Error ? e.message : String(e) } }));
    }
  };
  return (
    <Card>
      <div className="text-[13px] font-medium">Google files linked in this email</div>
      <p className="mt-0.5 text-xs text-[var(--text-2)]">The link is on google.com, so it looks safe, but attackers host phishing pages and malware in shared Docs, Sheets, Slides and Drive files. Unmask can read the shared copy without signing in as you, and without opening it.</p>
      <ul className="mt-2 space-y-2">
        {refs.map((ref) => {
          const st = state[ref.id];
          return (
            <li key={ref.id} className="text-xs">
              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <span className="font-medium text-[var(--text)]">{ref.label}</span> <Mono className="text-[var(--text-3)]">{ref.id.slice(0, 12)}…</Mono>
                </div>
                <Button onClick={() => void inspect(ref)} disabled={st?.status === 'loading'}>
                  {st?.status === 'loading' ? <Spinner /> : <Icon name="eye" className="h-3.5 w-3.5" />} Look inside
                </Button>
              </div>
              {st?.status === 'loading' && <p className="mt-1 text-[11px] text-[var(--text-3)]">{st.message}</p>}
              {st?.status === 'error' && <ErrorText>{st.error}</ErrorText>}
              {st?.status === 'done' && (
                <div className="mt-2">
                  <DocCard att={st.value} report={report} settings={settings} onSettingsChange={onSettingsChange} onFindings={onFindings} focused={false} onOpenLinks={onOpenLinks} showIntel={false} />
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

export function documentsAvailable(report: Report): boolean {
  return report.attachments.some((a) => !a.inline && a.forensics) || googleDocLinks(report.links.map((l) => l.resolved)).length > 0;
}

export function DocumentsTab({ report, settings, onSettingsChange, onFindings, focusSha, onOpenLinks }: { report: Report; settings: Settings; onSettingsChange: (s: Settings) => void; onFindings: (f: Finding[]) => void; focusSha?: string | null; onOpenLinks?: () => void }) {
  const docs = report.attachments.filter((a) => !a.inline && a.forensics);
  const gdocs = googleDocLinks(report.links.map((l) => l.resolved));
  if (!docs.length && !gdocs.length) return <p className="text-sm text-[var(--text-2)]">No documents to inspect: this email has no attachments.</p>;
  const sorted = [...docs].sort((a, b) => RANK[worst(b.forensics!)] - RANK[worst(a.forensics!)]);
  return (
    <div className="space-y-2.5">
      <p className="text-xs text-[var(--text-2)]">
        A closer look inside every attachment: the structure of PDFs and Office files, hidden scripts and macros, every link, and the file’s fingerprints. Everything is read on your computer. The file is never uploaded anywhere, so your documents stay private.
      </p>
      {gdocs.length > 0 && <GoogleDocsPanel refs={gdocs} report={report} settings={settings} onSettingsChange={onSettingsChange} onFindings={onFindings} onOpenLinks={onOpenLinks} />}
      {sorted.map((a) => (
        <DocCard key={a.sha256 + a.filename} att={a} report={report} settings={settings} onSettingsChange={onSettingsChange} onFindings={onFindings} focused={focusSha === a.sha256} onOpenLinks={onOpenLinks} />
      ))}
    </div>
  );
}
