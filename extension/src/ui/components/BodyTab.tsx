import { useMemo, useState, type ReactNode } from 'react';
import type { Report } from '../../core/types';
import { buildSafeSrcDoc } from '../safeHtml';
import { Card, SectionTitle } from './ui';
import { Icon } from './Icon';

type View = 'safe' | 'text';

function Toggle({ checked, onChange, children, title }: { checked: boolean; onChange: (v: boolean) => void; children: ReactNode; title?: string }) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-2 text-xs text-[var(--text-2)]" title={title}>
      <span className={`relative h-4 w-7 rounded-full transition-colors ${checked ? 'bg-[var(--accent)]' : 'bg-[var(--border-strong)]'}`}>
        <span className={`absolute top-0.5 h-3 w-3 rounded-full bg-[var(--surface)] shadow transition-all ${checked ? 'left-3.5' : 'left-0.5'}`} />
      </span>
      <input type="checkbox" className="sr-only" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {children}
    </label>
  );
}

/** Splits text into plain runs and URLs (linear scan, no backtracking). */
export function splitUrls(text: string): { text: string; url?: string }[] {
  const out: { text: string; url?: string }[] = [];
  const re = /https?:\/\/[^\s<>"'\])]{1,4000}/g;
  let last = 0;
  for (const m of text.matchAll(re)) {
    const url = m[0].replace(/[.,;:!?]+$/, '');
    if (m.index! > last) out.push({ text: text.slice(last, m.index) });
    out.push({ text: url, url });
    last = m.index! + url.length;
  }
  if (last < text.length) out.push({ text: text.slice(last) });
  return out;
}

export function BodyTab({ report, initialReveal, onHoverUrl }: { report: Report; initialReveal?: boolean; onHoverUrl?: (url: string | null) => void }) {
  const { email, hidden, annotatedHtml } = report;
  const hasHtml = Boolean(email.html);
  const [view, setView] = useState<View>(hasHtml ? 'safe' : 'text');
  const [reveal, setReveal] = useState(initialReveal ?? hidden.length > 0);
  const [remoteImages, setRemoteImages] = useState(false);

  const remoteCount = report.trackers.remoteImages;
  const srcDoc = useMemo(() => {
    const base = reveal ? (annotatedHtml ?? email.html) : email.html;
    return base ? buildSafeSrcDoc(base, { reveal, remoteImages, attachments: email.attachments }) : '';
  }, [reveal, remoteImages, annotatedHtml, email.html, email.attachments]);

  const seg = (active: boolean) =>
    `flex-1 rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${active ? 'bg-[var(--surface)] text-[var(--text)] shadow-[var(--shadow)]' : 'text-[var(--text-2)] hover:text-[var(--text)]'}`;

  return (
    <div>
      <div className="mb-2.5 flex rounded-lg bg-[var(--surface-2)] p-0.5">
        {hasHtml && (
          <button type="button" className={seg(view === 'safe')} onClick={() => setView('safe')}>
            Safe view
          </button>
        )}
        <button type="button" className={seg(view === 'text')} onClick={() => setView('text')}>
          Plain text
        </button>
      </div>

      {view === 'safe' && hasHtml && (
        <>
          <div className="mb-2.5 flex flex-wrap gap-x-4 gap-y-1.5">
            {hidden.length > 0 && (
              <Toggle checked={reveal} onChange={setReveal}>
                Show hidden text <span className="text-[var(--bad)]">({hidden.length})</span>
              </Toggle>
            )}
            {remoteCount > 0 && (
              <Toggle checked={remoteImages} onChange={setRemoteImages} title="Loading images tells the sender you opened the email">
                Load {remoteCount} remote image{remoteCount === 1 ? '' : 's'}
              </Toggle>
            )}
          </div>
          {remoteImages && (
            <p className="mb-2 flex items-center gap-1 rounded-lg bg-[var(--warn-soft)] px-2.5 py-1.5 text-[11px] text-[var(--warn)]">
              <Icon name="alert" className="h-3.5 w-3.5" /> Images are loading: the sender can now see that you opened this email.
            </p>
          )}
          <iframe
            title="Email body (safe view)"
            sandbox=""
            referrerPolicy="no-referrer"
            srcDoc={srcDoc}
            className="h-[460px] w-full resize-y rounded-xl border border-[var(--border)] bg-white"
          />
          <p className="mt-1.5 text-[11px] text-[var(--text-3)]">Scripts are off and links are disabled here. Hover a link to see where it really goes.</p>
        </>
      )}

      {view === 'text' && (
        <Card>
          <pre className="max-h-[460px] overflow-auto whitespace-pre-wrap break-words font-sans text-xs leading-relaxed text-[var(--text)]">
            {email.text?.trim()
              ? splitUrls(email.text.trim()).map((part, i) =>
                  part.url ? (
                    <span
                      key={i}
                      title="Hover to see where this link is in the email"
                      onMouseEnter={() => onHoverUrl?.(part.url!)}
                      onMouseLeave={() => onHoverUrl?.(null)}
                      className="cursor-help rounded-sm text-[var(--accent)] underline decoration-dotted underline-offset-2 hover:bg-[var(--accent-soft)]"
                    >
                      {part.text}
                    </span>
                  ) : (
                    <span key={i}>{part.text}</span>
                  ),
                )
              : '(This email has no plain-text part.)'}
          </pre>
          {onHoverUrl && <p className="mt-2 text-[11px] text-[var(--text-3)]">Hover a link to outline it in the email in Gmail.</p>}
        </Card>
      )}

      {hidden.length > 0 && (
        <>
          <SectionTitle>Hidden text ({hidden.length})</SectionTitle>
          <p className="mb-2 text-[11px] text-[var(--text-3)]">Text you can’t see in the email. Short lines are often harmless preview text; long blocks are used to fool spam filters.</p>
          <ul className="space-y-1.5">
            {hidden.map((h, i) => (
              <li key={i} className="rounded-lg border border-dashed border-[var(--bad)]/40 bg-[var(--bad-soft)] p-2.5 text-xs">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--bad)]">{h.reason}</div>
                <div className="mt-0.5 break-words text-[var(--text-2)]">{h.text}</div>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
