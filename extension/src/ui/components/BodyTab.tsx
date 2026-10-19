import { useMemo, useState } from 'react';
import type { Report } from '../../core/types';
import { buildSafeSrcDoc, countRemoteImages } from '../safeHtml';
import { Card, SectionTitle } from './ui';

type View = 'safe' | 'text';

export function BodyTab({ report, initialReveal }: { report: Report; initialReveal?: boolean }) {
  const { email, hidden, annotatedHtml } = report;
  const hasHtml = Boolean(email.html);
  const [view, setView] = useState<View>(hasHtml ? 'safe' : 'text');
  const [reveal, setReveal] = useState(initialReveal ?? hidden.length > 0);
  const [remoteImages, setRemoteImages] = useState(false);

  const remoteCount = useMemo(() => (email.html ? countRemoteImages(email.html) : 0), [email.html]);
  const srcDoc = useMemo(() => {
    const base = reveal ? (annotatedHtml ?? email.html) : email.html;
    return base ? buildSafeSrcDoc(base, { reveal, remoteImages, attachments: email.attachments }) : '';
  }, [reveal, remoteImages, annotatedHtml, email.html, email.attachments]);

  const tabClass = (active: boolean) =>
    `rounded-md px-2.5 py-1 text-xs font-medium ${active ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900' : 'text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800'}`;

  return (
    <div>
      <div className="mb-2 flex items-center gap-1">
        {hasHtml && (
          <button type="button" className={tabClass(view === 'safe')} onClick={() => setView('safe')}>
            Safe view
          </button>
        )}
        <button type="button" className={tabClass(view === 'text')} onClick={() => setView('text')}>
          Plain text
        </button>
      </div>

      {view === 'safe' && hasHtml && (
        <>
          <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-700 dark:text-slate-300">
            {hidden.length > 0 && (
              <label className="inline-flex items-center gap-1.5">
                <input type="checkbox" checked={reveal} onChange={(e) => setReveal(e.target.checked)} /> Reveal hidden text
              </label>
            )}
            {remoteCount > 0 && (
              <label className="inline-flex items-center gap-1.5" title="Loading images tells the sender you opened the email">
                <input type="checkbox" checked={remoteImages} onChange={(e) => setRemoteImages(e.target.checked)} /> Load {remoteCount} remote image{remoteCount === 1 ? '' : 's'}
              </label>
            )}
          </div>
          <iframe
            title="Email body (safe view)"
            sandbox=""
            referrerPolicy="no-referrer"
            srcDoc={srcDoc}
            className="h-[460px] w-full resize-y rounded-lg border border-slate-200 bg-white dark:border-slate-800"
          />
          <p className="mt-1 text-[11px] text-slate-500">Scripts are off and links are disabled here. Hover a link to see where it really goes.</p>
        </>
      )}

      {view === 'text' && (
        <Card>
          <pre className="max-h-[460px] overflow-auto whitespace-pre-wrap break-words font-sans text-xs text-slate-800 dark:text-slate-200">
            {email.text?.trim() || '(This email has no plain-text part.)'}
          </pre>
        </Card>
      )}

      {hidden.length > 0 && (
        <>
          <SectionTitle>Hidden text ({hidden.length})</SectionTitle>
          <ul className="space-y-1.5">
            {hidden.map((h, i) => (
              <li key={i} className="rounded-md border border-dashed border-red-300 bg-red-50 p-2 text-xs dark:border-red-900 dark:bg-red-950/40">
                <div className="font-semibold text-red-700 dark:text-red-300">{h.reason}</div>
                <div className="mt-0.5 break-words text-slate-700 dark:text-slate-300">{h.text}</div>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
