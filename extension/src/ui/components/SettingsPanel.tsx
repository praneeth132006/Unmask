import { useState, type ReactNode } from 'react';
import { saveSettings, type Settings } from '../../lib/settings';
import { Button } from './ui';
import { Icon } from './Icon';

function Field({ label, hint, children }: { label: string; hint: ReactNode; children: ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs font-semibold text-slate-800 dark:text-slate-200">{label}</span>
      <div className="mt-1">{children}</div>
      <span className="mt-1 block text-[11px] text-slate-500 dark:text-slate-400">{hint}</span>
    </label>
  );
}

const input = 'w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 font-mono text-xs dark:border-slate-700 dark:bg-slate-900';

export function SettingsPanel({ settings, onClose, onSaved }: { settings: Settings; onClose: () => void; onSaved: (s: Settings) => void }) {
  const [draft, setDraft] = useState(settings);
  const [saving, setSaving] = useState(false);
  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setDraft((d) => ({ ...d, [k]: v }));

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold">Settings</h2>
        <Button variant="ghost" onClick={onClose} aria-label="Close settings">
          <Icon name="close" />
        </Button>
      </div>
      <p className="text-xs text-slate-600 dark:text-slate-400">
        Everything below is optional. Keys are stored only in this browser. Unmask's local checks work without any of them.
      </p>

      <Field
        label="VirusTotal API key"
        hint={
          <>
            Free at{' '}
            <a className="text-indigo-600 underline" href="https://www.virustotal.com/gui/my-apikey" target="_blank" rel="noreferrer">
              virustotal.com → API key
            </a>
            . Free keys allow 4 lookups per minute.
          </>
        }
      >
        <input className={input} type="password" autoComplete="off" value={draft.vtApiKey} onChange={(e) => set('vtApiKey', e.target.value)} />
      </Field>

      <Field
        label="urlscan.io API key"
        hint={
          <>
            Free at{' '}
            <a className="text-indigo-600 underline" href="https://urlscan.io/user/profile/" target="_blank" rel="noreferrer">
              urlscan.io → Settings &amp; API
            </a>
            .
          </>
        }
      >
        <input className={input} type="password" autoComplete="off" value={draft.urlscanApiKey} onChange={(e) => set('urlscanApiKey', e.target.value)} />
      </Field>

      <Field label="urlscan.io scan visibility" hint="Unlisted scans are hidden from the public feed but visible to urlscan's security partners. Private needs a paid plan.">
        <select className={input} value={draft.urlscanVisibility} onChange={(e) => set('urlscanVisibility', e.target.value as Settings['urlscanVisibility'])}>
          <option value="unlisted">Unlisted (recommended)</option>
          <option value="private">Private</option>
          <option value="public">Public</option>
        </select>
      </Field>

      <Field label="Redirect-trace backend URL" hint="Your deployed Unmask backend, e.g. https://unmask-trace.vercel.app, or http://localhost:8787 when running it locally. See the README.">
        <input className={input} type="url" placeholder="https://…" value={draft.backendUrl} onChange={(e) => set('backendUrl', e.target.value)} />
      </Field>

      <label className="flex items-start gap-2 text-xs">
        <input type="checkbox" className="mt-0.5" checked={draft.autoDomainAge} onChange={(e) => set('autoDomainAge', e.target.checked)} />
        <span>
          <span className="font-semibold text-slate-800 dark:text-slate-200">Check domain age automatically</span>
          <span className="block text-[11px] text-slate-500 dark:text-slate-400">Sends only the sender's domain name to rdap.org (the public registry lookup service).</span>
        </span>
      </label>

      <div className="flex gap-2">
        <Button
          variant="primary"
          disabled={saving}
          onClick={async () => {
            setSaving(true);
            await saveSettings(draft);
            setSaving(false);
            onSaved({ ...draft, backendUrl: draft.backendUrl.trim().replace(/\/+$/, ''), vtApiKey: draft.vtApiKey.trim(), urlscanApiKey: draft.urlscanApiKey.trim() });
          }}
        >
          Save
        </Button>
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </div>
  );
}
