import { useState, type ReactNode } from 'react';
import { saveSettings, type Settings } from '../../lib/settings';
import { testBackend, testUrlscanKey, testVirusTotalKey, type KeyTestResult } from '../../integrations/keyTest';
import { Button, Spinner } from './ui';
import { Icon } from './Icon';

export type Service = 'virustotal' | 'urlscan' | 'backend';

interface ServiceInfo {
  name: string;
  what: string;
  /** Free quota, shown so nobody worries about being charged. */
  limits: string;
  field: 'vtApiKey' | 'urlscanApiKey' | 'backendUrl';
  placeholder: string;
  steps: ReactNode[];
  test: (value: string) => Promise<KeyTestResult>;
}

const ext = (href: string, children: ReactNode) => (
  <a className="font-medium text-[var(--accent)] underline underline-offset-2" href={href} target="_blank" rel="noreferrer">
    {children}
  </a>
);

export const SERVICES: Record<Service, ServiceInfo> = {
  virustotal: {
    name: 'VirusTotal',
    what: 'Checks files and links against 70+ antivirus engines. Free, and Unmask only sends a file’s fingerprint unless you choose to upload it.',
    limits: 'Free: 4 lookups per minute, 500 per day. A free key is never charged; past the limit, lookups just pause until it resets. Personal use only.',
    field: 'vtApiKey',
    placeholder: 'Paste your VirusTotal key',
    steps: [
      <>{ext('https://www.virustotal.com/gui/join-us', 'Create a free VirusTotal account')} (or sign in).</>,
      <>Open {ext('https://www.virustotal.com/gui/my-apikey', 'your API key page')}. It is also under your profile picture → <em>API key</em>.</>,
      <>Click the copy icon next to the key and paste it below.</>,
    ],
    test: testVirusTotalKey,
  },
  urlscan: {
    name: 'urlscan.io',
    what: 'Opens a link in urlscan.io’s own sandbox browser (never yours) and shows a screenshot of where it really lands.',
    limits: 'Free: 1,000 unlisted and 50 private scans per day. A free key is never charged; past the limit, scans just pause until the next day.',
    field: 'urlscanApiKey',
    placeholder: 'Paste your urlscan.io key',
    steps: [
      <>{ext('https://urlscan.io/user/signup', 'Create a free urlscan.io account')} (or sign in).</>,
      <>Open {ext('https://urlscan.io/user/profile/', 'Settings & API')} and click <em>New API key</em>.</>,
      <>Copy the key it shows and paste it below.</>,
    ],
    test: testUrlscanKey,
  },
  backend: {
    name: 'Your own trace server',
    what: 'Optional. A small server you run makes the trace requests instead of your browser, so the link’s website sees the server’s IP address, not yours.',
    limits: 'Free when run on your own computer.',
    field: 'backendUrl',
    placeholder: 'http://localhost:8787',
    steps: [
      <>Open a terminal in the UNMASK project folder.</>,
      <>Run <code className="rounded bg-[var(--surface-2)] px-1 font-mono text-[11px]">pnpm backend</code> and leave it running.</>,
      <>Click <em>Use local server</em> below. (You can also deploy it to Vercel: see the README.)</>,
    ],
    test: testBackend,
  },
};

/**
 * Step-by-step setup for an online service, shown inline where it is needed
 * and in Settings. Saves only after the key or server has been checked.
 */
export function ServiceSetup({
  service,
  settings,
  onSaved,
  onCancel,
  compact = false,
}: {
  service: Service;
  settings: Settings;
  onSaved: (s: Settings) => void;
  onCancel?: () => void;
  compact?: boolean;
}) {
  const info = SERVICES[service];
  const [value, setValue] = useState(settings[info.field]);
  const [state, setState] = useState<{ status: 'idle' | 'testing' } | { status: 'done'; result: KeyTestResult }>({ status: 'idle' });

  const save = async (v = value) => {
    setState({ status: 'testing' });
    const result = await info.test(v);
    setState({ status: 'done', result });
    if (result.ok) {
      const clean = service === 'backend' ? v.trim().replace(/\/+$/, '') : v.trim();
      const next = { ...settings, [info.field]: clean };
      await saveSettings(next);
      onSaved(next);
    }
  };

  return (
    <div className={`rounded-xl border border-[var(--accent-border)] bg-[var(--accent-soft)] ${compact ? 'p-3' : 'p-4'}`}>
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="text-[13px] font-semibold text-[var(--text)]">Set up {info.name}</div>
          <p className="mt-0.5 text-xs text-[var(--text-2)]">{info.what}</p>
        </div>
        {onCancel && (
          <button type="button" onClick={onCancel} className="rounded p-0.5 text-[var(--text-3)] hover:text-[var(--text)]" aria-label="Close">
            <Icon name="close" className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      <ol className="mt-2.5 space-y-1.5">
        {info.steps.map((step, i) => (
          <li key={i} className="flex gap-2 text-xs text-[var(--text-2)]">
            <span className="flex h-[18px] w-[18px] shrink-0 items-center justify-center rounded-full bg-[var(--accent)] text-[10px] font-bold text-[var(--on-accent)]">{i + 1}</span>
            <span className="pt-px">{step}</span>
          </li>
        ))}
      </ol>
      <div className="mt-3 flex gap-1.5">
        <input
          value={value}
          onChange={(e) => {
            setValue(e.target.value);
            setState({ status: 'idle' });
          }}
          onKeyDown={(e) => e.key === 'Enter' && value.trim() && void save()}
          placeholder={info.placeholder}
          spellCheck={false}
          autoComplete="off"
          type={service === 'backend' ? 'url' : 'password'}
          className="min-w-0 flex-1 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-2.5 py-1.5 font-mono text-xs text-[var(--text)] placeholder:font-sans placeholder:text-[var(--text-3)] focus:border-[var(--accent)] focus:outline-none"
        />
        <Button variant="primary" disabled={!value.trim() || state.status === 'testing'} onClick={() => void save()}>
          {state.status === 'testing' ? <Spinner /> : null} Save &amp; test
        </Button>
      </div>
      {service === 'backend' && (
        <Button variant="ghost" className="mt-1.5" onClick={() => { setValue('http://localhost:8787'); void save('http://localhost:8787'); }}>
          Use local server
        </Button>
      )}
      {state.status === 'done' && (
        <p className={`mt-2 flex items-center gap-1 text-xs font-medium ${state.result.ok ? 'text-[var(--good)]' : 'text-[var(--bad)]'}`}>
          <Icon name={state.result.ok ? 'check' : 'alert'} className="h-3.5 w-3.5" /> {state.result.message}
        </p>
      )}
      <p className="mt-2 text-[11px] text-[var(--text-3)]">
        {info.limits}{' '}
        <a className="underline" href="https://github.com/praneeth132006/Unmask/blob/main/docs/LIMITS_AND_COSTS.md" target="_blank" rel="noreferrer">
          Limits &amp; costs
        </a>
      </p>
      <p className="mt-1 text-[11px] text-[var(--text-3)]">Stored only in this browser. You can change or remove it any time in Settings.</p>
    </div>
  );
}
