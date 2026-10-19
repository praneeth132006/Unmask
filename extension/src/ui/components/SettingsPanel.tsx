import { useState } from 'react';
import { saveSettings, type Settings } from '../../lib/settings';
import { Button, Card, SectionTitle } from './ui';
import { Icon } from './Icon';
import { SERVICES, ServiceSetup, type Service } from './ServiceSetup';

function ServiceRow({ service, settings, onChange }: { service: Service; settings: Settings; onChange: (s: Settings) => void }) {
  const info = SERVICES[service];
  const connected = Boolean(settings[info.field]);
  const [open, setOpen] = useState(false);

  return (
    <div className="py-2.5 first:pt-0 last:pb-0">
      <div className="flex items-center justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5 text-[13px] font-semibold">
            {info.name}
            {connected ? (
              <span className="inline-flex items-center gap-0.5 rounded-md bg-[var(--good-soft)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--good)]">
                <Icon name="check" className="h-3 w-3" /> Connected
              </span>
            ) : (
              <span className="rounded-md bg-[var(--surface-2)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--text-3)]">Not set up</span>
            )}
          </div>
          <p className="mt-0.5 text-[11px] text-[var(--text-3)]">{info.what}</p>
        </div>
        <div className="flex shrink-0 gap-1">
          {connected && (
            <Button
              variant="ghost"
              onClick={async () => {
                const next = { ...settings, [info.field]: '' };
                await saveSettings(next);
                onChange(next);
              }}
            >
              Remove
            </Button>
          )}
          <Button variant={connected ? 'secondary' : 'primary'} onClick={() => setOpen((o) => !o)}>
            {open ? 'Close' : connected ? 'Change' : 'Set up'}
          </Button>
        </div>
      </div>
      {open && (
        <div className="mt-2.5">
          <ServiceSetup
            compact
            service={service}
            settings={settings}
            onSaved={(s) => {
              onChange(s);
              setOpen(false);
            }}
          />
        </div>
      )}
    </div>
  );
}

export function SettingsPanel({ settings, onClose, onSaved }: { settings: Settings; onClose: () => void; onSaved: (s: Settings) => void }) {
  const [advanced, setAdvanced] = useState(Boolean(settings.backendUrl));
  const update = async (patch: Partial<Settings>) => {
    const next = { ...settings, ...patch };
    await saveSettings(next);
    onSaved(next);
  };

  return (
    <div>
      <div className="mb-3 flex items-center gap-1">
        <Button variant="ghost" className="!px-1.5" onClick={onClose} aria-label="Back">
          <Icon name="back" />
        </Button>
        <h2 className="text-[15px] font-semibold">Settings</h2>
      </div>

      <Card className="!bg-[var(--accent-soft)] !border-[var(--accent-border)]">
        <p className="text-xs text-[var(--text-2)]">
          <strong className="text-[var(--text)]">Unmask works without any setup.</strong> Every check on the Overview runs inside your browser. The services below add optional extra checks you start with a button.
        </p>
      </Card>

      <SectionTitle>Extra checks</SectionTitle>
      <Card className="divide-y divide-[var(--border)]">
        <ServiceRow service="virustotal" settings={settings} onChange={onSaved} />
        <ServiceRow service="urlscan" settings={settings} onChange={onSaved} />
      </Card>

      {settings.urlscanApiKey && (
        <>
          <SectionTitle>urlscan.io scan visibility</SectionTitle>
          <Card>
            <select
              className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] px-2 py-1.5 text-xs text-[var(--text)]"
              value={settings.urlscanVisibility}
              onChange={(e) => void update({ urlscanVisibility: e.target.value as Settings['urlscanVisibility'] })}
            >
              <option value="unlisted">Unlisted: 1,000 free per day (recommended)</option>
              <option value="private">Private: only you can see it, 50 free per day</option>
              <option value="public">Public: anyone can find it, 5,000 free per day</option>
            </select>
            <p className="mt-1.5 text-[11px] text-[var(--text-3)]">Unlisted scans are hidden from urlscan’s public feed but visible to its security partners.</p>
          </Card>
        </>
      )}

      <SectionTitle>Privacy</SectionTitle>
      <Card>
        <label className="flex cursor-pointer items-start gap-2.5 text-xs">
          <input type="checkbox" className="mt-0.5 accent-[var(--accent)]" checked={settings.autoDomainAge} onChange={(e) => void update({ autoDomainAge: e.target.checked })} />
          <span>
            <span className="font-semibold text-[var(--text)]">Check how old the sender’s domain is</span>
            <span className="mt-0.5 block text-[11px] text-[var(--text-3)]">New domains are a strong phishing sign. Sends only the domain name (for example example.com) to rdap.org, the public domain registry lookup.</span>
          </span>
        </label>
      </Card>

      <SectionTitle
        right={
          <button type="button" className="text-[11px] font-medium text-[var(--accent)]" onClick={() => setAdvanced((a) => !a)}>
            {advanced ? 'Hide' : 'Show'}
          </button>
        }
      >
        Advanced
      </SectionTitle>
      {advanced && (
        <Card>
          <ServiceRow service="backend" settings={settings} onChange={onSaved} />
        </Card>
      )}

      <p className="mt-5 text-center text-[11px] text-[var(--text-3)]">
        Keys never leave this browser except to the service they belong to.{' '}
        <a className="underline" href="https://github.com/praneeth132006/Unmask/blob/main/docs/USER_GUIDE.md" target="_blank" rel="noreferrer">
          User guide
        </a>
      </p>
    </div>
  );
}
