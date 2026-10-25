import { browser } from 'wxt/browser';
import { useEffect, useState, type ReactNode } from 'react';
import { saveSettings, type Settings } from '../../lib/settings';
import { clearHistory, historySize, loadHistory } from '../../lib/historyStore';
import { Button, Card, SectionTitle } from './ui';
import { Icon } from './Icon';
import { SERVICES, ServiceSetup, type Service } from './ServiceSetup';
import { ProtectionPanel } from './ProtectionPanel';

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

/** One on/off setting with a title and a one-line explanation. */
export function Toggle({ checked, onChange, title, children }: { checked: boolean; onChange: (v: boolean) => void; title: string; children: ReactNode }) {
  return (
    <label className="flex cursor-pointer items-start gap-2.5 py-2.5 text-xs first:pt-0 last:pb-0">
      <input type="checkbox" className="mt-0.5 accent-[var(--accent)]" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>
        <span className="font-semibold text-[var(--text)]">{title}</span>
        <span className="mt-0.5 block text-[11px] text-[var(--text-3)]">{children}</span>
      </span>
    </label>
  );
}

function HistoryRow() {
  const [count, setCount] = useState<number | null>(null);
  useEffect(() => {
    void loadHistory().then((h) => setCount(historySize(h)));
  }, []);
  return (
    <div className="flex items-center justify-between gap-2 pt-2.5 text-[11px] text-[var(--text-3)]">
      <span>{count === null ? '…' : `${count} sender${count === 1 ? '' : 's'} remembered on this device`}</span>
      <Button
        variant="ghost"
        disabled={!count}
        onClick={async () => {
          await clearHistory();
          setCount(0);
        }}
      >
        Forget all
      </Button>
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

      <SectionTitle>Appearance</SectionTitle>
      <Card>
        <div className="flex rounded-lg bg-[var(--surface-2)] p-0.5" role="radiogroup" aria-label="Theme">
          {(
            [
              ['system', 'System', 'monitor'],
              ['light', 'Light', 'sun'],
              ['dark', 'Dark', 'moon'],
            ] as const
          ).map(([value, label, icon]) => (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={settings.theme === value}
              onClick={() => void update({ theme: value })}
              className={`flex flex-1 items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-xs font-medium transition-colors ${
                settings.theme === value ? 'bg-[var(--surface)] text-[var(--text)] shadow-[var(--shadow)]' : 'text-[var(--text-2)] hover:text-[var(--text)]'
              }`}
            >
              <Icon name={icon} className="h-3.5 w-3.5" /> {label}
            </button>
          ))}
        </div>
        <p className="mt-1.5 text-[11px] text-[var(--text-3)]">System follows your computer’s light or dark setting. Also switchable from the header.</p>
        <div className="mt-3 border-t border-[var(--border)] pt-3">
          <Toggle checked={settings.simpleMode} onChange={(v) => void update({ simpleMode: v })} title="Simple mode: plain words first">
            The Summary shows the verdict, the reasons in everyday words and what to do, with the technical red flags folded away. All tabs (Sender, Links, Files, Body, Privacy, Headers) stay available.
          </Toggle>
        </div>
      </Card>

      <SectionTitle>Protection inside Gmail</SectionTitle>
      <Card className="divide-y divide-[var(--border)]">
        <Toggle checked={settings.peekButtons} onChange={(v) => void update({ peekButtons: v })} title="Peek button in the inbox">
          Check an email from the inbox list without opening it, so its trackers never fire.
        </Toggle>
        <Toggle checked={settings.scanInbox} onChange={(v) => void update({ scanInbox: v })} title="Check new emails before I open them">
          Unmask checks up to 15 unread emails in the list you're looking at and marks the risky ones before you open them. Downloads each email's source from Gmail, like Peek; images and trackers never load.
        </Toggle>
        <Toggle checked={settings.gmailBanner} onChange={(v) => void update({ gmailBanner: v })} title="Warning banner on risky emails">
          A red or amber banner above the email with the main reasons, without opening this panel.
        </Toggle>
        <Toggle checked={settings.inboxBadges} onChange={(v) => void update({ inboxBadges: v })} title="Risk badges in the inbox list">
          Marks risky senders in the email list before you open anything.
        </Toggle>
        <Toggle checked={settings.clickProtection} onChange={(v) => void update({ clickProtection: v })} title="Check before risky links and replies">
          Shows “Wait, this goes to …” before a risky link opens, and warns when Reply would go to a different address.
        </Toggle>
      </Card>

      <ProtectionPanel />

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
      <Card className="divide-y divide-[var(--border)]">
        <Toggle checked={settings.senderHistory} onChange={(v) => void update({ senderHistory: v })} title="Remember who emails me">
          Powers “first contact” warnings and spots impostors using a contact’s name. The list stays in this browser and is never uploaded.
        </Toggle>
        {settings.senderHistory && <HistoryRow />}
        <Toggle checked={settings.autoDomainAge} onChange={(v) => void update({ autoDomainAge: v })} title="Check how old the sender’s domain is">
          New domains are a strong phishing sign. Sends only the domain name (for example example.com) to rdap.org, the public domain registry lookup.
        </Toggle>
        <Toggle checked={settings.domainIntel} onChange={(v) => void update({ domainIntel: v })} title="Check certificate history and mail records">
          Spots brand-new TLS certificates and domains with no mail server. Sends only domain names to crt.sh (Certificate Transparency) and dns.google (public DNS).
        </Toggle>
        <Toggle checked={settings.ipIntel} onChange={(v) => void update({ ipIntel: v })} title="Check who runs the sending server">
          Spots mail sent from home connections and rented servers. Sends the sending server’s IP address (from the email’s delivery path, not yours) to dns.google.
        </Toggle>
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
          <div className="text-[13px] font-semibold">Redirect tracing</div>
          <p className="mt-0.5 text-[11px] text-[var(--text-3)]">How the <em>Trace redirects</em> button follows a link.</p>
          <div className="mt-2 space-y-1.5">
            {(
              [
                ['builtin', 'Inside Unmask (recommended)', 'One click, no setup. Runs in the background without cookies; the website sees your IP address.'],
                ['server', 'My own server', 'Your self-hosted Unmask server makes the requests instead (pnpm backend or Vercel).'],
              ] as const
            ).map(([value, label, hint]) => (
              <label key={value} className="flex cursor-pointer items-start gap-2 text-xs">
                <input type="radio" name="traceMode" className="mt-0.5 accent-[var(--accent)]" checked={settings.traceMode === value} onChange={() => void update({ traceMode: value })} />
                <span>
                  <span className="font-medium text-[var(--text)]">{label}</span>
                  <span className="block text-[11px] text-[var(--text-3)]">{hint}</span>
                </span>
              </label>
            ))}
          </div>
          {settings.traceMode === 'server' && (
            <div className="mt-3 border-t border-[var(--border)] pt-3">
              <ServiceRow service="backend" settings={settings} onChange={onSaved} />
            </div>
          )}
        </Card>
      )}

      <p className="mt-5 text-center text-[11px] text-[var(--text-3)]">
        Unmask {browser.runtime.getManifest?.().version ?? ''} ·{' '}
        Keys never leave this browser except to the service they belong to.{' '}
        <a className="underline" href="https://praneeth132006.github.io/Unmask/guide.html" target="_blank" rel="noreferrer">
          User guide
        </a>
      </p>
    </div>
  );
}
