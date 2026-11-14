import { useState } from 'react';
import type { Settings } from '../../lib/settings';
import { hashPin, newSalt, pinMatches, validHelper } from '../../lib/family';
import { Button, Card, SectionTitle } from './ui';

const INPUT = 'w-full rounded-lg border border-[var(--border-strong)] bg-[var(--surface)] px-2.5 py-1.5 text-xs text-[var(--text)] outline-none focus:border-[var(--accent)]';
const PIN_RE = /^\d{4,8}$/;

/** Settings stay locked behind the PIN in family mode, so protection isn't switched off by accident. */
export function SettingsLock({ settings, onUnlock }: { settings: Settings; onUnlock: () => void }) {
  const [pin, setPin] = useState('');
  const [wrong, setWrong] = useState(false);
  const tryPin = async () => {
    if (await pinMatches(pin, settings.familyPinSalt, settings.familyPinHash)) onUnlock();
    else {
      setWrong(true);
      setPin('');
    }
  };
  return (
    <Card className="mt-2 text-center" aria-label="Settings are locked">
      <p className="text-sm font-semibold">Settings are locked</p>
      <p className="mt-1 text-xs text-[var(--text-2)]">Family mode is on{settings.helperName ? `, set up with ${settings.helperName}` : ''}. Enter the PIN to change anything.</p>
      <div className="mx-auto mt-3 flex max-w-[220px] gap-1.5">
        <input className={INPUT} type="password" inputMode="numeric" autoComplete="off" aria-label="PIN" value={pin} onChange={(e) => { setPin(e.target.value); setWrong(false); }} onKeyDown={(e) => e.key === 'Enter' && void tryPin()} />
        <Button variant="primary" onClick={() => void tryPin()}>Unlock</Button>
      </div>
      {wrong && <p className="mt-1.5 text-xs text-[var(--bad)]">That PIN isn’t right.</p>}
      <p className="mt-3 text-[11px] text-[var(--text-3)]">Forgot it? Removing and reinstalling Unmask clears the PIN, along with your settings.</p>
    </Card>
  );
}

/** Family mode: who to ask, and an optional PIN for Settings. */
export function FamilySettings({ settings, update }: { settings: Settings; update: (patch: Partial<Settings>) => Promise<void> }) {
  const [name, setName] = useState(settings.helperName);
  const [email, setEmail] = useState(settings.helperEmail);
  const [pin, setPin] = useState('');
  const [msg, setMsg] = useState<string | null>(null);
  const helperOk = validHelper({ name, email });

  return (
    <>
      <SectionTitle>Family mode</SectionTitle>
      <Card className="space-y-2.5">
        <label className="flex cursor-pointer items-start gap-2.5">
          <input
            type="checkbox"
            className="mt-0.5 accent-[var(--accent)]"
            checked={settings.familyMode}
            // Turning it on also turns on plain words; turning it off keeps the user's own choice.
            onChange={(e) => void update(e.target.checked ? { familyMode: true, simpleMode: true } : { familyMode: false })}
          />
          <span>
            <span className="block text-[13px] font-semibold">Ask someone I trust before risky emails</span>
            <span className="mt-0.5 block text-[11px] text-[var(--text-3)]">On High risk emails there is no “Open anyway” or “Reply anyway”. Instead, an <strong>Ask</strong> button writes an email to your helper with what Unmask found, from your own mail app. Nothing goes through Unmask.</span>
          </span>
        </label>
        {settings.familyMode && (
          <div className="space-y-2 border-t border-[var(--border)] pt-2.5">
            <div className="grid grid-cols-2 gap-1.5">
              <input className={INPUT} placeholder="Helper’s name (e.g. Sam)" aria-label="Helper’s name" value={name} onChange={(e) => setName(e.target.value)} />
              <input className={INPUT} placeholder="sam@example.com" type="email" aria-label="Helper’s email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <Button
              disabled={!helperOk || (name === settings.helperName && email === settings.helperEmail)}
              onClick={async () => {
                await update({ helperName: name.trim(), helperEmail: email.trim() });
                setMsg('Saved.');
              }}
            >
              Save helper
            </Button>
            {!helperOk && email && <p className="text-[11px] text-[var(--warn)]">Enter a full email address.</p>}
            <div className="border-t border-[var(--border)] pt-2.5">
              <p className="text-xs font-semibold">{settings.familyPinHash ? 'Settings are locked with a PIN' : 'Lock Settings with a PIN (optional)'}</p>
              <p className="mt-0.5 text-[11px] text-[var(--text-3)]">So family mode isn’t switched off by accident. 4 to 8 digits, stored only as a fingerprint in this browser.</p>
              <div className="mt-1.5 flex gap-1.5">
                <input className={INPUT} type="password" inputMode="numeric" autoComplete="new-password" aria-label="New PIN" placeholder={settings.familyPinHash ? 'New PIN' : 'PIN'} value={pin} onChange={(e) => setPin(e.target.value)} />
                <Button
                  disabled={!PIN_RE.test(pin)}
                  onClick={async () => {
                    const salt = newSalt();
                    await update({ familyPinSalt: salt, familyPinHash: await hashPin(pin, salt) });
                    setPin('');
                    setMsg('PIN set. Settings will ask for it next time.');
                  }}
                >
                  {settings.familyPinHash ? 'Change PIN' : 'Set PIN'}
                </Button>
                {settings.familyPinHash && (
                  <Button variant="ghost" onClick={async () => { await update({ familyPinHash: '', familyPinSalt: '' }); setMsg('PIN removed.'); }}>
                    Remove
                  </Button>
                )}
              </div>
              {pin && !PIN_RE.test(pin) && <p className="mt-1 text-[11px] text-[var(--warn)]">Use 4 to 8 digits.</p>}
            </div>
            {msg && <p className="text-[11px] text-[var(--good)]">{msg}</p>}
          </div>
        )}
      </Card>
    </>
  );
}
