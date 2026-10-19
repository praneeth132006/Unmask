import { useEffect, useRef, useState } from 'react';
import { EMPTY_PROTECTION, mergeProtection, sanitizeProtection, type ProtectionList } from '../../analyzers/protection';
import { loadProtection, saveProtection } from '../../lib/protectionStore';
import { Button, Card, SectionTitle } from './ui';
import { Icon } from './Icon';

const input = 'w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] px-2 py-1.5 text-xs text-[var(--text)] placeholder:text-[var(--text-3)] focus:border-[var(--accent)] focus:outline-none';
const split = (s: string) => s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);

function Row({ title, sub, onRemove }: { title: string; sub: string; onRemove: () => void }) {
  return (
    <li className="flex items-start justify-between gap-2 py-1.5 text-xs">
      <div className="min-w-0">
        <div className="font-medium text-[var(--text)]">{title}</div>
        <div className="break-all font-mono text-[10.5px] text-[var(--text-3)]">{sub}</div>
      </div>
      <button type="button" className="shrink-0 rounded p-0.5 text-[var(--text-3)] hover:text-[var(--bad)]" aria-label={`Remove ${title}`} onClick={onRemove}>
        <Icon name="close" className="h-3.5 w-3.5" />
      </button>
    </li>
  );
}

function AddPair({ namePlaceholder, valuePlaceholder, onAdd }: { namePlaceholder: string; valuePlaceholder: string; onAdd: (name: string, values: string[]) => string | null }) {
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);
  return (
    <form
      className="mt-1.5 space-y-1.5"
      onSubmit={(e) => {
        e.preventDefault();
        const err = onAdd(name.trim(), split(value));
        setError(err);
        if (!err) {
          setName('');
          setValue('');
        }
      }}
    >
      <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder={namePlaceholder} />
      <div className="flex gap-1.5">
        <input className={input} value={value} onChange={(e) => setValue(e.target.value)} placeholder={valuePlaceholder} />
        <Button type="submit" disabled={!name.trim() || !value.trim()}>
          Add
        </Button>
      </div>
      {error && <p className="text-[11px] text-[var(--bad)]">{error}</p>}
    </form>
  );
}

/** Settings section: protected brands and people, trusted senders, and sharing the list as a file. */
export function ProtectionPanel() {
  const [list, setList] = useState<ProtectionList>(EMPTY_PROTECTION);
  const [note, setNote] = useState<string | null>(null);
  const [trustedValue, setTrustedValue] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    void loadProtection().then(setList);
  }, []);

  const update = async (next: ProtectionList) => setList(await saveProtection(next));

  const exportFile = () => {
    const blob = new Blob([JSON.stringify({ ...list, exportedBy: 'Unmask' }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement('a'), { href: url, download: 'unmask-protection.json' });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    setNote('Saved unmask-protection.json. Send it to family or teammates and they import it here.');
  };

  const importFile = async (file: File) => {
    try {
      if (file.size > 1_000_000) throw new Error('too large');
      const incoming = sanitizeProtection(JSON.parse(await file.text()));
      const total = incoming.brands.length + incoming.contacts.length + incoming.trusted.length;
      if (!total) throw new Error('empty');
      await update(mergeProtection(list, incoming));
      setNote(`Added ${incoming.label ? `“${incoming.label}”: ` : ''}${incoming.brands.length} brands, ${incoming.contacts.length} people, ${incoming.trusted.length} trusted senders. Nothing already on your list was removed.`);
    } catch {
      setNote('That file isn’t an Unmask protection list.');
    }
  };

  return (
    <>
      <SectionTitle>Your protection list</SectionTitle>
      <Card className="space-y-3">
        <p className="text-[11px] text-[var(--text-3)]">
          Tell Unmask who scammers are likely to pretend to be. Anything imitating them gets the strongest warning. Stays in this browser; you can share it as a file.
        </p>

        <div>
          <div className="text-xs font-semibold">Companies you use</div>
          <p className="text-[11px] text-[var(--text-3)]">Your bank, your phone company, your employer’s payroll. Add their real website or email domains.</p>
          <ul className="divide-y divide-[var(--border)]">
            {list.brands.map((b, i) => (
              <Row key={b.name + i} title={b.name} sub={b.domains.join(', ')} onRemove={() => void update({ ...list, brands: list.brands.filter((_, j) => j !== i) })} />
            ))}
          </ul>
          <AddPair
            namePlaceholder="Name, e.g. HDFC Bank"
            valuePlaceholder="Domains, e.g. hdfcbank.com"
            onAdd={(name, domains) => {
              const next = sanitizeProtection({ ...list, brands: [...list.brands, { name, domains }] });
              if (next.brands.length === list.brands.length) return 'Add at least one domain like hdfcbank.com.';
              void update(next);
              return null;
            }}
          />
        </div>

        <div className="border-t border-[var(--border)] pt-3">
          <div className="text-xs font-semibold">People who might be impersonated</div>
          <p className="text-[11px] text-[var(--text-3)]">Your boss, your accountant, a parent. Add every address they really write from.</p>
          <ul className="divide-y divide-[var(--border)]">
            {list.contacts.map((c, i) => (
              <Row key={c.name + i} title={c.name} sub={c.addresses.join(', ')} onRemove={() => void update({ ...list, contacts: list.contacts.filter((_, j) => j !== i) })} />
            ))}
          </ul>
          <AddPair
            namePlaceholder="Name as it appears, e.g. Rahul Sharma"
            valuePlaceholder="Their real email address(es)"
            onAdd={(name, addresses) => {
              const next = sanitizeProtection({ ...list, contacts: [...list.contacts, { name, addresses }] });
              if (next.contacts.length === list.contacts.length) return 'Add a valid email address.';
              void update(next);
              return null;
            }}
          />
        </div>

        <div className="border-t border-[var(--border)] pt-3">
          <div className="text-xs font-semibold">Trusted senders</div>
          <p className="text-[11px] text-[var(--text-3)]">Addresses or whole domains you trust. Their verified emails are marked trusted; fakes using their address are flagged.</p>
          <ul className="divide-y divide-[var(--border)]">
            {list.trusted.map((t, i) => (
              <Row key={t} title={t} sub={t.includes('@') ? 'this address' : 'everyone at this domain'} onRemove={() => void update({ ...list, trusted: list.trusted.filter((_, j) => j !== i) })} />
            ))}
          </ul>
          <form
            className="mt-1.5 flex gap-1.5"
            onSubmit={(e) => {
              e.preventDefault();
              void update(sanitizeProtection({ ...list, trusted: [...list.trusted, ...split(trustedValue)] }));
              setTrustedValue('');
            }}
          >
            <input className={input} value={trustedValue} onChange={(e) => setTrustedValue(e.target.value)} placeholder="anna@acme.com or acme.com" />
            <Button type="submit" disabled={!trustedValue.trim()}>
              Add
            </Button>
          </form>
        </div>

        <div className="border-t border-[var(--border)] pt-3">
          <div className="text-xs font-semibold">Share with family or your team</div>
          <p className="text-[11px] text-[var(--text-3)]">Set the list up once, export it, and import it on every other computer. Importing adds to the list there; it never deletes anything.</p>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            <Button onClick={exportFile} disabled={!list.brands.length && !list.contacts.length && !list.trusted.length}>
              <Icon name="download" className="h-3.5 w-3.5" /> Export list
            </Button>
            <Button onClick={() => fileRef.current?.click()}>
              <Icon name="upload" className="h-3.5 w-3.5" /> Import list
            </Button>
            <input
              ref={fileRef}
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void importFile(f);
                e.target.value = '';
              }}
            />
          </div>
          {note && <p className="mt-1.5 text-[11px] text-[var(--text-2)]">{note}</p>}
        </div>
      </Card>
    </>
  );
}
