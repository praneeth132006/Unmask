/** Family mode in the panel: the Settings lock, setting a PIN, and the "Ask" card. */
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';

const store: Record<string, unknown> = {};
vi.mock('wxt/browser', () => ({ browser: { storage: { local: { get: async (k: string) => (k in store ? { [k]: store[k] } : {}), set: async (o: Record<string, unknown>) => void Object.assign(store, o), remove: async () => {} } }, runtime: { getManifest: () => ({ version: '0' }) }, permissions: { contains: async () => false } } }));
const { SettingsPanel } = await import('../src/ui/components/SettingsPanel');
const { AskHelperCard } = await import('../src/ui/components/FamilyCards');
const { DEFAULT_SETTINGS } = await import('../src/lib/settings');
const { hashPin } = await import('../src/lib/family');
const { analyzeRawEmail } = await import('../src/core/analyze');
const { fixture } = await import('./helpers');
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

async function render(el: ReturnType<typeof createElement>) {
  const host = document.createElement('div');
  document.body.append(host);
  const root = createRoot(host);
  await act(async () => root.render(el));
  return { host, root };
}
const flush = () => act(async () => new Promise((r) => setTimeout(r, 30)));

it('locks Settings behind the PIN in family mode', async () => {
  const settings = { ...DEFAULT_SETTINGS, familyMode: true, helperName: 'Sam', helperEmail: 'sam@example.org', familyPinSalt: 'ab', familyPinHash: await hashPin('2580', 'ab') };
  const { host, root } = await render(createElement(SettingsPanel, { settings, onClose: () => {}, onSaved: () => {} }));
  expect(host.textContent).toContain('Settings are locked');
  expect(host.textContent).not.toContain('Protection inside Gmail');
  const input = host.querySelector('input[aria-label="PIN"]') as HTMLInputElement;
  const type = async (v: string) => act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, v); input.dispatchEvent(new Event('input', { bubbles: true })); });
  await type('1111');
  await act(async () => [...host.querySelectorAll('button')].find((b) => b.textContent === 'Unlock')!.click());
  await flush();
  expect(host.textContent).toContain('That PIN isn’t right.');
  await type('2580');
  await act(async () => [...host.querySelectorAll('button')].find((b) => b.textContent === 'Unlock')!.click());
  await flush();
  expect(host.textContent).toContain('Protection inside Gmail');
  expect(host.textContent).toContain('Settings are locked with a PIN');
  act(() => root.unmount());
});

it('turning family mode on also turns on plain words', async () => {
  const saved: (typeof DEFAULT_SETTINGS)[] = [];
  const { host, root } = await render(createElement(SettingsPanel, { settings: DEFAULT_SETTINGS, onClose: () => {}, onSaved: (s: typeof DEFAULT_SETTINGS) => void saved.push(s) }));
  const box = [...host.querySelectorAll('label')].find((l) => l.textContent?.includes('Ask someone I trust'))!.querySelector('input')!;
  await act(async () => box.click());
  await flush();
  expect(saved.at(-1)).toMatchObject({ familyMode: true, simpleMode: true });
  act(() => root.unmount());
});

it('shows "Ask Sam" on risky emails only', async () => {
  const risky = await analyzeRawEmail(fixture('phishing-paypal.eml'));
  const clear = await analyzeRawEmail(fixture('legit-newsletter.eml'));
  const a = await render(createElement(AskHelperCard, { report: risky, name: 'Sam', email: 'sam@example.org' }));
  expect(a.host.querySelector('a')?.textContent).toBe('Ask Sam');
  expect(a.host.querySelector('a')?.getAttribute('href')).toMatch(/^mailto:sam@example\.org/);
  const b = await render(createElement(AskHelperCard, { report: clear, name: 'Sam', email: 'sam@example.org' }));
  expect(b.host.textContent).toBe('');
  act(() => { a.root.unmount(); b.root.unmount(); });
});
