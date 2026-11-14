/** The on-device AI card: hidden without a model, a download button when needed, a reading when ready. */
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import type { Finding } from '../src/core/types';

vi.mock('wxt/browser', () => ({ browser: { storage: { local: { get: async () => ({}), set: async () => {} } }, runtime: { getManifest: () => ({ version: '0' }) } } }));
const { AiCard } = await import('../src/ui/components/AiCard');
const { analyzeRawEmail } = await import('../src/core/analyze');
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let created = 0;
function install(availability: string) {
  created = 0;
  (globalThis as Record<string, unknown>).LanguageModel = {
    availability: async () => availability,
    create: async () => { created++; return { prompt: async () => JSON.stringify({ asks: ['pay-money'], urgent: true, pretendsToBe: 'your CEO', explanation: 'Your boss would not ask for money from a Gmail address.' }), destroy: () => {} }; },
  };
}
afterEach(() => { delete (globalThis as Record<string, unknown>).LanguageModel; });

async function mount(subject: string) {
  const report = await analyzeRawEmail(['From: "Dana" <dana.ceo@gmail.com>', 'To: me@example.org', `Subject: ${subject}`, `Message-ID: <${subject}@x>`, 'Content-Type: text/plain', '', 'Can you handle something for me before 3pm? I will explain later.'].join('\r\n'));
  const found: Finding[] = [];
  const host = document.createElement('div');
  document.body.append(host);
  const root = createRoot(host);
  await act(async () => root.render(createElement(AiCard, { report, onFindings: (f: Finding[]) => void found.push(...f) })));
  await act(async () => new Promise((r) => setTimeout(r, 20)));
  return { host, found, root };
}

it('reads the email when the model is ready, and reports one capped finding', async () => {
  install('available');
  const { host, found, root } = await mount('ready');
  expect(host.textContent).toContain('Your boss would not ask for money from a Gmail address.');
  expect(host.textContent).toContain('It asks you to: Pay money');
  expect(found.map((f) => [f.id, f.severity])).toEqual([['ai-intent', 'medium']]);
  act(() => root.unmount());
});

it('waits for a click before Chrome downloads the model', async () => {
  install('downloadable');
  const { host, root } = await mount('download');
  expect(created).toBe(0);
  const button = [...host.querySelectorAll('button')].find((b) => b.textContent?.includes('Download the model'))!;
  await act(async () => button.click());
  await act(async () => new Promise((r) => setTimeout(r, 20)));
  expect(created).toBe(1);
  expect(host.textContent).toContain('Your boss would not ask');
  act(() => root.unmount());
});

it('shows nothing where the model is unavailable', async () => {
  install('unavailable');
  const { host, root } = await mount('none');
  expect(host.textContent).toBe('');
  act(() => root.unmount());
});
