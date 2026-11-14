/** The Links tab turns a traced landing page into a visible warning and a red flag for the score. */
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import type { Finding } from '../src/core/types';

vi.mock('wxt/browser', () => ({ browser: { storage: { local: { get: async () => ({}), set: async () => {} } }, permissions: { contains: async () => true, request: async () => true }, runtime: { sendMessage: async () => undefined } } }));
vi.mock('../src/integrations/trace', async (orig) => ({
  ...(await orig<typeof import('../src/integrations/trace')>()),
  hasTracePermission: async () => true,
  traceBuiltinFromPanel: async () => ({
    hops: [{ url: 'https://secure-doc-view.top/s', status: 200 }],
    finalUrl: 'https://secure-doc-view.top/s',
    truncated: false,
    landing: { captcha: 'Cloudflare Turnstile', fakeLogin: 'Microsoft', relayedLogin: null, passwordField: true, host: 'secure-doc-view.top' },
  }),
}));

const { LinksTab } = await import('../src/ui/components/LinksTab');
const { analyzeRawEmail } = await import('../src/core/analyze');
const { DEFAULT_SETTINGS } = await import('../src/lib/settings');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

it('shows the fake sign-in found behind the link and reports it', async () => {
  const report = await analyzeRawEmail(['From: IT <it@example.com>', 'Subject: Mailbox', 'Content-Type: text/html', '', '<a href="https://secure-doc-view.top/s">Open</a>'].join('\r\n'));
  const found: Finding[] = [];
  const host = document.createElement('div');
  document.body.append(host);
  const root = createRoot(host);
  await act(async () => root.render(createElement(LinksTab, { report, settings: { ...DEFAULT_SETTINGS, traceMode: 'builtin' }, onSettingsChange: () => {}, onFindings: (f: Finding[]) => void found.push(...f) })));
  const button = [...host.querySelectorAll('button')].find((b) => b.textContent?.includes('Trace redirects'))!;
  await act(async () => button.click());
  await act(async () => new Promise((r) => setTimeout(r, 20)));
  expect(host.textContent).toContain('Lands on a fake Microsoft sign-in page at secure-doc-view.top, behind Cloudflare Turnstile');
  expect(found.map((f) => [f.id, f.severity])).toEqual([['landing-fake-login-0', 'critical']]);
  act(() => root.unmount());
});
