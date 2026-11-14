import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { analyzeRawEmail } from '../src/core/analyze';
import { PRACTICE } from '../src/demo/practice';

vi.mock('wxt/browser', () => ({ browser: { storage: { local: { get: async () => ({}), set: async () => {} } }, runtime: { getManifest: () => ({ version: '0' }), getURL: (p: string) => p } } }));
const { Practice, pickRound } = await import('../src/ui/Practice');
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

describe('practice mode', () => {
  it('mixes scams and real emails in every round', () => {
    for (let seed = 0; seed < 20; seed++) {
      let x = seed + 1;
      const rand = () => ((x = (x * 16807) % 2147483647) / 2147483647);
      const r = pickRound(PRACTICE, 10, rand);
      expect(r).toHaveLength(10);
      expect(new Set(r.map((i) => i.id)).size).toBe(10);
      expect(r.filter((i) => i.scam).length).toBe(6);
    }
  });

  it.each(PRACTICE.map((p) => [p.id, p] as const))('Unmask agrees with the answer for %s', async (_id, p) => {
    const r = await analyzeRawEmail(p.raw);
    expect(r.verdict === 'clear').toBe(!p.scam);
  });

  it('nothing in a practice email is clickable', async () => {
    const host = document.createElement('div');
    document.body.append(host);
    const root = createRoot(host);
    await act(async () => root.render(createElement(Practice)));
    await act(async () => new Promise((r) => setTimeout(r, 50)));
    const email = host.querySelector('[aria-label="Practice email"]')!;
    expect(email.querySelectorAll('a, img, iframe, form').length).toBe(0);
    expect(host.querySelector('[aria-label="Progress"]')?.textContent).toBe('Email 1 of 10 · 0 right');
    await act(async () => [...host.querySelectorAll('button')].find((b) => b.textContent === 'It’s a scam')!.click());
    await act(async () => new Promise((r) => setTimeout(r, 30)));
    expect(host.querySelector('[role="status"]')?.textContent).toMatch(/^(Right\.|Not this time\.) This email is (a scam|real)\.$/);
    expect(PRACTICE.some((p) => host.textContent!.includes(p.lesson))).toBe(true);
    await act(async () => [...host.querySelectorAll('button')].find((b) => b.textContent === 'Next email')!.click());
    await act(async () => new Promise((r) => setTimeout(r, 30)));
    expect(host.querySelector('[aria-label="Progress"]')?.textContent).toMatch(/^Email 2 of 10 · [01] right$/);
    act(() => root.unmount());
  });
});
