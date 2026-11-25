import { describe, expect, it } from 'vitest';
import { confirmDialog } from '../src/lib/inpage';

const shadow = () => document.querySelector('[data-unmask-dialog]')!.shadowRoot!;

describe('Preview safely in the click warning', () => {
  it('is offered only when a preview is available, and shows the sandbox picture', async () => {
    void confirmDialog(document, { title: 'Wait', reasons: [] });
    expect(shadow().querySelector('.pv')).toBeNull();
    let release!: (v: { image: string; caption: string }) => void;
    void confirmDialog(document, { title: 'Wait', reasons: [], preview: () => new Promise((r) => { release = r; }) });
    const btn = shadow().querySelector('.pv button') as HTMLButtonElement;
    expect(btn.textContent).toMatch(/Preview the page safely/);
    btn.click();
    expect(shadow().querySelector('.pv p')!.textContent).toMatch(/sandbox/);
    release({ image: 'data:image/png;base64,AA==', caption: 'The link ended on evil.top.' });
    await new Promise((r) => setTimeout(r, 0));
    expect((shadow().querySelector('.pv img') as HTMLImageElement).src).toMatch(/^data:image\/png/);
    expect(shadow().querySelector('.pv p')!.textContent).toBe('The link ended on evil.top.');
  });

  it('shows the error and a report link when the scan fails', async () => {
    void confirmDialog(document, { title: 'Wait', reasons: [], preview: async () => ({ error: 'Still scanning.', link: 'https://urlscan.io/result/x/' }) });
    (shadow().querySelector('.pv button') as HTMLButtonElement).click();
    await new Promise((r) => setTimeout(r, 0));
    expect(shadow().querySelector('.pv p')!.textContent).toMatch(/Still scanning/);
    expect((shadow().querySelector('.pv a') as HTMLAnchorElement).href).toBe('https://urlscan.io/result/x/');
  });
});
