import { applyHighlight, chipName } from '../src/lib/highlight';

const ref = { permId: 'msg-f:1', legacyId: null, fromName: '', fromEmail: '', subject: '' };
const outlined = () => Array.from(document.querySelectorAll('[data-unmask-hl]')).map((e) => e.getAttribute('data-n'));

describe('pointing at the right attachment in Gmail', () => {
  afterEach(() => (document.body.innerHTML = ''));

  it('outlines only the tile with exactly that name, not ones with similar names', () => {
    document.body.innerHTML = `<div data-message-id="#msg-f:1"><div class="a3s"></div><div class="aQH">
      <span class="aZo" data-n="1" download_url="application/pdf:GST-CHALLAN.pdf:https://x/1"></span>
      <span class="aZo" data-n="2" download_url="application/pdf:GST-CHALLAN - K Mallikarjun Naidu.pdf:https://x/2"></span>
      <span class="aZo" data-n="3" download_url="image/png:scan.png:https://x/3"></span></div></div>`;
    expect(applyHighlight(document, ref, { kind: 'attachments', names: ['GST-CHALLAN.pdf'], index: 0 }, false)).toBe(1);
    expect(outlined()).toEqual(['1']);
    applyHighlight(document, ref, { kind: 'attachments', names: ['GST-CHALLAN - K Mallikarjun Naidu.pdf'], index: 1 }, false);
    expect(outlined()).toEqual(['2']);
  });

  it('matches names Gmail shortened with an ellipsis', () => {
    document.body.innerHTML = `<div data-message-id="#msg-f:1"><div class="a3s"></div><div class="aQH">
      <div data-n="1"><span class="aV3">Invoice.pdf</span></div>
      <div data-n="2"><span class="aV3">GST-CHALLAN - K Mallik….pdf</span></div></div></div>`;
    applyHighlight(document, ref, { kind: 'attachments', names: ['GST-CHALLAN - K Mallikarjun Naidu.pdf'] }, false);
    expect(outlined()).toEqual(['2']);
  });

  it('uses the position when two files share a name', () => {
    document.body.innerHTML = `<div data-message-id="#msg-f:1"><div class="a3s"></div><div class="aQH">
      <div data-n="1"><span class="aV3">challan.pdf</span></div>
      <div data-n="2"><span class="aV3">challan.pdf</span></div></div></div>`;
    applyHighlight(document, ref, { kind: 'attachments', names: ['challan.pdf'], index: 1 }, false);
    expect(outlined()).toEqual(['2']);
  });

  it('reads names from download_url and aria-labels', () => {
    const a = document.createElement('span');
    a.setAttribute('download_url', 'application/pdf:a:b.pdf:https://mail.google.com/x');
    expect(chipName(a)).toBe('a:b.pdf');
    const b = document.createElement('div');
    b.setAttribute('aria-label', 'Attachment: report.docx');
    expect(chipName(b)).toBe('report.docx');
  });
});
