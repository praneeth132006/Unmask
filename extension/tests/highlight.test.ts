import { applyHighlight, clearHighlights } from '../src/lib/highlight';

const ref = { permId: 'msg-f:1', legacyId: 'a1', fromName: '', fromEmail: '', subject: '' };

function gmailDom() {
  document.body.innerHTML = `
    <div class="adn ads" data-message-id="#msg-f:1" data-legacy-message-id="a1">
      <span class="gD" email="billing@paypa1.xyz" name="PayPal">PayPal</span>
      <div class="a3s">
        <p>Dear customer, please <b>verify your account</b> within 24 hours. Verify your account now!</p>
        <a href="https://paypa1-secure.top/login">https://www.paypal.com/signin</a>
        <a href="https://github.com/x" data-saferedirecturl="https://www.google.com/url?q=https://evil.top/a&amp;source=gmail">x</a>
      </div>
      <div class="aQH"><span class="aZo" download_url="text/html:Invoice.pdf.html:https://mail.google.com/x">Invoice.pdf.html</span></div>
    </div>`;
}

beforeEach(gmailDom);

describe('applyHighlight', () => {
  it('outlines matching links, including via Gmail safe-redirect URLs', () => {
    expect(applyHighlight(document, ref, { kind: 'links', hrefs: ['https://paypa1-secure.top/login', 'https://evil.top/a'] }, false)).toBe(2);
    expect(document.querySelectorAll('[data-unmask-hl]')).toHaveLength(2);
  });

  it('outlines the sender and attachment chips', () => {
    expect(applyHighlight(document, ref, { kind: 'sender' }, false)).toBe(1);
    expect(applyHighlight(document, ref, { kind: 'attachments', names: ['Invoice.pdf.html'] }, false)).toBe(1);
    expect(document.querySelector('[data-unmask-hl]')?.textContent).toBe('Invoice.pdf.html');
  });

  it('marks every phrase occurrence case-insensitively and restores the text exactly', () => {
    const before = document.querySelector('.a3s')!.innerHTML;
    expect(applyHighlight(document, ref, { kind: 'text', phrases: ['verify your account', 'within 24 hours'] }, false)).toBe(3);
    expect(Array.from(document.querySelectorAll('mark[data-unmask-mark]'), (m) => m.textContent)).toEqual(['verify your account', 'within 24 hours', 'Verify your account']);
    clearHighlights(document);
    expect(document.querySelector('.a3s')!.innerHTML).toBe(before);
  });

  it('outlines the element when a phrase crosses tags', () => {
    document.querySelector('.a3s')!.insertAdjacentHTML('beforeend', '<p id="split">Please confirm <i>your password</i> today</p>');
    expect(applyHighlight(document, ref, { kind: 'text', phrases: ['confirm your password'] }, false)).toBe(1);
    expect(document.querySelector('[data-unmask-hl]')?.id).toBe('split');
  });

  it('clears the previous highlight and handles a missing message', () => {
    applyHighlight(document, ref, { kind: 'sender' }, false);
    expect(applyHighlight(document, { ...ref, permId: 'msg-f:999', legacyId: null }, { kind: 'sender' }, false)).toBe(0);
    expect(document.querySelectorAll('[data-unmask-hl]')).toHaveLength(0);
  });
});

describe('plain-text URL fallback', () => {
  it('finds a link whose visible text is the URL when the href differs', () => {
    document.querySelector('.a3s')!.insertAdjacentHTML('beforeend', '<a id="t" href="https://track.example/x?id=1">https://news.example/story</a>');
    expect(applyHighlight(document, ref, { kind: 'links', hrefs: ['https://news.example/story'] }, false)).toBe(1);
    expect(document.querySelector('[data-unmask-hl]')?.id).toBe('t');
  });
});
