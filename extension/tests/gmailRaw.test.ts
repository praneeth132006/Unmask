import { candidateUrls, describeResponse, findIkInHtml, looksLikeRawEmail, parseOriginalPage, permIdToLegacy } from '../src/lib/gmailRaw';
import { parseEmail } from '../src/core/parse';
import { fixture } from './helpers';

const msg = { permId: 'msg-f:1780954093844218223', legacyId: null, fromName: 'A', fromEmail: 'a@b.com', subject: 's' };

describe('permIdToLegacy', () => {
  it('converts the decimal permanent id to Gmail hex id', () => {
    expect(permIdToLegacy('msg-f:1780954093844218223')).toBe(BigInt('1780954093844218223').toString(16));
    expect(permIdToLegacy('msg-a:r123')).toBeNull();
    expect(permIdToLegacy(null)).toBeNull();
  });
});

describe('findIkInHtml', () => {
  it('reads ik from URLs', () => {
    expect(findIkInHtml('<a href="?ui=2&ik=a1b2c3d4e5&view=pt">')).toBe('a1b2c3d4e5');
  });
  it('reads GLOBALS[9]', () => {
    const g = 'var GLOBALS=[null,null,12345,"/mail/u/0","en","US",null,"x",0,"9f8e7d6c5b",1,"other"];';
    expect(findIkInHtml(g)).toBe('9f8e7d6c5b');
  });
  it('returns null when absent', () => {
    expect(findIkInHtml('<html></html>')).toBeNull();
  });
});

describe('candidateUrls', () => {
  it('tries download first, then show original, with and without ik', () => {
    const urls = candidateUrls('https://mail.google.com', '1', msg, 'a1b2c3d4e5');
    const hex = BigInt('1780954093844218223').toString(16);
    expect(urls[0]).toEqual({ label: 'download (th)', kind: 'download', url: `https://mail.google.com/mail/u/1/?ui=2&ik=a1b2c3d4e5&view=att&th=${hex}&attid=0&disp=comp&safe=1&zw` });
    expect(urls[1]?.url).toBe('https://mail.google.com/mail/u/1/?ik=a1b2c3d4e5&view=om&permmsgid=msg-f%3A1780954093844218223');
    expect(urls.some((u) => u.label.includes('no ik'))).toBe(true);
    expect(new Set(urls.map((u) => u.url)).size).toBe(urls.length);
  });
  it('works without a token', () => {
    const urls = candidateUrls('https://mail.google.com', '0', msg, null);
    expect(urls.every((u) => !u.url.includes('ik='))).toBe(true);
    expect(urls.length).toBe(3);
  });
});

describe('looksLikeRawEmail', () => {
  it('accepts real messages and rejects HTML', () => {
    expect(looksLikeRawEmail(fixture('legit-newsletter.eml'))).toBe(true);
    expect(looksLikeRawEmail('<!DOCTYPE html><html><head><title>Gmail</title>')).toBe(false);
    expect(looksLikeRawEmail('Hello there\nthis is text')).toBe(false);
  });
});

describe('parseOriginalPage', () => {
  const raw = fixture('phishing-paypal.eml');
  const escaped = raw.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const page = `<!DOCTYPE html><html><head><title>Original Message</title></head><body>
    <table><tr><td>Message ID</td><td>&lt;fake-001@paypa1-support.xyz&gt;</td></tr></table>
    <a href="?ui=2&amp;ik=a1b2c3d4e5&amp;view=att&amp;th=18b7&amp;attid=0&amp;disp=comp&amp;safe=1&amp;zw">Download Original</a>
    <pre class="raw_message_text" id="raw_message_text">${escaped}</pre></body></html>`;

  it('extracts the raw message and download link', async () => {
    const r = parseOriginalPage(page, 'https://mail.google.com/mail/u/0/?view=om&permmsgid=x', new DOMParser());
    expect(r.downloadUrl).toBe('https://mail.google.com/mail/u/0/?ui=2&ik=a1b2c3d4e5&view=att&th=18b7&attid=0&disp=comp&safe=1&zw');
    expect(r.raw).toBe(raw);
    expect((await parseEmail(r.raw!)).from?.address).toBe('billing@paypa1-support.xyz');
  });

  it('returns null raw for an unrelated page', () => {
    expect(parseOriginalPage('<html><body><pre>not an email</pre></body></html>', 'https://mail.google.com/', new DOMParser()).raw).toBeNull();
  });
});

describe('describeResponse', () => {
  it('summarises a failed response', () => {
    expect(describeResponse(302, 'https://accounts.google.com/ServiceLogin?x=1', 'text/html; charset=utf-8', '<title>Sign in</title>')).toBe(
      'HTTP 302 from accounts.google.com/ServiceLogin (text/html, 22 bytes, title "Sign in")',
    );
  });
});
