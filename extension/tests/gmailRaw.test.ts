import { candidateUrls, decodeEntities, describeResponse, findIkInHtml, looksLikeRawEmail, parseOriginalPage, permIdToLegacy } from '../src/lib/gmailRaw';
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
  it("reads current Gmail's GM_ID_KEY and boot data", () => {
    expect(findIkInHtml("var GM_INITIAL_PADDING_PREF = 'n';var GM_ID_KEY = 'ab12cd34ef';var GM_INBOX_TYPE")).toBe('ab12cd34ef');
    expect(findIkInHtml('["x","AAAA","/mail/u/0",50,"0f1e2d3c4b","me@example.com"]')).toBe('0f1e2d3c4b');
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
    const r = parseOriginalPage(page, 'https://mail.google.com/mail/u/0/?view=om&permmsgid=x');
    expect(r.downloadUrl).toBe('https://mail.google.com/mail/u/0/?ui=2&ik=a1b2c3d4e5&view=att&th=18b7&attid=0&disp=comp&safe=1&zw');
    expect(r.raw).toBe(raw);
    expect((await parseEmail(r.raw!)).from?.address).toBe('billing@paypa1-support.xyz');
  });

  it('returns null raw for an unrelated page', () => {
    expect(parseOriginalPage('<html><body><pre>not an email</pre></body></html>', 'https://mail.google.com/').raw).toBeNull();
  });
});

describe('describeResponse', () => {
  it('summarises a failed response', () => {
    expect(describeResponse(302, 'https://accounts.google.com/ServiceLogin?x=1', 'text/html; charset=utf-8', '<title>Sign in</title>')).toBe(
      'HTTP 302 from accounts.google.com/ServiceLogin (text/html, 22 bytes, title "Sign in")',
    );
  });
});

describe('decodeEntities', () => {
  it('decodes named and numeric entities', () => {
    expect(decodeEntities('&lt;a@b.com&gt; &amp; &quot;x&quot; &#39;y&#39; &#x41;&#66;')).toBe('<a@b.com> & "x" \'y\' AB');
  });
});

describe('parseOriginalPage under Trusted Types', () => {
  it('never touches DOMParser', () => {
    const spy = vi.spyOn(DOMParser.prototype, 'parseFromString');
    parseOriginalPage('<pre id="raw_message_text">From: a@b.com\nTo: c@d.com\nSubject: x\nDate: now\n\nhi</pre>', 'https://mail.google.com/');
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

describe('parseOriginalPage performance', () => {
  it('handles crafted pages with thousands of unterminated tags quickly', () => {
    const t = performance.now();
    expect(parseOriginalPage('<a '.repeat(50_000) + '<pre '.repeat(20_000), 'https://mail.google.com/').raw).toBeNull();
    expect(performance.now() - t).toBeLessThan(500);
  });
});
