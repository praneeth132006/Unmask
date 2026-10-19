import { buildSafeSrcDoc, countRemoteImages } from '../src/ui/safeHtml';
import { parseReceived } from '../src/ui/components/HeadersTab';

describe('buildSafeSrcDoc', () => {
  const html = '<html><body><a href="https://evil.top/x" onclick="steal()">Click</a><script>alert(1)</script><form action="https://evil.top/p"><input></form><img src="https://t.example/p.gif"><img src="cid:logo@x"></body></html>';
  const attachments = [{ filename: 'logo.png', mimeType: 'image/png', size: 3, disposition: 'inline', contentId: '<logo@x>', related: true, content: new Uint8Array([1, 2, 3]) }];

  it('disarms links, scripts, handlers and forms', () => {
    const out = buildSafeSrcDoc(html, { reveal: false, remoteImages: false, attachments });
    expect(out).not.toContain('<script');
    expect(out).not.toContain('onclick');
    expect(out).not.toContain('href="https://evil.top/x"');
    expect(out).toContain('title="Real destination: https://evil.top/x"');
    expect(out).not.toContain('action="https://evil.top/p"');
  });

  it('blocks remote images with a CSP unless allowed', () => {
    expect(buildSafeSrcDoc(html, { reveal: false, remoteImages: false, attachments })).toContain("img-src data:;");
    expect(buildSafeSrcDoc(html, { reveal: false, remoteImages: true, attachments })).toContain('img-src data: https: http:');
  });

  it('inlines cid: images', () => {
    expect(buildSafeSrcDoc(html, { reveal: false, remoteImages: false, attachments })).toContain('src="data:image/png;base64,AQID"');
  });

  it('adds reveal styles only when asked', () => {
    expect(buildSafeSrcDoc(html, { reveal: true, remoteImages: false, attachments })).toContain('HIDDEN (');
    expect(buildSafeSrcDoc(html, { reveal: false, remoteImages: false, attachments })).not.toContain('HIDDEN (');
  });

  it('counts remote images', () => {
    expect(countRemoteImages(html)).toBe(1);
  });
});

describe('parseReceived', () => {
  it('orders hops from origin to inbox', () => {
    const hops = parseReceived([
      'from mx.google.com by inbox.example.com; Mon, 19 Oct 2026 09:13:00 -0700',
      'from mail.evil.xyz (mail.evil.xyz [185.220.101.4]) by mx.google.com with ESMTPS id abc; Mon, 19 Oct 2026 09:12:03 -0700',
    ]);
    expect(hops[0]).toMatchObject({ from: 'mail.evil.xyz', by: 'mx.google.com', ip: '185.220.101.4' });
    expect(hops[1]?.by).toBe('inbox.example.com');
  });
});
