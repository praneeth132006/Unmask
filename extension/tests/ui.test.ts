import { buildSafeSrcDoc, countRemoteImages } from '../src/ui/safeHtml';

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

describe('safe view hardening', () => {
  const att = (mimeType: string) => [{ filename: 'x', mimeType, size: 3, disposition: 'inline', contentId: '<x@y>', related: true, content: new Uint8Array([1, 2, 3]) }];

  it('drops <link> prefetch hints, metas from the email, ping attributes and noscript', () => {
    const out = buildSafeSrcDoc('<head><link rel="dns-prefetch" href="//t.evil.top"><link rel="stylesheet" href="https://x/a.css"><meta http-equiv="refresh" content="0;url=https://evil.top"></head><body><a href="https://x" ping="https://t.evil.top/p">x</a><noscript><img src="https://t/p"></noscript></body>', { reveal: false, remoteImages: false, attachments: [] });
    expect(out).not.toContain('rel="dns-prefetch"');
    expect(out).not.toContain('stylesheet');
    expect(out).not.toContain('url=https://evil.top');
    expect(out).not.toContain('ping=');
    expect(out).not.toContain('<noscript');
    expect(out).toContain('x-dns-prefetch-control');
  });

  it('only inlines cid: parts that are images', () => {
    const html = '<img src="cid:x@y">';
    expect(buildSafeSrcDoc(html, { reveal: false, remoteImages: false, attachments: att('image/png') })).toContain('data:image/png');
    expect(buildSafeSrcDoc(html, { reveal: false, remoteImages: false, attachments: att('text/html') })).not.toContain('data:text/html');
  });

  it('counts remote images in linear time on crafted input', () => {
    const t = performance.now();
    expect(countRemoteImages('<img '.repeat(40_000))).toBe(0);
    expect(performance.now() - t).toBeLessThan(1500);
  });
});

describe('plain-text URL splitting', () => {
  it('separates URLs from text and trims trailing punctuation', async () => {
    const { splitUrls } = await import('../src/ui/components/BodyTab');
    expect(splitUrls('Read https://click.email.bbc.com/?qs=AB_12. Thanks')).toEqual([
      { text: 'Read ' },
      { text: 'https://click.email.bbc.com/?qs=AB_12', url: 'https://click.email.bbc.com/?qs=AB_12' },
      { text: '. Thanks' },
    ]);
  });
});
