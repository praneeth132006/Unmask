import { analyzeRawEmail } from '../src/core/analyze';
import { buildSafeSrcDoc } from '../src/ui/safeHtml';
import { describePixelPlace, positionWords } from '../src/ui/pixelPlace';
import { applyHighlight, pixelElements } from '../src/lib/highlight';

const PIXEL = 'https://open.list-manage.com/track/open.php?u=1&id=2';
const BG = 'https://track.example.com/pixel/abc';

function email(html: string): string {
  return ['From: "Shop" <news@shop.com>', 'Subject: Sale', 'Content-Type: text/html; charset=utf-8', '', html].join('\r\n');
}

const HTML = `<p>Hello Sai, our autumn sale starts today.</p>
<img src="https://cdn.shop.com/banner.jpg" width="600">
<p>Shop the new collection before Friday.</p>
<div style="display:none">preview text <img src="https://t.sendgrid.net/wf/open?upn=x" width="1" height="1"></div>
<table><tr><td>Unsubscribe | Privacy</td></tr></table>
<div style="background-image:url(${BG})"></div>
<img src="${PIXEL}" width="1" height="1" alt="">`;

describe('where tracking pixels are', () => {
  it('records each pixel’s number, image position, place and surrounding text', async () => {
    const r = await analyzeRawEmail(email(HTML));
    const px = r.trackers.pixels;
    // Paragraphs are separated by a space in the quoted text.
    expect(px.find((p) => p.service === 'Mailchimp')!.before).toContain('before Friday. Unsubscribe | Privacy');
    expect(px.map((p) => [p.n, p.kind, p.service])).toEqual([
      [1, 'img', 'SendGrid'],
      [2, 'img', 'Mailchimp'],
      [3, 'background', null],
    ]);
    const mc = px.find((p) => p.service === 'Mailchimp')!;
    expect(mc).toMatchObject({ imageIndex: 3, imageCount: 3, size: '1×1', inHiddenBlock: false, after: '' });
    expect(mc.before.endsWith('Unsubscribe | Privacy')).toBe(true);
    expect(mc.positionPct).toBe(100);
    expect(describePixelPlace(mc)).toBe(`Image 3 of 3, at the very end of the email’s visible text (100% of the way down), after “${mc.before}”.`);
    const sg = px.find((p) => p.service === 'SendGrid')!;
    expect(sg.inHiddenBlock).toBe(true);
    expect(describePixelPlace(sg)).toContain('inside a hidden block: you would never see it, but it still loads');
    // The same numbers are on the elements in the annotated HTML.
    expect(r.annotatedHtml).toContain(`data-unmask-pixel="2"`);
  });

  it('cuts quoted text at whole words', async () => {
    const long = 'word '.repeat(40);
    const r = await analyzeRawEmail(email(`<p>${long}tail</p><img src="${PIXEL}" width="1" height="1"><p>head ${long}</p>`));
    const p = r.trackers.pixels[0]!;
    expect(p.before.startsWith('…word ')).toBe(true);
    expect(p.after.endsWith('word…')).toBe(true);
  });

  it('words positions by how far down the email they are', () => {
    expect([0, 20, 50, 80, 100].map(positionWords)).toEqual(['at the very top', 'near the top', 'in the middle', 'near the end', 'at the very end']);
  });

  it('marks each pixel in the safe view and never loads one, even with remote images on', async () => {
    const r = await analyzeRawEmail(email(HTML));
    const doc = buildSafeSrcDoc(r.annotatedHtml!, { reveal: false, remoteImages: true, attachments: [], pixelLabels: { 1: 'SendGrid', 2: 'Mailchimp', 3: 'track.example.com' }, focusPixel: 2 });
    expect(doc).not.toContain(PIXEL);
    expect(doc).not.toContain(BG);
    expect(doc).not.toContain('t.sendgrid.net');
    expect(doc).toContain('https://cdn.shop.com/banner.jpg'); // a real image still loads when allowed
    expect(doc).toContain('● Tracking pixel 2 (Mailchimp): blocked');
    expect(doc).toMatch(/data-unmask-pixel-tag="2"[^>]*data-unmask-focus/);
  });

  it('finds the pixel in Gmail through Gmail’s image proxy and labels its spot', () => {
    document.body.innerHTML = `<div data-message-id="#msg-f:1"><div class="a3s"><p>Unsubscribe</p>
      <img id="real" src="https://ci3.googleusercontent.com/meips/ADKq_Nb=s0-d-e1-ft#${PIXEL}" width="1" height="1"></div></div>`;
    const root = document.querySelector('[data-message-id]')!;
    expect(pixelElements(root, PIXEL).map((e) => e.id)).toEqual(['real']);
    const ref = { permId: 'msg-f:1', legacyId: null, fromName: '', fromEmail: '', subject: '' };
    expect(applyHighlight(document, ref, { kind: 'pixel', src: PIXEL, n: 2 }, false)).toBe(1);
    const label = document.querySelector('[data-unmask-pixel-mark]')!;
    expect(label.textContent).toBe('● Tracking pixel 2 is here');
    expect(label.nextElementSibling?.id).toBe('real');
    applyHighlight(document, ref, null, false);
    expect(document.querySelector('[data-unmask-pixel-mark]')).toBeNull();
  });
});
