import { inspectContents } from '../src/analyzers/documents';
import { inspectAttachment } from '../src/analyzers/attachments';
import { analyzeRawEmail } from '../src/core/analyze';
import { pdfUris, zipEntries } from '../src/lib/binary';
import { makePdf, makeZip } from './helpers';

const enc = (s: string) => new TextEncoder().encode(s);
const ids = (fs: { id: string }[]) => fs.map((f) => f.id);

describe('looking inside attachments', () => {
  it('reads links from a PDF, including compressed object streams', async () => {
    const pdf = await makePdf({ uris: ['https://paypa1-secure.top/login'], compressedUris: ['https://evil.example/x?a=(1)'] });
    const r = await inspectContents(pdf, 'pdf', 'application/pdf');
    expect(r?.contents.links).toEqual(['https://paypa1-secure.top/login', 'https://evil.example/x?a=(1)']);
    expect(ids(r!.flags)).toContain('pdf-lure');
  });

  it('flags PDF JavaScript and launch actions', async () => {
    const r = await inspectContents(await makePdf({ extra: '/OpenAction << /S /JavaScript /JS (app.alert(1)) >> /Launch' }), 'pdf', 'application/pdf');
    expect(ids(r!.flags)).toEqual(expect.arrayContaining(['pdf-javascript', 'pdf-launch']));
  });

  it('decodes hex and escaped PDF URI strings', () => {
    expect(pdfUris('/URI <68747470733a2f2f612e6578616d706c65>')).toEqual(['https://a.example']);
    expect(pdfUris('/URI (https://a.example/\\(x\\))')).toEqual(['https://a.example/(x)']);
  });

  it('lists ZIP contents and flags programs inside', async () => {
    const zip = await makeZip([
      { name: 'invoice/Invoice_2026.pdf.exe', data: enc('MZ...') },
      { name: 'readme.txt', data: enc('hello'), deflate: true },
    ]);
    expect(zipEntries(zip).map((e) => e.name)).toEqual(['invoice/Invoice_2026.pdf.exe', 'readme.txt']);
    const r = await inspectContents(zip, 'zip', 'application/zip');
    expect(r?.contents.files.map((f) => f.name)).toHaveLength(2);
    expect(ids(r!.flags)).toContain('zip-executable');
  });

  it('finds macros and remote templates in Office files', async () => {
    const docx = await makeZip([
      { name: '[Content_Types].xml', data: enc('<Types/>') },
      { name: 'word/document.xml', data: enc('<w:document/>'), deflate: true },
      { name: 'word/vbaProject.bin', data: enc('VBA') },
      {
        name: 'word/_rels/settings.xml.rels',
        deflate: true,
        data: enc('<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://cdn.bad.example/t.dotm" TargetMode="External"/></Relationships>'),
      },
    ]);
    const r = await inspectContents(docx, 'docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    expect(r?.contents).toMatchObject({ kind: 'office', macros: true, links: ['https://cdn.bad.example/t.dotm'] });
    expect(ids(r!.flags)).toEqual(expect.arrayContaining(['office-macros', 'office-remote-template']));
  });

  it('collects form targets from HTML attachments', async () => {
    const html = enc('<form action="https://collect.bad.example/p"><input type="password"></form><a href="https://x.example">x</a>');
    const r = await inspectContents(html, 'html', 'text/html');
    expect(r?.contents.links).toEqual(['https://collect.bad.example/p', 'https://x.example']);
  });

  it('puts links found in files through the normal link checks', async () => {
    const pdf = await makePdf({ uris: ['https://paypa1.com/signin'] });
    const b64 = Buffer.from(pdf).toString('base64');
    const raw = [
      'From: Billing <billing@example.com>',
      'Subject: Invoice',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="b"',
      '',
      '--b',
      'Content-Type: text/plain',
      '',
      'See attached.',
      '--b',
      'Content-Type: application/pdf; name="invoice.pdf"',
      'Content-Disposition: attachment; filename="invoice.pdf"',
      'Content-Transfer-Encoding: base64',
      '',
      b64,
      '--b--',
    ].join('\r\n');
    const report = await analyzeRawEmail(raw);
    const link = report.links.find((l) => l.source === 'attachment');
    expect(link).toMatchObject({ origin: 'invoice.pdf', host: 'paypa1.com' });
    expect(ids(report.findings)).toContain('link-lookalike');
    expect(report.attachments[0]!.contents?.kind).toBe('pdf');
  });

  it('does not look inside inline images', async () => {
    const att = await inspectAttachment({ filename: 'logo.png', mimeType: 'image/png', size: 4, disposition: 'inline', related: true, content: enc('%PDF') });
    expect(att.contents).toBeUndefined();
  });
});
