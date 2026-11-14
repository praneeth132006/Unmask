import QRCode from 'qrcode';
import { decodeQr, findQrCodes, samplesToRgba, type ImageDecoder } from '../src/analyzers/qr';
import { analyzeRawEmail } from '../src/core/analyze';
import { parseEmail } from '../src/core/parse';
import { makePdf } from './helpers';

/** Renders a real QR code as 8-bit gray samples: 4px modules and a 4-module quiet zone. */
function qrGray(text: string, scale = 4): { width: number; height: number; gray: Uint8Array } {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  const n = qr.modules.size;
  const side = (n + 8) * scale;
  const gray = new Uint8Array(side * side).fill(255);
  for (let y = 0; y < n; y++)
    for (let x = 0; x < n; x++)
      if (qr.modules.get(y, x))
        for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) gray[((y + 4) * scale + dy) * side + (x + 4) * scale + dx] = 0;
  return { width: side, height: side, gray };
}

function email(parts: { name: string; mime: string; bytes: Uint8Array }[], body = 'Scan the code to keep your account.'): string {
  const lines = ['From: IT Desk <it@example.com>', 'Subject: MFA reset', 'MIME-Version: 1.0', 'Content-Type: multipart/mixed; boundary="b"', '', '--b', 'Content-Type: text/plain', '', body];
  for (const p of parts) {
    lines.push('--b', `Content-Type: ${p.mime}; name="${p.name}"`, `Content-Disposition: attachment; filename="${p.name}"`, 'Content-Transfer-Encoding: base64', '', Buffer.from(p.bytes).toString('base64'));
  }
  lines.push('--b--');
  return lines.join('\r\n');
}

describe('QR codes', () => {
  it('decodes a QR code from pixels', () => {
    const { width, height, gray } = qrGray('https://paypa1-secure.top/verify');
    expect(decodeQr(samplesToRgba(gray, width, height, 1)!)).toBe('https://paypa1-secure.top/verify');
  });

  it('finds a QR code drawn inside a PDF without any image decoder', async () => {
    const img = qrGray('https://micros0ft-login.click/mfa');
    const pdf = await makePdf({ images: [img] });
    const codes = await findQrCodes(await parseEmail(email([{ name: 'MFA.pdf', mime: 'application/pdf', bytes: pdf }])));
    expect(codes).toEqual([{ origin: 'image in MFA.pdf', text: 'https://micros0ft-login.click/mfa' }]);
  });

  it('uses the image decoder for image attachments', async () => {
    const img = qrGray('https://example.org/menu');
    const decode: ImageDecoder = async () => samplesToRgba(img.gray, img.width, img.height, 1);
    const codes = await findQrCodes(await parseEmail(email([{ name: 'scan-me.png', mime: 'image/png', bytes: new Uint8Array([137, 80, 78, 71]) }])), decode);
    expect(codes).toEqual([{ origin: 'scan-me.png', text: 'https://example.org/menu' }]);
  });

  it('turns QR links into checked links and a finding', async () => {
    const img = qrGray('https://paypa1.com/login');
    const pdf = await makePdf({ images: [img] });
    const report = await analyzeRawEmail(email([{ name: 'secure.pdf', mime: 'application/pdf', bytes: pdf }]));
    expect(report.qrCodes).toHaveLength(1);
    expect(report.links.find((l) => l.source === 'qr')).toMatchObject({ origin: 'QR code in image in secure.pdf', host: 'paypa1.com' });
    const ids = report.findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(['qr-code', 'link-lookalike']));
  });

  it('ignores images that are not QR codes', async () => {
    const noise = new Uint8Array(64 * 64).map((_, i) => (i * 7919) % 256);
    expect(decodeQr(samplesToRgba(noise, 64, 64, 1)!)).toBeNull();
  });
});

describe('QR link next to the same PDF link', () => {
  it('lists the QR code link even when the PDF also links there', async () => {
    const url = 'https://paypa1.com/login';
    const pdf = await makePdf({ uris: [url], images: [qrGray(url)] });
    const report = await analyzeRawEmail(email([{ name: 'm.pdf', mime: 'application/pdf', bytes: pdf }]));
    expect(report.links.filter((l) => l.href === url).map((l) => l.source).sort()).toEqual(['attachment', 'qr']);
  });
});

describe('QR codes drawn without an image', () => {
  const modules = (text: string) => {
    const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
    const n = qr.modules.size;
    return Array.from({ length: n }, (_, y) => Array.from({ length: n }, (_, x) => !!qr.modules.get(y, x)));
  };
  const htmlEmail = (html: string) => ['From: IT Desk <it@example.com>', 'Subject: MFA reset', 'MIME-Version: 1.0', 'Content-Type: text/html; charset=utf-8', '', html].join('\r\n');
  const textEmail = (text: string) => ['From: IT Desk <it@example.com>', 'Subject: MFA reset', 'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', '', text].join('\r\n');

  it('reads a QR code built from table cells with bgcolor, styles and colspan', async () => {
    const grid = modules('https://micros0ft-mfa.top/r');
    const rows = grid.map((r, y) => {
      // Mix the ways phishing kits colour cells, and merge runs with colspan.
      const cells: string[] = [];
      for (let x = 0; x < r.length; ) {
        let run = 1;
        while (x + run < r.length && r[x + run] === r[x]) run++;
        const color = r[x] ? (y % 3 === 0 ? 'bgcolor="#000000"' : y % 3 === 1 ? 'style="background-color: rgb(0,0,0)"' : 'style="background:black"') : 'bgcolor="#ffffff"';
        cells.push(`<td ${color} colspan="${run}" width="${run * 4}" height="4"></td>`);
        x += run;
      }
      return `<tr>${cells.join('')}</tr>`;
    });
    const r = await analyzeRawEmail(htmlEmail(`<p>Scan to keep your mailbox:</p><table cellpadding="0" cellspacing="0">${rows.join('')}</table>`));
    expect(r.qrCodes).toEqual([{ origin: 'QR code drawn with table cells', text: 'https://micros0ft-mfa.top/r' }]);
    expect(r.links.find((l) => l.source === 'qr')?.host).toBe('micros0ft-mfa.top');
  });

  it('reads a QR code made of half-block characters and of doubled full blocks', async () => {
    const grid = modules('https://paypa1-help.top/q');
    const quiet = (g: boolean[][]) => [Array(g[0]!.length + 4).fill(false), Array(g[0]!.length + 4).fill(false), ...g.map((r) => [false, false, ...r, false, false]), Array(g[0]!.length + 4).fill(false), Array(g[0]!.length + 4).fill(false)];
    const q = quiet(grid);
    const half: string[] = [];
    for (let y = 0; y < q.length; y += 2) half.push('    ' + q[y]!.map((top, x) => { const bottom = q[y + 1]?.[x] ?? false; return top && bottom ? '█' : top ? '▀' : bottom ? '▄' : ' '; }).join(''));
    const r1 = await analyzeRawEmail(textEmail(`Scan this code with your phone:\n${half.join('\n')}\nThanks, IT`));
    expect(r1.qrCodes[0]).toEqual({ origin: 'QR code drawn with text characters', text: 'https://paypa1-help.top/q' });

    const full = q.map((r) => r.map((d) => (d ? '██' : '  ')).join(''));
    const r2 = await analyzeRawEmail(textEmail(`Scan:\n${full.join('\n')}`));
    expect(r2.qrCodes[0]?.text).toBe('https://paypa1-help.top/q');
  });

  it('ignores ordinary layout tables and box-drawing banners', async () => {
    const layout = `<table>${Array.from({ length: 30 }, (_, i) => `<tr>${Array.from({ length: 25 }, (_, j) => `<td bgcolor="${(i + j) % 2 ? '#ffffff' : '#f4f4f4'}">x</td>`).join('')}</tr>`).join('')}</table>`;
    expect((await analyzeRawEmail(htmlEmail(layout))).qrCodes).toEqual([]);
    const banner = Array.from({ length: 12 }, () => '████████████████████████████').join('\n');
    expect((await analyzeRawEmail(textEmail(banner))).qrCodes).toEqual([]);
  });
});
