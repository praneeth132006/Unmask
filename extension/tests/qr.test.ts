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
