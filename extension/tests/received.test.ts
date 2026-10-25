import { deliveryPath, originIp, parseReceivedLine, receivedFindings } from '../src/analyzers/received';
import { splitRawMessage, parseTags } from '../src/lib/rawMessage';
import { analyzeRawEmail } from '../src/core/analyze';
import { fixture } from './helpers';

const ids = (fs: { id: string }[]) => fs.map((f) => f.id);

describe('raw message', () => {
  it('keeps header order and folding, rebuilds CRLF', () => {
    const m = splitRawMessage('A: 1\nDKIM-Signature: v=1;\n\td=x.com\nB: 2\n\nbody\n');
    expect(m.rebuiltLineEndings).toBe(true);
    expect(m.headers.map((h) => h.key)).toEqual(['a', 'dkim-signature', 'b']);
    expect(m.headers[1]!.raw).toBe('DKIM-Signature: v=1;\r\n\td=x.com');
    expect(m.body).toBe('body\r\n');
    expect(parseTags(m.headers[1]!.rawValue)).toEqual({ v: '1', d: 'x.com' });
  });

  it('keeps bytes as bytes', () => {
    const m = splitRawMessage(new Uint8Array([...new TextEncoder().encode('A: é\r\n\r\n')]));
    expect(m.headers[0]!.raw).toBe('A: Ã©');
  });
});

describe('Received headers', () => {
  it('reads Postfix, Exim, Microsoft and Gmail styles', () => {
    expect(parseReceivedLine('from mail.evil.xyz (mail.evil.xyz [185.220.101.4]) by mx.google.com with ESMTPS id abc; Mon, 19 Oct 2026 09:12:03 -0700 (PDT)')).toMatchObject({
      helo: 'mail.evil.xyz', rdns: 'mail.evil.xyz', ip: '185.220.101.4', by: 'mx.google.com', protocol: 'ESMTPS', time: Date.parse('2026-10-19T16:12:03Z'),
    });
    expect(parseReceivedLine('from [203.0.113.9] (helo=DESKTOP-7Q2K) by smtp.example.net with esmtpsa; Mon, 19 Oct 2026 16:00:00 +0000')).toMatchObject({ helo: 'desktop-7q2k', ip: '203.0.113.9' });
    expect(parseReceivedLine('from AM0PR04MB1234.eurprd04.prod.outlook.com (2603:10a6:208:12::34) by DB9PR.eurprd04.prod.outlook.com (2603:10a6:10::5) with Microsoft SMTP Server (version=TLS1_2) id 15.20.1; Mon, 19 Oct 2026 16:00:00 +0000')).toMatchObject({ ip: '2603:10a6:208:12::34', by: 'db9pr.eurprd04.prod.outlook.com' });
    expect(parseReceivedLine('from unknown (HELO pc01) (198.51.100.7) by mail.x.org; Mon, 19 Oct 2026 16:00:00 +0000')).toMatchObject({ helo: 'pc01', rdns: 'unknown', ip: '198.51.100.7' });
  });

  it('orders from origin to inbox and trusts only your provider', () => {
    const hops = deliveryPath([
      'by 2002:a05:6a10:abcd with SMTP id x; Mon, 19 Oct 2026 09:12:05 -0700 (PDT)',
      'from mail.evil.xyz (mail.evil.xyz [185.220.101.4]) by mx.google.com with ESMTPS id abc; Mon, 19 Oct 2026 09:12:03 -0700 (PDT)',
      'from [10.0.0.5] by mail.evil.xyz; Mon, 19 Oct 2026 16:12:00 +0000',
    ], 'mx.google.com');
    expect(hops.map((h) => [h.n, h.trusted])).toEqual([[1, false], [2, true], [3, true]]);
    expect(hops[1]!.delaySec).toBe(3);
    expect(originIp(hops)).toBe('185.220.101.4');
    expect(originIp(hops, '[203.0.113.50]')).toBe('203.0.113.50');
  });

  it('flags a computer sending straight to your provider, and forged times', () => {
    const hops = deliveryPath([
      'from DESKTOP-ABC12 (unknown [203.0.113.9]) by mx.google.com with ESMTP; Mon, 19 Oct 2026 16:00:00 +0000',
      'from relay.example.org (relay.example.org [198.51.100.1]) by DESKTOP-ABC12; Wed, 21 Oct 2026 16:00:00 +0000',
    ], 'mx.google.com');
    expect(ids(receivedFindings(hops, null))).toEqual(['received-out-of-order', 'received-workstation', 'received-no-rdns']);
    expect(receivedFindings(hops, null)[0]!.severity).toBe('medium');
  });

  it('compares the Date header with the arrival', () => {
    const hops = deliveryPath(['from a.b.com (a.b.com [198.51.100.1]) by mx.google.com; Mon, 19 Oct 2026 16:00:00 +0000'], 'mx.google.com');
    expect(ids(receivedFindings(hops, 'Mon, 5 Oct 2026 16:00:00 +0000'))).toEqual(['date-old']);
    expect(ids(receivedFindings(hops, 'Tue, 20 Oct 2026 16:00:00 +0000'))).toEqual(['date-future']);
    expect(receivedFindings(hops, 'Mon, 19 Oct 2026 15:59:00 +0000')).toEqual([]);
  });

  it('is quiet for normal mail', async () => {
    const r = await analyzeRawEmail(fixture('legit-newsletter.eml'));
    expect(r.forensics.hops).toHaveLength(1);
    expect(r.findings.filter((f) => f.id.startsWith('received-') || f.id.startsWith('date-'))).toEqual([]);
  });
});

describe('Authentication-Results authenticity', () => {
  const spoof = [
    'Received: from DESKTOP-1 (unknown [203.0.113.9]) by mx1.example-mail.net with ESMTP; Mon, 19 Oct 2026 16:00:00 +0000',
    'Authentication-Results: mx1.example-mail.net; spf=fail smtp.mailfrom=paypal.com; dkim=none; dmarc=fail header.from=paypal.com',
    'Authentication-Results: mx.google.com; dkim=pass header.i=@paypal.com; spf=pass smtp.mailfrom=paypal.com; dmarc=pass header.from=paypal.com',
    'From: PayPal <service@paypal.com>',
    'To: a@example.com',
    'Subject: hi',
    '',
    'body',
  ].join('\n');

  it('ignores a fake Google stamp when Google never handled the email', async () => {
    const r = await analyzeRawEmail(spoof);
    expect(r.auth.dmarc).toBe('fail');
    expect(r.auth.server).toBe('mx1.example-mail.net');
    expect(ids(r.findings)).toEqual(expect.arrayContaining(['auth-results-forged', 'dmarc-fail']));
  });

  it('trusts the Google stamp when Google delivered it', async () => {
    const r = await analyzeRawEmail(fixture('legit-newsletter.eml'));
    expect(ids(r.findings)).not.toContain('auth-results-forged');
    expect(r.auth.dmarc).toBe('pass');
  });
});
