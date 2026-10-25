import { analyzeRawEmail } from '../src/core/analyze';
import { canonicalizeBody, readDkimSignatures } from '../src/lib/dkim';
import { splitRawMessage } from '../src/lib/rawMessage';
import { makeKey, message, sign } from './signing';

const ids = (fs: { id: string }[]) => fs.map((f) => f.id);
const key = makeKey();
const base = message(['From: Alice <alice@example.com>', 'To: bob@example.org', 'Subject: Invoice 42', 'Date: Mon, 19 Oct 2026 16:00:00 +0000', 'Message-ID: <1@example.com>'], 'Hello  Bob, \r\n\r\nPlease see https://example.com/invoice\r\n\r\n\r\n');

describe('DKIM body hash (local)', () => {
  it('canonicalizes bodies as RFC 6376 says', () => {
    expect(canonicalizeBody('a  b \r\n\r\n\r\n', 'relaxed')).toBe('a b\r\n');
    expect(canonicalizeBody('a  b \r\n\r\n', 'simple')).toBe('a  b \r\n');
    expect(canonicalizeBody('', 'simple')).toBe('\r\n');
    expect(canonicalizeBody('\r\n\r\n', 'relaxed')).toBe('');
  });

  it.each(['relaxed/relaxed', 'simple/simple', 'relaxed/simple', 'simple/relaxed'])('matches a real %s signature', async (c) => {
    const sigs = await readDkimSignatures(splitRawMessage(await sign(base, { key, canonicalization: c })));
    expect(sigs).toHaveLength(1);
    expect(sigs[0]).toMatchObject({ domain: 'example.com', selector: 's1', bodyHash: 'match', canonicalization: c });
    expect(sigs[0]!.signedHeaders).toContain('from');
  });

  it('survives Gmail-style bare LF copies', async () => {
    const signed = (await sign(base, { key })).replace(/\r\n/g, '\n');
    expect((await readDkimSignatures(splitRawMessage(signed)))[0]!.bodyHash).toBe('match');
  });

  it('flags a body changed after signing', async () => {
    const tampered = (await sign(base, { key })).replace('https://example.com/invoice', 'https://evil.top/invoice');
    const r = await analyzeRawEmail(tampered);
    expect(r.forensics.dkim[0]!.bodyHash).toBe('mismatch');
    expect(ids(r.findings)).toContain('dkim-body-altered');
  });

  it('is quiet for an intact signed email', async () => {
    const r = await analyzeRawEmail(await sign(base, { key }));
    expect(r.findings.filter((f) => f.id.startsWith('dkim-') && f.id !== 'dkim-none')).toEqual([]);
  });

  it('flags text appended past an l= limit', async () => {
    const signed = await sign(base, { key, maxBodyLength: 20 });
    const r = await analyzeRawEmail(signed.replace(/\r\n$/, '\r\n<a href="https://evil.top/login">Log in now to keep your account</a>\r\n'.repeat(3)));
    expect(r.forensics.dkim[0]).toMatchObject({ bodyLength: 20, bodyHash: 'match' });
    expect(r.findings.find((f) => f.id === 'dkim-partial-body')?.severity).toBe('medium');
  });

  it('flags a second Subject added on top after signing', async () => {
    const signed = await sign(base, { key, headerList: ['from', 'to', 'subject', 'date'] });
    const r = await analyzeRawEmail(`Subject: URGENT: your account is locked\r\n${signed}`);
    expect(ids(r.findings)).toContain('dkim-added-subject');
  });

  it('notices an old signature', async () => {
    const signed = await sign(base, { key, signTime: new Date('2026-08-01T00:00:00Z') });
    const r = await analyzeRawEmail(`Received: from mx.example.com (mx.example.com [198.51.100.1]) by mx.google.com; Mon, 19 Oct 2026 16:00:00 +0000\r\n${signed}`);
    expect(ids(r.findings)).toContain('dkim-old-signature');
  });
});

describe('DKIM replay', () => {
  it('recognises the Google OAuth-alert replay pattern', async () => {
    const alert = message(['From: Google <no-reply@accounts.google.com>', 'To: attacker.lure@gmail.com', 'Subject: Security alert', 'Date: Mon, 12 Oct 2026 10:00:00 +0000', 'Message-ID: <a1@accounts.google.com>'], 'Google Legal: a subpoena has been issued. View the case: https://sites.google.com/view/case-3381\r\n');
    const signed = await sign(alert, { key, domain: 'accounts.google.com', selector: '20230601', signTime: new Date('2026-10-12T10:00:00Z') });
    const raw = [
      'Delivered-To: victim@example.org',
      'Received: from fwd-03.fwd.privateemail.com (fwd-03.fwd.privateemail.com [198.54.122.148]) by mx.google.com with ESMTPS; Mon, 19 Oct 2026 16:00:00 +0000',
      'Authentication-Results: mx.google.com; dkim=pass header.i=@accounts.google.com header.s=20230601; spf=pass smtp.mailfrom=SRS1=HHH=accounts.google.com==ab12=xyz@eforward.registrar-servers.com; dmarc=pass header.from=accounts.google.com',
      'Return-Path: <SRS1=HHH=accounts.google.com==ab12=xyz@eforward.registrar-servers.com>',
    ].join('\r\n') + '\r\n' + signed;
    const r = await analyzeRawEmail(raw);
    const replay = r.findings.find((f) => f.id === 'dkim-replay');
    expect(replay?.severity).toBe('critical');
    expect(replay?.detail).toMatch(/signed long before.*addressed to someone else.*forwarding service/);
    expect(r.findings.map((f) => f.id)).not.toContain('dmarc-pass');
  });

  it('does not call an ordinary signed email a replay', async () => {
    const r = await analyzeRawEmail(`Received: from mx.example.com (mx.example.com [198.51.100.1]) by mx.google.com; Mon, 19 Oct 2026 16:00:30 +0000\r\n${await sign(base, { key })}`);
    expect(r.findings.map((f) => f.id)).not.toContain('dkim-replay');
  });
});
