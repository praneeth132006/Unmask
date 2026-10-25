import { readDkimSignatures } from '../src/lib/dkim';
import { splitRawMessage } from '../src/lib/rawMessage';
import { dkimVerifyFindings, parseKeyRecord, verifyAll, type KeyResolver } from '../src/integrations/dkimVerify';
import { makeEd25519Key, makeKey, message, sign } from './signing';

const rsa = makeKey();
const ed = makeEd25519Key();
const base = message(['From: Alice <alice@example.com>', 'To: bob@example.org', 'Subject: Invoice 42', 'Date: Mon, 19 Oct 2026 16:00:00 +0000'], 'Pay invoice 42 at https://example.com/pay\r\n');
const resolver = (records: Record<string, string | null>): KeyResolver => async (s, d) => records[`${s}._domainkey.${d}`] ?? null;

async function check(raw: string, records: Record<string, string | null>) {
  const msg = splitRawMessage(raw);
  return verifyAll(msg, await readDkimSignatures(msg), resolver(records));
}

describe('DKIM signature verification', () => {
  it('parses key records', () => {
    expect(parseKeyRecord('v=DKIM1; k=rsa; t=y:s; p=')).toMatchObject({ type: 'rsa', testing: true, key: new Uint8Array() });
  });

  it.each(['relaxed/relaxed', 'simple/simple', 'relaxed/simple'])('verifies a real RSA %s signature', async (c) => {
    const [r] = await check(await sign(base, { key: rsa, canonicalization: c }), { 's1._domainkey.example.com': rsa.record });
    expect(r).toMatchObject({ signature: 'pass', keyBits: 2048 });
    expect(dkimVerifyFindings([r!], [], 'example.com').map((f) => f.id)).toEqual(['dkim-verified']);
  });

  it('verifies Ed25519 signatures (RFC 8463)', async () => {
    const [r] = await check(await sign(base, { key: ed, algorithm: 'ed25519-sha256' }), { 's1._domainkey.example.com': ed.record });
    expect(r?.signature).toBe('pass');
  });

  it('catches a signed header edited afterwards', async () => {
    const edited = (await sign(base, { key: rsa })).replace('Subject: Invoice 42', 'Subject: Invoice 42 - bank details changed');
    const [r] = await check(edited, { 's1._domainkey.example.com': rsa.record });
    expect(r).toMatchObject({ signature: 'fail', bodyHash: 'match' });
    expect(dkimVerifyFindings([r!], [], 'example.com').map((f) => f.id)).toEqual(['dkim-verify-fail-example.com']);
    // Your provider verified it on arrival: a rotated key, not tampering.
    expect(dkimVerifyFindings([r!], ['example.com'], 'example.com')).toEqual([]);
  });

  it('flags a signature with no published key, harder when it names a brand', async () => {
    const [r] = await check(await sign(base, { key: rsa, domain: 'paypal.com', selector: 'fake' }), {});
    expect(r?.signature).toBe('no-key');
    expect(dkimVerifyFindings([r!], [], 'paypal.com')[0]).toMatchObject({ id: 'dkim-no-key-paypal.com', severity: 'medium' });
  });

  it('reports withdrawn and weak keys', async () => {
    const [revoked] = await check(await sign(base, { key: rsa }), { 's1._domainkey.example.com': 'v=DKIM1; p=' });
    expect(revoked?.signature).toBe('revoked');
    const weak = makeKey(512);
    const [w] = await check(await sign(base, { key: weak }), { 's1._domainkey.example.com': weak.record });
    expect(w).toMatchObject({ signature: 'pass', keyBits: 512 });
    expect(dkimVerifyFindings([w!], [], 'example.com').map((f) => f.id)).toEqual(['dkim-weak-key-example.com']);
  });

  it('survives lookup errors', async () => {
    const msg = splitRawMessage(await sign(base, { key: rsa }));
    const [r] = await verifyAll(msg, await readDkimSignatures(msg), async () => { throw new Error('offline'); });
    expect(r).toMatchObject({ signature: 'error' });
  });
});
