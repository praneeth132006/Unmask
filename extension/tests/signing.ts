/**
 * Real DKIM signatures for tests, made by mailauth (an independent
 * implementation), so the checks are tested against the outside world and
 * not against Unmask's own idea of DKIM.
 */
import { generateKeyPairSync } from 'node:crypto';
import { dkimSign, sealMessage } from 'mailauth';

export function makeKey(bits = 2048) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  // The p= value of a DKIM DNS record: base64 SubjectPublicKeyInfo.
  const p = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  return { pem, p, record: `v=DKIM1; k=rsa; p=${p}` };
}

export function makeEd25519Key() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  // For ed25519 the record holds the raw 32-byte key.
  const p = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
  return { pem, p, record: `v=DKIM1; k=ed25519; p=${p}` };
}

export async function sign(
  message: string,
  opts: { domain?: string; selector?: string; key: { pem: string }; canonicalization?: string; maxBodyLength?: number; signTime?: Date; algorithm?: string; headerList?: string[] },
): Promise<string> {
  const r = await dkimSign(message, {
    signTime: opts.signTime ?? new Date('2026-10-19T16:00:00Z'),
    signatureData: [
      {
        signingDomain: opts.domain ?? 'example.com',
        selector: opts.selector ?? 's1',
        privateKey: opts.key.pem,
        canonicalization: opts.canonicalization ?? 'relaxed/relaxed',
        algorithm: opts.algorithm,
        maxBodyLength: opts.maxBodyLength,
        headerList: opts.headerList,
      } as never,
    ],
  });
  if (r.errors.length) throw new Error(JSON.stringify(r.errors));
  return r.signatures + message;
}

export async function seal(message: string, opts: { domain: string; selector?: string; key: { pem: string }; authResults: string; cv?: 'none' | 'pass' | 'fail'; instance: number }): Promise<string> {
  const headers = await sealMessage(message, {
    signingDomain: opts.domain,
    selector: opts.selector ?? 'arc',
    privateKey: opts.key.pem,
    authResults: opts.authResults,
    cv: opts.cv ?? (opts.instance === 1 ? 'none' : 'pass'),
    i: opts.instance,
    signTime: new Date('2026-10-19T16:00:00Z'),
  } as never);
  return headers.toString() + message;
}

/** A plain message with CRLF line endings. */
export const message = (headers: string[], body: string) => `${headers.join('\r\n')}\r\n\r\n${body}`;
