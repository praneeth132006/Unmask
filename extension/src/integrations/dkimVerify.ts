/**
 * Full DKIM signature verification, the same check a receiving mail server
 * does: fetch the signer's public key from DNS and verify the signature over
 * the exact signed bytes. Only the key's DNS name (selector._domainkey.domain)
 * is looked up, over DNS-over-HTTPS; the email itself never leaves.
 *
 * Your provider already checked this on arrival. Doing it again catches
 * what that verdict can't show: an email changed after it arrived (edited
 * .eml files), a signature with no published key, keys withdrawn or too
 * weak to trust.
 */
import type { DkimSignatureInfo, Finding } from '../core/types';
import { signedData, toBytes, type DkimSignature } from '../lib/dkim';
import { parseTags, type RawMessage } from '../lib/rawMessage';
import { sameOrg } from '../lib/domain';
import { brandOwningDomain } from '../analyzers/brands';
import { doh } from './domainIntel';

export interface DkimKey {
  /** "rsa" or "ed25519". */
  type: string;
  /** Raw key bytes from p=; empty when the key was withdrawn. */
  key: Uint8Array;
  testing: boolean;
  /** Allowed hash algorithms (h=), lowercase, empty for any. */
  hashes: string[];
}

/** Fetches selector._domainkey.domain. Null when nothing is published. */
export type KeyResolver = (selector: string, domain: string) => Promise<string | null>;

export const dnsKeyResolver: KeyResolver = async (selector, domain) => {
  const txt = await doh(`${selector}._domainkey.${domain}`, 'TXT');
  return txt.find((t) => /(^|;)\s*p\s*=/i.test(t)) ?? null;
};

function fromBase64(b64: string): Uint8Array {
  return toBytes(atob(b64.replace(/[^A-Za-z0-9+/=]/g, '')));
}

export function parseKeyRecord(record: string): DkimKey {
  const t = parseTags(record);
  return {
    type: (t.k ?? 'rsa').toLowerCase(),
    key: t.p ? fromBase64(t.p) : new Uint8Array(),
    testing: (t.t ?? '').toLowerCase().split(':').includes('y'),
    hashes: (t.h ?? '').toLowerCase().split(':').filter(Boolean),
  };
}

async function rsaBits(key: CryptoKey): Promise<number> {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  const n = atob((jwk.n ?? '').replace(/-/g, '+').replace(/_/g, '/'));
  return (n.length - (n.charCodeAt(0) === 0 ? 1 : 0)) * 8;
}

/** Verifies one signature. Never throws; problems become the result. */
export async function verifySignature(msg: RawMessage, sig: DkimSignature, resolve: KeyResolver = dnsKeyResolver): Promise<DkimSignatureInfo> {
  const info: DkimSignatureInfo = { ...sig };
  delete (info as Partial<DkimSignature>).header;
  delete (info as Partial<DkimSignature>).tags;
  const done = (signature: NonNullable<DkimSignatureInfo['signature']>, reason?: string) => ({ ...info, signature, ...(reason ? { reason } : {}) });

  if (!sig.selector) return done('error', 'The signature names no key (no s= selector).');
  const iDomain = sig.tags.i?.split('@').pop()?.toLowerCase();
  if (iDomain && iDomain !== sig.domain && !iDomain.endsWith(`.${sig.domain}`)) return done('fail', `The signer identity (i=${iDomain}) is outside the signing domain ${sig.domain}.`);

  let record: string | null;
  try {
    record = await resolve(sig.selector, sig.domain);
  } catch (e) {
    return done('error', `Could not look up the key: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (!record) return done('no-key', `${sig.domain} publishes no key named "${sig.selector}".`);
  const key = parseKeyRecord(record);
  info.testing = key.testing;
  if (!key.key.length) return done('revoked', `${sig.domain} has withdrawn this signing key.`);

  const hash = sig.algorithm.endsWith('sha1') ? 'SHA-1' : 'SHA-256';
  if (key.hashes.length && !key.hashes.includes(hash.replace('-', '').toLowerCase())) return done('fail', `The key doesn't allow ${hash}.`);
  const data = toBytes(signedData(msg, sig)) as BufferSource;
  const signature = fromBase64(sig.tags.b ?? '') as BufferSource;
  try {
    if (sig.algorithm.startsWith('ed25519')) {
      if (key.type !== 'ed25519') return done('fail', 'The key type does not match the signature.');
      // RFC 8463: the Ed25519 signature is over the SHA-256 hash of the signed data.
      const digest = await crypto.subtle.digest('SHA-256', data);
      const k = await crypto.subtle.importKey('raw', key.key as BufferSource, { name: 'Ed25519' }, false, ['verify']);
      info.keyBits = 256;
      return done((await crypto.subtle.verify({ name: 'Ed25519' }, k, signature, digest)) ? 'pass' : 'fail', undefined);
    }
    if (key.type !== 'rsa') return done('unsupported', `Unknown key type "${key.type}".`);
    const k = await crypto.subtle.importKey('spki', key.key as BufferSource, { name: 'RSASSA-PKCS1-v1_5', hash }, true, ['verify']);
    info.keyBits = await rsaBits(k);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', k, signature, data);
    return done(ok ? 'pass' : 'fail', ok ? undefined : sig.bodyHash === 'mismatch' ? 'The body was changed after signing.' : 'The signed headers were changed after signing.');
  } catch (e) {
    return done('unsupported', `This browser can't check ${sig.algorithm} signatures (${e instanceof Error ? e.message : String(e)}).`);
  }
}

export async function verifyAll(msg: RawMessage, sigs: DkimSignature[], resolve?: KeyResolver): Promise<DkimSignatureInfo[]> {
  return Promise.all(sigs.map((s) => verifySignature(msg, s, resolve)));
}

const target = { kind: 'header', key: 'dkim-signature' } as const;

/**
 * Findings from the full check. `providerDkim` lists the domains your
 * provider verified on arrival: a signature that passed then and fails now
 * was usually re-signed with a rotated key, not tampered with.
 */
export function dkimVerifyFindings(results: DkimSignatureInfo[], providerDkim: string[], fromDomain: string): Finding[] {
  const findings: Finding[] = [];
  const passedOnArrival = (d: string) => providerDkim.includes(d);
  const aligned = results.filter((r) => r.signature === 'pass' && sameOrg(r.domain, fromDomain));

  for (const r of results) {
    if (r.signature === 'fail' && r.bodyHash === 'match' && !passedOnArrival(r.domain)) {
      findings.push({ id: `dkim-verify-fail-${r.domain}`, category: 'auth', severity: 'medium', points: 12, title: `${r.domain}'s signature doesn't verify: headers were changed after signing`, detail: `Unmask fetched ${r.domain}'s public key and checked the signature itself. The body is intact, so the From, Subject or another signed header was edited afterwards.`, target });
    } else if (r.signature === 'no-key' && !passedOnArrival(r.domain)) {
      const brand = brandOwningDomain(r.domain);
      findings.push({
        id: `dkim-no-key-${r.domain}`,
        category: 'auth',
        severity: brand ? 'medium' : 'low',
        points: brand ? 12 : 4,
        title: brand ? `Fake ${brand.name} signature: ${r.domain} has no such key` : `${r.domain} publishes no key for its signature`,
        detail: `The signature points to the key "${r.selector}._domainkey.${r.domain}", which doesn't exist.${brand ? ` Adding a signature that names ${r.domain} makes an email look signed by ${brand.name} without being so.` : ' Either the key was removed long ago or the signature was never real.'}`,
        target,
      });
    } else if (r.signature === 'revoked') {
      findings.push({ id: `dkim-revoked-${r.domain}`, category: 'auth', severity: 'low', points: 5, title: `${r.domain} has withdrawn the key this email was signed with`, detail: 'Senders withdraw keys when they retire them. A recent email signed with a withdrawn key, or an old one re-sent now, is suspicious.', target });
    }
    if (r.keyBits && r.keyBits < 1024) {
      findings.push({ id: `dkim-weak-key-${r.domain}`, category: 'auth', severity: 'low', points: 5, title: `${r.domain} signs with a ${r.keyBits}-bit key, too weak to trust`, detail: 'Keys this short can be cracked, so anyone could sign as this domain.', target });
    }
    if (r.testing && r.signature === 'pass') {
      findings.push({ id: `dkim-testing-${r.domain}`, category: 'auth', severity: 'low', points: 2, title: `${r.domain}'s key is in test mode`, detail: 'Its DNS record says t=y: receivers are told not to rely on it.', target });
    }
  }
  if (aligned.length && !findings.some((f) => f.points > 0)) {
    findings.push({ id: 'dkim-verified', category: 'auth', severity: 'good', points: -5, title: `Unmask verified ${aligned[0]!.domain}'s signature itself`, detail: `Checked with ${aligned[0]!.domain}'s public key from DNS (${aligned[0]!.keyBits ?? '?'}-bit ${aligned[0]!.algorithm}): this email is exactly what ${aligned[0]!.domain} signed. That proves who sent it, not that the content is safe.`, target });
  }
  return findings;
}
