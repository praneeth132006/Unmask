/**
 * What the DKIM signatures themselves say, beyond the receiving server's
 * pass/fail: whether the text still matches what was signed, what the
 * signature leaves unprotected, and how old it is.
 */
import type { AuthSummary, Finding } from '../core/types';
import type { DkimSignature } from '../lib/dkim';
import type { RawMessage } from '../lib/rawMessage';
import { sameOrg } from '../lib/domain';

const target = { kind: 'header', key: 'dkim-signature' } as const;
const days = (ms: number) => Math.floor(ms / 86_400_000);

/** Headers whose extra, unsigned copy changes what you see. (Two Froms are flagged on their own, signed or not.) */
const SHOWN = ['subject', 'reply-to', 'to', 'date', 'sender'];

export function dkimFindings(sigs: DkimSignature[], msg: RawMessage, auth: AuthSummary, arrivedAt: number | null, fromDomain: string): Finding[] {
  const findings: Finding[] = [];
  if (!sigs.length) return findings;
  const providerPassed = (d: string) => auth.dkimDomains.some((x) => x === d);

  // 1. The body no longer matches what was signed.
  const altered = sigs.filter((s) => s.bodyHash === 'mismatch');
  const intact = sigs.filter((s) => s.bodyHash === 'match');
  if (altered.length && !intact.length) {
    const s = altered[0]!;
    if (providerPassed(s.domain)) {
      findings.push({ id: 'dkim-body-copy', category: 'auth', severity: 'info', points: 0, title: 'This copy of the email differs from what was signed', detail: `Your mail provider verified ${s.domain}'s signature when the email arrived, but the text Unmask was given has changed since. That usually means it was copied or pasted rather than downloaded as the original.`, target });
    } else if (auth.dkim !== 'fail') {
      findings.push({
        id: 'dkim-body-altered',
        category: 'auth',
        severity: msg.rebuiltLineEndings ? 'low' : 'medium',
        points: msg.rebuiltLineEndings ? 4 : 12,
        title: 'The text was changed after it was signed',
        detail: `The email is signed by ${s.domain}, but its body no longer matches the signature. Someone or something changed it on the way: a forwarder adding a footer, or a tampered message.${msg.rebuiltLineEndings ? ' (This copy had lost its line endings, which can also cause this.)' : ''}`,
        target,
      });
    }
  }

  // 2. Only the first part of the body is signed (l=), so text can be added below it.
  const partial = sigs.find((s) => s.bodyLength !== null && s.bodyHash === 'match');
  if (partial) {
    const extra = msg.body.length - partial.bodyLength!;
    findings.push({
      id: 'dkim-partial-body',
      category: 'auth',
      severity: extra > 64 ? 'medium' : 'low',
      points: extra > 64 ? 10 : 3,
      title: extra > 64 ? 'Content was added after the signed part' : 'Only part of the body is signed',
      detail: `${partial.domain}'s signature covers only the first ${partial.bodyLength} bytes of the body (an "l=" limit)${extra > 64 ? `, and about ${extra} more bytes follow it. Anyone can append text or links there without breaking the signature` : '. Anything appended later would not break the signature'}.`,
      target,
    });
  }

  for (const s of sigs) {
    // 3. A From that isn't signed makes the signature meaningless for the sender's identity.
    if (!s.signedHeaders.includes('from')) {
      findings.push({ id: 'dkim-from-unsigned', category: 'auth', severity: 'medium', points: 10, title: `${s.domain}'s signature doesn't cover the From address`, detail: 'DKIM requires the From header to be signed. Without it, the signature says nothing about who sent the email.', target });
    }
  }

  // 4. An extra, unsigned copy of a header you see: added after signing. Mail apps show the top one.
  const valid = sigs.filter((s) => s.bodyHash === 'match' && s.signedHeaders.includes('from'));
  for (const s of valid) {
    for (const name of SHOWN) {
      const present = msg.headers.filter((h) => h.key === name).length;
      const signedCount = s.signedHeaders.filter((h) => h === name).length;
      if (signedCount > 0 && present > signedCount) {
        findings.push({ id: `dkim-added-${name}`, category: 'auth', severity: 'high', points: 22, title: `A second ${name === 'from' ? 'From' : name.replace(/^./, (c) => c.toUpperCase())} header was added after signing`, detail: `The email has ${present} ${name} headers but ${s.domain} signed only ${signedCount}. Your mail app may show the unsigned one, so the signature passes while you see something the signer never wrote.`, target: { kind: 'header', key: name } });
      }
    }
  }
  const replyTo = msg.headers.some((h) => h.key === 'reply-to');
  const fromSigner = valid.find((s) => sameOrg(s.domain, fromDomain));
  if (replyTo && fromSigner && !fromSigner.signedHeaders.includes('reply-to')) {
    findings.push({ id: 'dkim-reply-to-unsigned', category: 'auth', severity: 'low', points: 4, title: 'Reply-To was not signed by the sender', detail: `${fromSigner.domain} signed the email but not its Reply-To, so the reply address could have been added by someone else.`, target: { kind: 'header', key: 'reply-to' } });
  }

  // 5. Signature age and expiry. A replayed email keeps its old signature.
  const when = arrivedAt ?? Date.now();
  const oldest = valid.filter((s) => s.signedAt !== null).sort((a, b) => a.signedAt! - b.signedAt!)[0];
  if (oldest && when - oldest.signedAt! > 7 * 86_400_000) {
    findings.push({ id: 'dkim-old-signature', category: 'auth', severity: 'medium', points: 10, title: `Signed ${days(when - oldest.signedAt!)} days before it reached you`, detail: `${oldest.domain} signed this email on ${new Date(oldest.signedAt!).toISOString().slice(0, 10)}. A genuine email re-sent unchanged to new people ("DKIM replay") keeps its old, valid signature.`, target });
  }
  const expired = valid.find((s) => s.expiresAt !== null && s.expiresAt < when);
  if (expired) {
    findings.push({ id: 'dkim-expired', category: 'auth', severity: 'low', points: 4, title: `${expired.domain}'s signature had expired when it arrived`, detail: 'The signer set an expiry date (x=) so the email could not be reused later. It arrived after that date.', target });
  }
  if (sigs.length && sigs.every((s) => s.algorithm === 'rsa-sha1')) {
    findings.push({ id: 'dkim-sha1', category: 'auth', severity: 'low', points: 3, title: 'Signed with an outdated algorithm (SHA-1)', target });
  }
  return findings;
}
