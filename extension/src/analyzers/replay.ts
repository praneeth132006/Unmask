/**
 * DKIM replay: an attacker gets a genuine signed email (often a notification
 * they triggered on their own account, with their lure in a field they
 * control), then re-sends it unchanged to thousands of people. The signature
 * still verifies and DMARC can pass, so the usual checks rate it *safer*.
 * No single sign proves it; analysts look for several together.
 */
import type { AuthSummary, Finding, ParsedEmail } from '../core/types';
import type { DkimSignature } from '../lib/dkim';
import { sameOrg } from '../lib/domain';

export function replayFindings(email: ParsedEmail, auth: AuthSummary, sigs: DkimSignature[], found: Finding[]): Finding[] {
  const from = email.from?.domain ?? '';
  if (!from) return [];
  const signer = sigs.find((s) => sameOrg(s.domain, from) && s.bodyHash === 'match') ?? null;
  const providerSigned = auth.dkimDomains.find((d) => sameOrg(d, from));
  if (!signer && !providerSigned) return [];

  const has = (id: string) => found.some((f) => f.id === id);
  const signs: string[] = [];
  if (has('dkim-old-signature')) signs.push('it was signed long before it reached you');
  else if (has('date-old')) signs.push('it was written days before it arrived');
  if (has('replay-addressee')) signs.push('it was addressed to someone else');
  if (has('arc-passed-earlier')) signs.push('it passed checks at an earlier server and failed at yours');
  if (/^SRS[01][=+]/i.test(email.returnPath ?? '')) signs.push('it was passed on by a forwarding service');
  if ((auth.spf === 'fail' || auth.spf === 'softfail') && auth.spfDomain && !sameOrg(auth.spfDomain, from)) signs.push(`the server that delivered it isn't one ${from} uses`);
  if (signs.length < 2) return [];

  const domain = signer?.domain ?? providerSigned!;
  return [
    {
      id: 'dkim-replay',
      category: 'auth',
      severity: 'high',
      points: 20,
      title: `Looks like a genuine ${domain} email re-sent by someone else`,
      detail: `The signature is real, but ${signs.slice(0, -1).join(', ')} and ${signs[signs.length - 1]}. That combination is a "DKIM replay": a real email re-sent unchanged so it passes authentication. Judge it by its links and what it asks for, not by the signature.`,
      plain: 'It looks like an old genuine email that someone re-sent to you.',
      target: { kind: 'header', key: 'dkim-signature' },
    },
  ];
}
