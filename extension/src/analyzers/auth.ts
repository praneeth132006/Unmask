import type { AuthResult, AuthSummary, DeliveryHop, Finding, ParsedEmail } from '../core/types';
import { getHeaders } from '../core/parse';
import { registrableDomain, sameOrg } from '../lib/domain';
import { deliveryPath, sameProvider } from './received';

const RESULTS: AuthResult[] = ['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror', 'policy'];

function normalise(result: string | undefined): AuthResult {
  const r = (result ?? '').toLowerCase();
  if (r === 'hardfail') return 'fail';
  return (RESULTS as string[]).includes(r) ? (r as AuthResult) : 'unknown';
}

function stripComments(value: string): string {
  // Comments are parenthesised and may contain ';', remove them before splitting.
  let out = '';
  let depth = 0;
  for (const ch of value) {
    if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    else if (depth === 0) out += ch;
  }
  return out;
}

interface MethodResult {
  method: string;
  result: AuthResult;
  props: Record<string, string>;
}

/** Parses one Authentication-Results header (RFC 8601). */
export function parseAuthResults(value: string): { server: string | null; results: MethodResult[] } {
  const segments = stripComments(value)
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
  let server: string | null = null;
  if (segments[0] && !/^[a-z-]+=/i.test(segments[0])) {
    server = segments.shift()!.split(/\s+/)[0] ?? null;
  }
  const results: MethodResult[] = [];
  for (const seg of segments) {
    const tokens = seg.split(/\s+/);
    const [method, result] = (tokens.shift() ?? '').split('=');
    if (!method || !result) continue;
    const props: Record<string, string> = {};
    for (const t of tokens) {
      const eq = t.indexOf('=');
      if (eq > 0) props[t.slice(0, eq).toLowerCase()] = t.slice(eq + 1).replace(/^"|"$/g, '');
    }
    results.push({ method: method.toLowerCase(), result: normalise(result), props });
  }
  return { server, results };
}

function domainOf(value: string | undefined): string | null {
  if (!value) return null;
  const at = value.lastIndexOf('@');
  return (at >= 0 ? value.slice(at + 1) : value).toLowerCase() || null;
}

const BIG_PROVIDER = /^\s*(mx\.google\.com|mx\.microsoft\.com|[\w.-]*\.outlook\.com|[\w.-]*\.yahoo\.com|[\w.-]*icloud\.com)\b/i;

/** authserv-id (the server that wrote it) of an Authentication-Results value, lowercase. */
function authServer(value: string): string | null {
  return parseAuthResults(value).server?.toLowerCase() ?? null;
}

/** Organisation domains of the servers your own provider used to receive this email. */
function providerOrgs(hops: DeliveryHop[]): string[] {
  return [...new Set(hops.filter((h) => h.trusted && h.by && /[a-z]/i.test(h.by) && !h.by.includes(':')).map((h) => registrableDomain(h.by!)))];
}

/** Every organisation that handled the email at all, trusted or not. */
function handlerOrgs(hops: DeliveryHop[]): string[] {
  return [...new Set(hops.flatMap((h) => [h.by, h.helo, h.rdns]).filter((x): x is string => !!x && /[a-z]/i.test(x) && !x.includes(':')).map(registrableDomain))];
}

/**
 * Authentication-Results that name a big mailbox provider which never
 * handled the email: the sender wrote them to look checked.
 */
export function forgedAuthResults(email: ParsedEmail, hops: DeliveryHop[]): string[] {
  if (!hops.length) return [];
  const handled = handlerOrgs(hops);
  return getHeaders(email, 'authentication-results').filter((h) => {
    const server = authServer(h);
    if (!server || !BIG_PROVIDER.test(server)) return false;
    const org = registrableDomain(server);
    return !handled.some((d) => sameProvider(d, org));
  });
}

export function summariseAuth(email: ParsedEmail, hops: DeliveryHop[] = deliveryPath(getHeaders(email, 'received'))): AuthSummary {
  const forged = new Set(forgedAuthResults(email, hops));
  const headers = getHeaders(email, 'authentication-results').filter((h) => !forged.has(h));
  // Your provider prepends its own header, so the first one written by it is the one to trust.
  // Otherwise prefer the big providers' headers in case a relay added one above.
  const mine = providerOrgs(hops);
  const preferred =
    headers.find((h) => {
      const server = authServer(h);
      return !!server && mine.some((d) => sameProvider(registrableDomain(server), d));
    }) ??
    headers.find((h) => BIG_PROVIDER.test(h)) ??
    headers[0] ??
    null;

  const summary: AuthSummary = {
    server: null,
    spf: 'none',
    spfDomain: null,
    dkim: 'none',
    dkimDomains: [],
    dmarc: 'none',
    dmarcDomain: null,
    raw: preferred,
  };
  if (!preferred) {
    summary.spf = summary.dkim = summary.dmarc = 'unknown';
    return summary;
  }

  const { server, results } = parseAuthResults(preferred);
  summary.server = server;
  const dkims = results.filter((r) => r.method === 'dkim');
  for (const r of results) {
    if (r.method === 'spf') {
      summary.spf = r.result;
      summary.spfDomain = domainOf(r.props['smtp.mailfrom'] ?? r.props['smtp.helo']);
    } else if (r.method === 'dmarc') {
      summary.dmarc = r.result;
      summary.dmarcDomain = domainOf(r.props['header.from']);
    }
  }
  if (dkims.length) {
    const passing = dkims.filter((d) => d.result === 'pass');
    summary.dkim = passing.length ? 'pass' : dkims.some((d) => d.result === 'fail') ? 'fail' : (dkims[0]?.result ?? 'none');
    summary.dkimDomains = [
      ...new Set(passing.map((d) => domainOf(d.props['header.d'] ?? d.props['header.i'])).filter((d): d is string => !!d)),
    ];
  }
  return summary;
}

export function analyzeAuth(email: ParsedEmail, hops: DeliveryHop[] = deliveryPath(getHeaders(email, 'received'))): { auth: AuthSummary; findings: Finding[] } {
  const auth = summariseAuth(email, hops);
  const findings: Finding[] = [];
  const fromDomain = email.from?.domain ?? '';

  const forged = forgedAuthResults(email, hops).filter((h) => parseAuthResults(h).results.some((r) => r.result === 'pass'));
  if (forged.length) {
    const server = authServer(forged[0]!);
    findings.push({
      id: 'auth-results-forged',
      category: 'auth',
      severity: 'high',
      points: 25,
      title: `Fake "passed" check: claims ${server} verified it, but ${server} never handled this email`,
      detail: 'The email carries an authentication stamp from a mail provider that does not appear anywhere in its delivery path. The sender wrote it to make the email look checked. Unmask ignores it.',
      target: { kind: 'header', key: 'authentication-results' },
    });
  }

  if (!auth.raw) {
    findings.push({
      id: 'auth-missing',
      category: 'auth',
      severity: 'info',
      points: 0,
      title: 'No authentication results in the headers',
      detail: 'This usually means the email was forwarded or pasted without its original headers, so SPF/DKIM/DMARC could not be checked.',
    });
    return { auth, findings };
  }

  if (auth.dmarc === 'fail') {
    findings.push({
      id: 'dmarc-fail',
      category: 'auth',
      severity: 'high',
      points: 30,
      title: 'Failed DMARC: the sender domain did not authorise this email',
      detail: `The domain in the From address (${auth.dmarcDomain ?? fromDomain}) could not be verified. Spoofed emails fail this check.`,
    });
  } else if (auth.dmarc === 'pass') {
    findings.push({
      id: 'dmarc-pass',
      category: 'auth',
      severity: 'good',
      points: -10,
      title: `DMARC passed for ${auth.dmarcDomain ?? fromDomain}`,
      detail: 'The email really came from the domain shown in the From address. Note: scammers can pass DMARC on domains they own, so also check the domain itself.',
    });
  }

  if (auth.spf === 'fail') {
    findings.push({ id: 'spf-fail', category: 'auth', severity: 'medium', points: 15, title: 'SPF failed: sent from a server the domain does not allow', detail: auth.spfDomain ? `Envelope sender domain: ${auth.spfDomain}` : undefined });
  } else if (auth.spf === 'softfail') {
    findings.push({ id: 'spf-softfail', category: 'auth', severity: 'low', points: 8, title: 'SPF soft-failed: the sending server is not clearly authorised', detail: auth.spfDomain ? `Envelope sender domain: ${auth.spfDomain}` : undefined });
  } else if (auth.spf === 'none' || auth.spf === 'neutral') {
    findings.push({ id: 'spf-none', category: 'auth', severity: 'low', points: 4, title: 'No SPF protection for the sending domain' });
  }

  if (auth.dkim === 'fail') {
    findings.push({ id: 'dkim-fail', category: 'auth', severity: 'medium', points: 12, title: 'DKIM signature failed: the email may have been altered or forged' });
  } else if (auth.dkim === 'none') {
    findings.push({ id: 'dkim-none', category: 'auth', severity: 'low', points: 4, title: 'Email is not DKIM-signed' });
  } else if (auth.dkim === 'pass' && fromDomain && auth.dmarc !== 'pass' && !auth.dkimDomains.some((d) => sameOrg(d, fromDomain))) {
    findings.push({
      id: 'dkim-unaligned',
      category: 'auth',
      severity: 'low',
      points: 5,
      title: 'Signed by a different domain than the From address',
      detail: `Signed by ${auth.dkimDomains.join(', ')}, but From is ${registrableDomain(fromDomain)}. Normal for some mailing services, suspicious otherwise.`,
    });
  }

  const target = { kind: 'header', key: 'authentication-results' } as const;
  return { auth, findings: findings.map((f) => ({ target, ...f })) };
}
