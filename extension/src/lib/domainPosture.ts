/**
 * "Is your domain spoofable?": reads a domain's public mail records (SPF,
 * DMARC, MX, DKIM at common selectors, MTA-STS, BIMI) and says, in plain
 * words, whether someone could send email that looks like it came from it.
 * The evaluation is pure; `lookupPosture` does the DNS-over-HTTPS queries.
 */
export type Grade = 'protected' | 'partial' | 'spoofable';

export interface Check {
  id: 'spf' | 'dmarc' | 'mx' | 'dkim' | 'mta-sts' | 'bimi';
  label: string;
  status: 'good' | 'warn' | 'bad' | 'info';
  found: string | null;
  says: string;
  fix?: string;
}

export interface Posture {
  domain: string;
  grade: Grade;
  headline: string;
  checks: Check[];
}

export interface Records {
  txt: string[];
  dmarc: string[];
  mx: string[];
  dkimSelectors: string[];
  mtaSts: string[];
  bimi: string[];
}

export const DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'default', 'k1', 'k2', 's1', 's2', 'mail', 'dkim', 'smtp', 'mxvault', 'zoho', 'protonmail'];

const tags = (rec: string) => Object.fromEntries(rec.split(';').map((p) => p.trim().split('=').map((x) => x.trim())).filter((kv) => kv.length === 2 && kv[0]).map(([k, v]) => [k!.toLowerCase(), v!]));

export function evaluate(domain: string, r: Records): Posture {
  const checks: Check[] = [];
  const spfs = r.txt.filter((t) => /^v=spf1(\s|$)/i.test(t));
  const spf = spfs[0] ?? null;
  const sendsMail = r.mx.length > 0;

  if (spfs.length > 1) checks.push({ id: 'spf', label: 'SPF', status: 'bad', found: spfs.join(' | '), says: 'There are two SPF records. Receivers treat that as an error, so SPF protects nothing.', fix: 'Merge them into one record starting v=spf1.' });
  else if (!spf) checks.push({ id: 'spf', label: 'SPF', status: 'bad', found: null, says: 'No SPF record: nothing says which servers may send email for this domain.', fix: sendsMail ? 'Add a TXT record listing your mail provider, e.g. v=spf1 include:_spf.google.com -all' : 'This domain sends no mail. Add v=spf1 -all to say so.' });
  else {
    const all = spf.match(/\s([-~?+])?all\b/i);
    const q = all ? (all[1] ?? '+') : null;
    const lookups = (spf.match(/\b(include:|a\b|a:|mx\b|mx:|exists:|redirect=|ptr)/gi) ?? []).length;
    if (q === '-') checks.push({ id: 'spf', label: 'SPF', status: 'good', found: spf, says: 'SPF lists your senders and tells receivers to reject anyone else (-all).' });
    else if (q === '~') checks.push({ id: 'spf', label: 'SPF', status: 'warn', found: spf, says: 'SPF ends in ~all (soft fail): other senders are only marked, not rejected. Fine when DMARC enforces.', fix: 'Once DMARC is at quarantine or reject, ~all is fine; -all is stricter.' });
    else checks.push({ id: 'spf', label: 'SPF', status: 'bad', found: spf, says: q === '+' ? 'SPF ends in +all: it allows every server on the internet to send as you.' : 'SPF has no "all" rule (or ?all), so it allows anyone.', fix: 'End the record with -all (or ~all).' });
    if (lookups > 10) checks.push({ id: 'spf', label: 'SPF lookups', status: 'warn', found: `${lookups} lookups`, says: 'SPF may need more than 10 DNS lookups, the limit; receivers can then ignore it.', fix: 'Remove unused includes or flatten the record.' });
  }

  const dmarc = r.dmarc.find((t) => /^v=DMARC1/i.test(t)) ?? null;
  let policy: string | null = null;
  if (!dmarc) checks.push({ id: 'dmarc', label: 'DMARC', status: 'bad', found: null, says: 'No DMARC record: receivers have no instruction to block email that fakes this domain.', fix: `Add a TXT record at _dmarc.${domain}: v=DMARC1; p=none; rua=mailto:dmarc@${domain} then move to p=quarantine and p=reject.` });
  else {
    const t = tags(dmarc);
    policy = (t.p ?? '').toLowerCase();
    const pct = t.pct ? Number(t.pct) : 100;
    if (policy === 'reject' && pct >= 100) checks.push({ id: 'dmarc', label: 'DMARC', status: 'good', found: dmarc, says: 'DMARC is at reject: email faking this domain is blocked by Gmail, Outlook and most others.' });
    else if (policy === 'quarantine') checks.push({ id: 'dmarc', label: 'DMARC', status: 'warn', found: dmarc, says: `DMARC is at quarantine${pct < 100 ? ` for ${pct}% of mail` : ''}: fakes go to spam, not blocked.`, fix: 'When your reports show only real senders, move to p=reject.' });
    else if (policy === 'reject') checks.push({ id: 'dmarc', label: 'DMARC', status: 'warn', found: dmarc, says: `DMARC is at reject, but only for ${pct}% of mail.`, fix: 'Remove pct= (or set pct=100).' });
    else checks.push({ id: 'dmarc', label: 'DMARC', status: 'bad', found: dmarc, says: 'DMARC is at p=none: it only reports fakes, it doesn’t stop them. Anyone can still send as this domain.', fix: 'Read the reports, fix your real senders, then move to p=quarantine and p=reject.' });
    if (!t.rua) checks.push({ id: 'dmarc', label: 'DMARC reports', status: 'info', found: null, says: 'No report address (rua=): you won’t see who is sending as you.', fix: `Add rua=mailto:dmarc@${domain} to the DMARC record.` });
  }

  checks.push(sendsMail
    ? { id: 'mx', label: 'Mail servers (MX)', status: 'info', found: r.mx.join(', '), says: 'This domain receives email.' }
    : { id: 'mx', label: 'Mail servers (MX)', status: 'info', found: null, says: 'No mail servers: this domain doesn’t receive email. Domains that send none should still publish v=spf1 -all and DMARC p=reject.' });

  checks.push(r.dkimSelectors.length
    ? { id: 'dkim', label: 'DKIM', status: 'good', found: r.dkimSelectors.map((s) => `${s}._domainkey`).join(', '), says: 'Signing keys found, so real email from this domain can be signed.' }
    : { id: 'dkim', label: 'DKIM', status: sendsMail ? 'warn' : 'info', found: null, says: `No DKIM key at the ${DKIM_SELECTORS.length} common names checked. Your provider may use another name; check its settings.`, fix: sendsMail ? 'Turn on DKIM signing in your mail provider’s admin settings.' : undefined });

  if (r.mtaSts.some((t) => /^v=STSv1/i.test(t))) checks.push({ id: 'mta-sts', label: 'MTA-STS', status: 'good', found: r.mtaSts[0]!, says: 'Mail to this domain must arrive encrypted.' });
  else if (sendsMail) checks.push({ id: 'mta-sts', label: 'MTA-STS', status: 'info', found: null, says: 'No MTA-STS: incoming mail can be downgraded to unencrypted. Nice to have.' });
  if (r.bimi.some((t) => /^v=BIMI1/i.test(t))) checks.push({ id: 'bimi', label: 'BIMI', status: 'good', found: r.bimi[0]!, says: 'A verified logo can appear next to your emails.' });

  const enforce = policy === 'reject' || policy === 'quarantine';
  const spfOk = checks.some((c) => c.id === 'spf' && c.status !== 'bad') && spfs.length === 1;
  const grade: Grade = policy === 'reject' && spfOk ? 'protected' : enforce ? 'partial' : 'spoofable';
  const headline = grade === 'protected'
    ? `${domain} is well protected: email faking it is rejected.`
    : grade === 'partial'
      ? `${domain} is partly protected: fakes are sent to spam, not blocked.`
      : `Anyone can send email that looks like it comes from ${domain}.`;
  return { domain, grade, headline, checks };
}

/** A domain as typed by a person: an address, a URL or a bare name. */
export function cleanDomain(input: string): string | null {
  let d = input.trim().toLowerCase();
  if (d.includes('@')) d = d.split('@').pop()!;
  d = d.replace(/^[a-z]+:\/\//, '').split(/[/?#:]/)[0]!.replace(/\.$/, '');
  return /^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(d) ? d : null;
}

type Fetch = (url: string) => Promise<{ ok: boolean; json(): Promise<unknown> }>;

async function txt(fetcher: Fetch, name: string, type = 'TXT'): Promise<string[]> {
  const r = await fetcher(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`);
  if (!r.ok) throw new Error('The DNS lookup failed. Try again.');
  const j = (await r.json()) as { Answer?: { type: number; data: string }[] };
  return (j.Answer ?? []).filter((a) => (type === 'MX' ? a.type === 15 : a.type === 16)).map((a) => (type === 'MX' ? a.data.split(' ').pop()!.replace(/\.$/, '') : a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, '')));
}

/** Looks the records up with Google Public DNS (only the domain name is sent) and evaluates them. */
export async function lookupPosture(domain: string, fetcher: Fetch = (u) => fetch(u)): Promise<Posture> {
  const [root, dmarc, mx, mtaSts, bimi, ...dkim] = await Promise.all([
    txt(fetcher, domain), txt(fetcher, `_dmarc.${domain}`), txt(fetcher, domain, 'MX'), txt(fetcher, `_mta-sts.${domain}`), txt(fetcher, `default._bimi.${domain}`),
    ...DKIM_SELECTORS.map((s) => txt(fetcher, `${s}._domainkey.${domain}`).catch(() => [])),
  ]);
  const dkimSelectors = DKIM_SELECTORS.filter((_, i) => dkim[i]!.some((t) => /p=/.test(t)));
  return evaluate(domain, { txt: root, dmarc, mx, dkimSelectors, mtaSts, bimi });
}
