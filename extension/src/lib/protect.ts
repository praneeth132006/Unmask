/**
 * Decisions behind the in-Gmail protection: when a click on a link or on
 * Reply deserves a warning, and the quick sender-only check that drives the
 * inbox badges. Pure functions over a Report, so they are easy to test.
 */
import type { Finding, LinkInfo, ParsedEmail, Report, Verdict } from '../core/types';
import { SEVERITY_RANK, scoreFindings, sortFindings } from '../core/score';
import { analyzeSender } from '../analyzers/sender';
import { historyFindings, type SenderHistory } from '../analyzers/history';
import { linkFlagTitle, unwrapUrl } from '../analyzers/links';
import { registrableDomain, safeUrl, sameOrg } from './domain';

function normalise(url: string): string {
  const u = safeUrl(url.trim());
  return u ? u.href.replace(/\/$/, '') : url.trim();
}

/** The analyzed link behind a clicked <a>, matching Gmail's rewritten hrefs too. */
export function findLink(report: Report, href: string, saferedirect?: string | null): LinkInfo | null {
  const candidates = [href, saferedirect ? (safeUrl(saferedirect)?.searchParams.get('q') ?? '') : '', unwrapUrl(href).url].filter(Boolean).map(normalise);
  return (
    report.links.find((l) => (l.source === 'html' || l.source === 'text') && (candidates.includes(normalise(l.href)) || candidates.includes(normalise(l.resolved)))) ?? null
  );
}

export interface LinkWarning {
  host: string;
  url: string;
  reasons: string[];
}

/**
 * Warn when the link itself is flagged high/critical, when it has any real
 * flag in a suspicious email, or when it leaves the sender's domain in a
 * high-risk email.
 */
export function linkWarning(report: Report, href: string, saferedirect?: string | null): LinkWarning | null {
  const link = findLink(report, href, saferedirect);
  const url = link?.resolved ?? unwrapUrl(saferedirect ? (safeUrl(saferedirect)?.searchParams.get('q') ?? href) : href).url;
  const u = safeUrl(url);
  if (!u || !/^https?:$/.test(u.protocol)) return null;
  const host = u.hostname;
  const worst = Math.max(-1, ...(link?.flags ?? []).map((f) => SEVERITY_RANK[f.severity]));
  const senderDomain = report.email.from?.domain ?? '';
  const offSender = !sameOrg(host, senderDomain);

  const strongLink = worst >= SEVERITY_RANK.high;
  const flaggedInSuspicious = report.verdict !== 'clear' && worst >= SEVERITY_RANK.medium;
  const riskyEmail = report.verdict === 'high' && offSender;
  if (!strongLink && !flaggedInSuspicious && !riskyEmail) return null;

  // Short labels (".top", "bit.ly") read better with the flag's title in front.
  const reasons = (link?.flags ?? [])
    .filter((f) => SEVERITY_RANK[f.severity] >= SEVERITY_RANK.low)
    .slice(0, 3)
    .map((f) => (f.label.length < 16 && linkFlagTitle(f.id) ? `${linkFlagTitle(f.id)} (${f.label})` : f.label));
  if (riskyEmail) reasons.push(`Unmask rated this email high risk (${report.score}/100)`);
  if (offSender && senderDomain) reasons.push(`It does not go to the sender’s domain (${registrableDomain(senderDomain)})`);
  return { host, url, reasons: [...new Set(reasons)] };
}

export interface ReplyWarning {
  replyTo: string;
  from: string;
}

/** Replying would send the answer to an address on another domain. */
export function replyWarning(report: Report): ReplyWarning | null {
  const from = report.email.from;
  if (!from) return null;
  const other = report.email.replyTo.find((r) => r.domain && !sameOrg(r.domain, from.domain));
  return other ? { replyTo: other.address, from: from.address } : null;
}

/**
 * A sender-only verdict for an inbox row, before the email is opened: display
 * name tricks, lookalike domains, brand claims and sender history.
 */
export function quickVerdict(name: string, address: string, history?: SenderHistory): { verdict: Verdict; reasons: string[] } {
  const domain = address.split('@')[1]?.toLowerCase() ?? '';
  const email: ParsedEmail = {
    headers: [],
    from: { name, address, domain },
    sender: null,
    replyTo: [],
    returnPath: null,
    to: [],
    subject: '',
    date: null,
    messageId: `inbox-row:${address}`,
    html: null,
    text: null,
    attachments: [],
  };
  // Header-only signals (reply-to, return-path) aren't known from the inbox row.
  const findings: Finding[] = sortFindings([...analyzeSender(email).filter((f) => f.id !== 'return-path-mismatch'), ...(history ? historyFindings(email, history) : [])]);
  const { verdict } = scoreFindings(findings);
  return { verdict, reasons: findings.filter((f) => f.points > 0).slice(0, 3).map((f) => f.title) };
}

export interface StoredVerdict {
  verdict: Verdict;
  score: number;
  reasons: string[];
  at: number;
}

export const MAX_STORED_VERDICTS = 1000;

/** Keeps the newest verdicts, so the cache can't grow without limit. */
export function pruneVerdicts(map: Record<string, StoredVerdict>, max = MAX_STORED_VERDICTS): Record<string, StoredVerdict> {
  const keys = Object.keys(map);
  if (keys.length <= max) return map;
  const keep = keys.sort((a, b) => map[b]!.at - map[a]!.at).slice(0, max);
  return Object.fromEntries(keep.map((k) => [k, map[k]!]));
}
