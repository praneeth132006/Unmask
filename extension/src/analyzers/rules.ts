/**
 * Detection rules written as data (extension/rules/*.yml, compiled into
 * src/rules/rules.json by `pnpm rules`), so a new scam pattern can be added
 * without writing TypeScript. See extension/rules/README.md.
 */
import type { AuthSummary, Finding, ParsedEmail, Severity } from '../core/types';
import RULES from '../rules/rules.json';
import { registrableDomain, sameOrg } from '../lib/domain';

export interface Rule {
  id: string;
  title: string;
  plain: string;
  severity: Extract<Severity, 'low' | 'medium' | 'high'>;
  points: number;
  category: Finding['category'];
  any: string[];
  also: string[];
  subject: string[];
  needsLink: boolean;
  notFrom: string[];
  examples: { phish: string; legit: string };
}

export const RULE_LIST = RULES as Rule[];

const compiled = new Map<string, RegExp | string>();
function matcher(phrase: string): RegExp | string {
  let m = compiled.get(phrase);
  if (m === undefined) {
    m = phrase.length > 2 && phrase.startsWith('/') && phrase.endsWith('/') ? new RegExp(phrase.slice(1, -1), 'i') : phrase.toLowerCase();
    compiled.set(phrase, m);
  }
  return m;
}

/** The text a phrase matched, or null. */
function find(phrase: string, text: string, lower: string): string | null {
  const m = matcher(phrase);
  if (typeof m === 'string') {
    const at = lower.indexOf(m);
    return at < 0 ? null : text.slice(at, at + m.length);
  }
  return text.match(m)?.[0] ?? null;
}

export interface RuleContext {
  email: ParsedEmail;
  visibleText: string;
  auth: AuthSummary;
  /** The email has a link, a QR code or a real attachment. */
  hasLinkLike: boolean;
}

export function ruleFindings(ctx: RuleContext, rules: Rule[] = RULE_LIST): Finding[] {
  const text = `${ctx.email.subject}\n${ctx.visibleText}`.replace(/\s+/g, ' ');
  const lower = text.toLowerCase();
  const subject = ctx.email.subject;
  const subjectLower = subject.toLowerCase();
  const fromOrg = ctx.email.from ? registrableDomain(ctx.email.from.domain) : '';
  const out: Finding[] = [];
  for (const r of rules) {
    if (r.needsLink && !ctx.hasLinkLike) continue;
    if (ctx.auth.dmarc === 'pass' && fromOrg && r.notFrom.some((d) => sameOrg(fromOrg, d))) continue;
    const hit = r.any.map((p) => find(p, text, lower)).find((m) => m);
    if (!hit) continue;
    const also = r.also.length ? r.also.map((p) => find(p, text, lower)).find((m) => m) : '';
    if (also === undefined || also === null) continue;
    if (r.subject.length && !r.subject.some((p) => find(p, subject, subjectLower))) continue;
    out.push({
      id: `rule-${r.id}`,
      category: r.category,
      severity: r.severity,
      points: r.points,
      title: r.title,
      plain: r.plain,
      detail: `Matched “${hit.trim()}”${also ? ` and “${also.trim()}”` : ''}. This pattern comes from Unmask’s rule ${r.id}.yml.`,
      target: { kind: 'text', phrases: [hit.trim(), ...(also ? [also.trim()] : [])].filter((p) => p.length >= 3) },
    });
  }
  return out;
}
