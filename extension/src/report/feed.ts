/**
 * The Scam watch feed as STIX 2.1: one identity, one indicator per malicious
 * domain and one report per case. Published on the website as a file and by
 * the backend over TAXII 2.1, so MISP, OpenCTI, Sentinel or Splunk can pull it.
 * Ids are content-based (UUIDv5), so re-publishing never duplicates objects.
 */
import { uuid5 } from './stix';

export interface FeedCase {
  id: string;
  date: string;
  title: string;
  brand: string;
  lure: string;
  tells: string[];
  indicators: string[];
  report: string;
}

const SITE = 'https://praneeth132006.github.io/Unmask/';
const MONTHS = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

/** "Oct 2026" → 2026-10-01T00:00:00.000Z */
export function caseTime(date: string): string {
  const [m, y] = date.toLowerCase().split(/\s+/);
  const month = MONTHS.indexOf((m ?? '').slice(0, 3));
  return new Date(Date.UTC(Number(y) || 2026, Math.max(0, month), 1)).toISOString();
}

export async function buildFeedBundle(cases: FeedCase[]): Promise<{ type: 'bundle'; id: string; objects: Record<string, unknown>[] }> {
  const identity = { type: 'identity', spec_version: '2.1', id: `identity--${await uuid5('unmask-scam-watch')}`, created: '2026-01-01T00:00:00.000Z', modified: '2026-01-01T00:00:00.000Z', name: 'Unmask Scam watch', identity_class: 'system' };
  const objects: Record<string, unknown>[] = [identity];
  const marking = 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9'; // TLP:CLEAR
  for (const c of cases) {
    const t = caseTime(c.date);
    const refs: string[] = [];
    for (const domain of c.indicators) {
      const id = `indicator--${await uuid5(`scam-watch:${c.id}:${domain}`)}`;
      refs.push(id);
      objects.push({
        type: 'indicator', spec_version: '2.1', id, created: t, modified: t, valid_from: t,
        created_by_ref: identity.id, object_marking_refs: [marking],
        name: `${domain} (${c.brand} phishing)`, indicator_types: ['malicious-activity'],
        pattern: `[domain-name:value = '${domain.replace(/'/g, "\\'")}']`, pattern_type: 'stix',
        description: `${c.title}. ${c.lure}`,
      });
    }
    objects.push({
      type: 'report', spec_version: '2.1', id: `report--${await uuid5(`scam-watch:${c.id}`)}`, created: t, modified: t, published: t,
      created_by_ref: identity.id, object_marking_refs: [marking], name: c.title, report_types: ['threat-report'],
      description: [c.lure, ...c.tells].join(' '), object_refs: refs.length ? refs : [identity.id],
      external_references: [{ source_name: 'unmask', url: new URL(c.report, SITE).href }],
    });
  }
  return { type: 'bundle', id: `bundle--${await uuid5(`scam-watch:${cases.map((c) => c.id).join(',')}`)}`, objects };
}
