/**
 * STIX 2.1 export: the report as a bundle that threat-intelligence tools
 * (MISP, OpenCTI, Sentinel, Splunk ES …) can ingest. Indicators are exact
 * values, not defanged. A clear verdict exports the report object only, so
 * nothing harmless is ever pushed onto a block list.
 */
import { ATTACK_NAMES, collectIocs, type CaseDoc, type Ioc, type Tlp } from './model';
import type { Report } from '../core/types';
import { hypotheses } from '../core/assessment';

/** The namespace STIX 2.1 defines for ids built from content. */
const NS = '00abedb4-aa42-466c-9c01-fed23315a9b7';

/** TLP marking definitions from STIX 2.1. AMBER+STRICT uses AMBER's id and is also labelled. */
const TLP_MARKING: Record<Tlp, string> = {
  CLEAR: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
  GREEN: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
  AMBER: 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
  'AMBER+STRICT': 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
  RED: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
};

/** A version 5 UUID: the same input always gives the same id, so bundles from repeated runs merge cleanly. */
export async function uuid5(name: string, namespace = NS): Promise<string> {
  const ns = namespace.replace(/-/g, '').match(/../g)!.map((h) => parseInt(h, 16));
  const data = Uint8Array.from([...ns, ...new TextEncoder().encode(name)]);
  const h = new Uint8Array(await crypto.subtle.digest('SHA-1', data)).slice(0, 16);
  h[6] = (h[6]! & 0x0f) | 0x50;
  h[8] = (h[8]! & 0x3f) | 0x80;
  const hex = Array.from(h, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const q = (s: string) => `'${s.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;

/** The STIX pattern for an indicator, or null for types STIX has no object for. */
export function stixPattern(i: Ioc): string | null {
  switch (i.type) {
    case 'url':
    case 'file-url':
      return `[url:value = ${q(i.value)}]`;
    case 'domain':
    case 'dkim-domain':
      return `[domain-name:value = ${q(i.value)}]`;
    case 'origin-ip':
    case 'file-ip':
      return /:/.test(i.value) ? `[ipv6-addr:value = ${q(i.value)}]` : `[ipv4-addr:value = ${q(i.value)}]`;
    case 'sender':
    case 'reply-to':
    case 'return-path':
    case 'file-email':
      return `[email-addr:value = ${q(i.value)}]`;
    case 'sha256':
      return `[file:hashes.'SHA-256' = ${q(i.value)}]`;
    case 'sha1':
      return `[file:hashes.'SHA-1' = ${q(i.value)}]`;
    case 'md5':
      return `[file:hashes.MD5 = ${q(i.value)}]`;
    case 'filename':
      return `[file:name = ${q(i.value)}]`;
    default:
      return null;
  }
}

const NAME: Record<string, string> = { sender: 'Sender address', 'reply-to': 'Reply-To address', 'return-path': 'Return-Path address', 'origin-ip': 'Origin IP address', 'dkim-domain': 'DKIM signing domain', url: 'Phishing URL', domain: 'Domain', 'file-ip': 'IP address in attachment', 'file-email': 'Email address in attachment', 'file-url': 'URL in attachment', sha256: 'File SHA-256', sha1: 'File SHA-1', md5: 'File MD5', filename: 'Attachment file name' };

export async function buildStixBundle(report: Report, doc: CaseDoc, now = new Date()): Promise<Record<string, unknown>> {
  const ts = now.toISOString().replace(/(\.\d{3})?Z$/, '.000Z');
  const identityId = `identity--${await uuid5('Unmask')}`;
  const marking = TLP_MARKING[doc.tlp];
  const confidence = report.verdict === 'high' ? 85 : report.verdict === 'suspicious' ? 55 : 15;
  const common = { spec_version: '2.1', created: ts, modified: ts, created_by_ref: identityId, object_marking_refs: [marking] };
  const objects: Record<string, unknown>[] = [
    { type: 'identity', spec_version: '2.1', id: identityId, created: ts, modified: ts, name: 'Unmask', identity_class: 'system', description: 'Unmask phishing email inspector (https://github.com/praneeth132006/Unmask). Analysis ran locally in the analyst’s browser.' },
  ];
  const refs: string[] = [];

  if (report.verdict !== 'clear') {
    for (const ioc of collectIocs(report)) {
      const pattern = stixPattern(ioc);
      if (!pattern) continue;
      const id = `indicator--${await uuid5(`${ioc.type}:${ioc.value}`)}`;
      if (refs.includes(id)) continue;
      refs.push(id);
      objects.push({ type: 'indicator', ...common, id, name: `${NAME[ioc.type] ?? ioc.type}: ${ioc.value.slice(0, 80)}`, description: `Seen in a ${report.verdict === 'high' ? 'high-risk' : 'suspicious'} email titled “${report.email.subject.slice(0, 120)}”.`, indicator_types: ['malicious-activity'], pattern, pattern_type: 'stix', valid_from: ts, confidence, labels: ['phishing'] });
    }
  }

  // Attack patterns referenced by ATT&CK id.
  const attackIds = new Set<string>();
  for (const s of doc.sections) for (const b of s.blocks) if (b.t === 'table' && b.head[0] === 'Technique') for (const r of b.rows) attackIds.add(r[0]!);
  const externalRefs: Record<string, string>[] = [];
  for (const tid of attackIds) {
    const id = `attack-pattern--${await uuid5(`mitre:${tid}`)}`;
    const ref = { source_name: 'mitre-attack', external_id: tid, url: `https://attack.mitre.org/techniques/${tid.replace('.', '/')}/` };
    objects.push({ type: 'attack-pattern', ...common, id, name: ATTACK_NAMES[tid] ?? tid, external_references: [ref] });
    refs.push(id);
    externalRefs.push(ref);
  }

  // The email itself as an observed object.
  const fromAddr = report.email.from?.address;
  if (fromAddr) {
    const addrId = `email-addr--${await uuid5(JSON.stringify({ value: fromAddr }))}`;
    const msgId = `email-message--${crypto.randomUUID()}`;
    objects.push({ type: 'email-addr', spec_version: '2.1', id: addrId, value: fromAddr, ...(report.email.from?.name ? { display_name: report.email.from.name } : {}) });
    objects.push({ type: 'email-message', spec_version: '2.1', id: msgId, is_multipart: false, ...(report.email.date && !Number.isNaN(Date.parse(report.email.date)) ? { date: new Date(report.email.date).toISOString() } : {}), from_ref: addrId, subject: report.email.subject, ...(report.email.messageId ? { message_id: report.email.messageId } : {}) });
    const obsId = `observed-data--${await uuid5(`observed:${report.email.messageId ?? report.email.subject}:${fromAddr}`)}`;
    objects.push({ type: 'observed-data', ...common, id: obsId, first_observed: ts, last_observed: ts, number_observed: 1, object_refs: [msgId, addrId] });
    refs.push(obsId);
  }

  const kinds = hypotheses(report);
  const reportId = `report--${await uuid5(`report:${doc.meta[0]?.[1] ?? ''}:${report.email.messageId ?? report.email.subject}`)}`;
  objects.push({
    type: 'report',
    ...common,
    id: reportId,
    name: `Email analysis: ${report.email.subject.slice(0, 120) || '(no subject)'}`,
    description: `${doc.verdict.label}, risk score ${report.score}/100. ${kinds.length ? `Assessed as: ${kinds.map((k) => `${k.label} (${k.confidence})`).join('; ')}.` : 'No known attack pattern matched.'} ${report.verdict === 'clear' ? 'No indicators were exported because nothing malicious was found.' : ''}`.trim(),
    published: ts,
    report_types: ['threat-report'],
    labels: ['phishing', ...(doc.tlp === 'AMBER+STRICT' ? ['tlp:amber+strict'] : [])],
    confidence,
    object_refs: refs.length ? refs : [identityId],
    ...(externalRefs.length ? { external_references: externalRefs } : {}),
  });
  return { type: 'bundle', id: `bundle--${await uuid5(`bundle:${reportId}`)}`, objects };
}
