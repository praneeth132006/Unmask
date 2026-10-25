import { useState } from 'react';
import type { Report } from '../../core/types';
import { Button, Card, Mono, SectionTitle } from './ui';
import { Icon } from './Icon';

const KEY_HEADERS = new Set(['from', 'reply-to', 'return-path', 'sender', 'to', 'subject', 'date', 'message-id', 'authentication-results', 'received-spf', 'x-originating-ip', 'x-mailer', 'list-unsubscribe']);

export function HeadersTab({ report, initialFilter }: { report: Report; initialFilter?: string }) {
  const [filter, setFilter] = useState(initialFilter ?? '');
  const headers = report.email.headers;
  const hops = report.forensics.hops;
  const shown = headers.filter((h) => !filter || h.key.includes(filter.toLowerCase()) || h.value.toLowerCase().includes(filter.toLowerCase()));

  const { dkim, arc, arcProblem } = report.forensics;

  return (
    <div>
      {dkim.length > 0 && (
        <>
          <SectionTitle>Signatures (DKIM)</SectionTitle>
          <Card>
            <ul className="space-y-2 text-xs">
              {dkim.map((d, i) => (
                <li key={i} className="min-w-0">
                  <div>
                    <Mono>{d.domain}</Mono>
                    <span className="ml-1 text-[var(--text-3)]">
                      key “{d.selector}” · {d.algorithm}
                      {d.keyBits ? ` · ${d.keyBits}-bit` : ''}
                    </span>
                  </div>
                  <div className="text-[11px] text-[var(--text-2)]">
                    Body: {d.bodyHash === 'match' ? 'unchanged since signing' : d.bodyHash === 'mismatch' ? 'changed after signing' : 'not checked'}
                    {d.bodyLength !== null && ` (only the first ${d.bodyLength} bytes are signed)`} · Signature: {SIGNATURE_LABEL[d.signature ?? 'pending']}
                  </div>
                  {d.reason && <div className="text-[11px] text-[var(--text-3)]">{d.reason}</div>}
                  <div className="text-[11px] text-[var(--text-3)]">Signs: {d.signedHeaders.join(', ')}</div>
                </li>
              ))}
            </ul>
          </Card>
        </>
      )}

      {arc.length > 0 && (
        <>
          <SectionTitle>Forwarding record (ARC)</SectionTitle>
          <Card>
            <ol className="space-y-1.5 text-xs">
              {arc.map((a) => (
                <li key={a.instance}>
                  <span className="font-semibold">{a.instance}.</span> <Mono>{a.domain}</Mono>
                  <span className="ml-1 text-[var(--text-3)]">
                    saw {Object.entries(a.results).filter(([m]) => ['spf', 'dkim', 'dmarc'].includes(m)).map(([m, r]) => `${m}=${r}`).join(', ') || 'no results'} · chain {a.cv}
                  </span>
                </li>
              ))}
            </ol>
            {arcProblem && <p className="mt-2 text-[11px] text-[var(--warn)]">{arcProblem}</p>}
          </Card>
        </>
      )}

      {hops.length > 0 && (
        <>
          <SectionTitle>Delivery path (where it came from, first)</SectionTitle>
          <Card>
            <ol className="space-y-2.5">
              {hops.map((h, i) => (
                <li key={i} className="flex gap-2.5 text-xs">
                  <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-[var(--accent-soft)] text-[10px] font-semibold text-[var(--accent)]">{h.n}</span>
                  <div className="min-w-0">
                    <Mono>{h.helo ?? h.rdns ?? 'unknown'}</Mono>
                    {h.ip && <span className="ml-1 text-[var(--text-3)]">[{h.ip}]</span>}
                    {h.rdns && h.rdns !== h.helo && <div className="text-[11px] text-[var(--text-3)]">DNS name: {h.rdns}</div>}
                    {report.forensics.sender && report.forensics.sender.ip === h.ip && h.trusted && (
                      <div className="text-[11px] text-[var(--text-3)]">
                        {[report.forensics.sender.network && `Network: ${report.forensics.sender.network}`, report.forensics.sender.asn && `AS${report.forensics.sender.asn}`, report.forensics.sender.country].filter(Boolean).join(' · ')}
                      </div>
                    )}
                    {h.by && (
                      <div className="text-[11px] text-[var(--text-3)]">
                        → <Mono>{h.by}</Mono>
                        {h.delaySec !== null && h.delaySec !== 0 && <span className={h.delaySec < 0 ? 'ml-1 text-[var(--warn)]' : 'ml-1'}>({formatDelay(h.delaySec)})</span>}
                      </div>
                    )}
                    {!h.trusted && hops.some((x) => x.trusted) && <div className="text-[11px] text-[var(--text-3)]">Written before your provider got it: can’t be verified</div>}
                  </div>
                </li>
              ))}
            </ol>
          </Card>
        </>
      )}

      <div className={`flex flex-wrap gap-2 ${hops.length > 0 ? 'mt-2.5' : ''}`}>
        <CopyAll label="Copy all headers" value={headers.map((h) => `${h.name}: ${h.value}`).join('\n')} />
        {hops.length > 0 && <CopyAll label="Copy delivery path" value={hops.map((h) => `${h.n}. ${h.helo ?? h.rdns ?? 'unknown'}${h.ip ? ` [${h.ip}]` : ''}${h.by ? ` → ${h.by}` : ''}${h.trusted ? '' : ' (unverified)'}`).join('\n')} />}
      </div>

      <SectionTitle
        right={
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter headers"
            className="w-36 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--text)] placeholder:text-[var(--text-3)] focus:border-[var(--accent)] focus:outline-none"
          />
        }
      >
        All headers ({headers.length})
      </SectionTitle>
      <Card className="!p-0 overflow-hidden">
        <dl className="divide-y divide-[var(--border)]">
          {shown.map((h, i) => (
            <div key={i} className={`px-3 py-1.5 ${KEY_HEADERS.has(h.key) ? 'bg-[var(--accent-soft)]' : ''}`}>
              <dt className="text-[11px] font-semibold text-[var(--text)]">{h.name}</dt>
              <dd>
                <Mono>{h.value}</Mono>
              </dd>
            </div>
          ))}
        </dl>
      </Card>
    </div>
  );
}

/** A visible button (not the small inline one) for copying a whole block. */
function CopyAll({ label, value }: { label: string; value: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
    >
      <Icon name={done ? 'check' : 'copy'} className="h-3.5 w-3.5" />
      {done ? 'Copied' : label}
    </Button>
  );
}

const SIGNATURE_LABEL: Record<string, string> = {
  pending: 'not checked (needs "Check certificate history and mail records" in Settings)',
  pass: 'verified with the signer’s public key',
  fail: 'does not verify',
  'no-key': 'no such key published',
  revoked: 'key withdrawn',
  unsupported: 'can’t be checked in this browser',
  error: 'lookup failed',
};

function formatDelay(sec: number): string {
  const a = Math.abs(sec);
  const t = a < 60 ? `${a}s` : a < 3600 ? `${Math.round(a / 60)} min` : a < 86_400 ? `${Math.round(a / 3600)} h` : `${Math.round(a / 86_400)} days`;
  return sec < 0 ? `${t} earlier: clock out of order` : `+${t}`;
}
