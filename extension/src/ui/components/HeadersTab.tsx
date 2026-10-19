import { useMemo, useState } from 'react';
import type { Report } from '../../core/types';
import { Card, Mono, SectionTitle } from './ui';

const KEY_HEADERS = new Set(['from', 'reply-to', 'return-path', 'sender', 'to', 'subject', 'date', 'message-id', 'authentication-results', 'received-spf', 'x-originating-ip', 'x-mailer', 'list-unsubscribe']);

export interface ReceivedHop {
  from: string | null;
  by: string | null;
  ip: string | null;
  date: string | null;
}

/** Received headers are prepended by each server, so reversing gives the path from origin to inbox. */
export function parseReceived(values: string[]): ReceivedHop[] {
  return values
    .map((v) => {
      const flat = v.replace(/\s+/g, ' ');
      return {
        from: flat.match(/\bfrom\s+([^\s;()]+)/i)?.[1] ?? null,
        by: flat.match(/\bby\s+([^\s;()]+)/i)?.[1] ?? null,
        ip: flat.match(/\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,})\]/i)?.[1] ?? null,
        date: flat.split(';').pop()?.trim() ?? null,
      };
    })
    .reverse();
}

export function HeadersTab({ report, initialFilter }: { report: Report; initialFilter?: string }) {
  const [filter, setFilter] = useState(initialFilter ?? '');
  const headers = report.email.headers;
  const hops = useMemo(() => parseReceived(headers.filter((h) => h.key === 'received').map((h) => h.value)), [headers]);
  const shown = headers.filter((h) => !filter || h.key.includes(filter.toLowerCase()) || h.value.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div>
      {hops.length > 0 && (
        <>
          <SectionTitle>Delivery path (where it came from, first)</SectionTitle>
          <Card>
            <ol className="space-y-1.5">
              {hops.map((h, i) => (
                <li key={i} className="flex gap-2 text-xs">
                  <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-[var(--accent-soft)] text-[10px] font-semibold text-[var(--accent)]">{i + 1}</span>
                  <div className="min-w-0">
                    <Mono>{h.from ?? 'unknown'}</Mono>
                    {h.ip && <span className="ml-1 text-[var(--text-3)]">[{h.ip}]</span>}
                    {h.by && (
                      <div className="text-[11px] text-[var(--text-3)]">
                        → <Mono>{h.by}</Mono>
                      </div>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          </Card>
        </>
      )}

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
              <dt className="text-[11px] font-semibold text-[var(--text)]">{h.key}</dt>
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
