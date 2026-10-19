import type { ReactNode } from 'react';
import type { AuthResult, Report } from '../../core/types';
import type { DomainAge } from '../../integrations/rdap';
import { registrableDomain } from '../../lib/domain';
import { Button, Card, ErrorText, Mono, Pill, SectionTitle, Spinner, type Async } from './ui';

const AUTH_SEVERITY: Record<AuthResult, 'good' | 'high' | 'medium' | 'low' | 'info'> = {
  pass: 'good',
  fail: 'high',
  softfail: 'medium',
  neutral: 'low',
  none: 'low',
  temperror: 'info',
  permerror: 'medium',
  policy: 'info',
  unknown: 'info',
};

const AUTH_HELP: Record<string, string> = {
  SPF: 'Was the sending server allowed to send for this domain?',
  DKIM: 'Is the message cryptographically signed and unaltered?',
  DMARC: 'Does the From domain match what was verified?',
};

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[88px_1fr] gap-2 py-1.5 text-xs">
      <div className="text-slate-500 dark:text-slate-400">{label}</div>
      <div className="min-w-0 break-words text-slate-900 dark:text-slate-100">{children}</div>
    </div>
  );
}

export function SenderTab({
  report,
  domainAge,
  onCheckAge,
}: {
  report: Report;
  domainAge: Async<DomainAge> | undefined;
  onCheckAge: () => void;
}) {
  const { email, auth } = report;
  const from = email.from;
  const fromOrg = from ? registrableDomain(from.domain) : '';

  return (
    <div>
      <SectionTitle>Who really sent it</SectionTitle>
      <Card className="divide-y divide-slate-100 !py-1 dark:divide-slate-800">
        <Row label="Display name">{from?.name || <span className="text-slate-400">(none)</span>}</Row>
        <Row label="Address">
          <Mono>{from?.address ?? 'missing'}</Mono>
        </Row>
        <Row label="Domain">
          <Mono>{fromOrg || '—'}</Mono>
        </Row>
        <Row label="Reply-To">
          {email.replyTo.length ? email.replyTo.map((r) => <Mono key={r.address} className="block">{r.address}</Mono>) : <span className="text-slate-400">same as sender</span>}
        </Row>
        <Row label="Return-Path">{email.returnPath ? <Mono>{email.returnPath}</Mono> : <span className="text-slate-400">—</span>}</Row>
        <Row label="Sent">{email.date ? new Date(email.date).toLocaleString() : '—'}</Row>
        <Row label="Domain age">
          {domainAge?.status === 'loading' && (
            <span className="inline-flex items-center gap-1.5 text-slate-500">
              <Spinner /> Looking up…
            </span>
          )}
          {domainAge?.status === 'done' &&
            (domainAge.value.created ? (
              <span>
                {domainAge.value.ageDays! < 365 ? `${domainAge.value.ageDays} days` : `${(domainAge.value.ageDays! / 365).toFixed(1)} years`}{' '}
                <span className="text-slate-500">(registered {domainAge.value.created.slice(0, 10)})</span>
              </span>
            ) : (
              <span className="text-slate-500">Registry does not publish it</span>
            ))}
          {domainAge?.status === 'error' && <ErrorText>{domainAge.error}</ErrorText>}
          {(!domainAge || domainAge.status === 'idle') && fromOrg && (
            <Button className="!py-0.5" onClick={onCheckAge}>
              Check via RDAP
            </Button>
          )}
        </Row>
      </Card>

      <SectionTitle>Authentication {auth.server && <span className="font-normal normal-case">· checked by {auth.server}</span>}</SectionTitle>
      <Card className="space-y-2">
        {(
          [
            ['SPF', auth.spf, auth.spfDomain],
            ['DKIM', auth.dkim, auth.dkimDomains.join(', ') || null],
            ['DMARC', auth.dmarc, auth.dmarcDomain],
          ] as const
        ).map(([name, result, domain]) => (
          <div key={name} className="flex items-start justify-between gap-2">
            <div>
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">{name}</div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400">{AUTH_HELP[name]}</div>
            </div>
            <div className="text-right">
              <Pill severity={AUTH_SEVERITY[result]}>{result}</Pill>
              {domain && <div className="mt-0.5 font-mono text-[10px] text-slate-500">{domain}</div>}
            </div>
          </div>
        ))}
        {!auth.raw && <p className="text-xs text-slate-500">No Authentication-Results header was found. Forwarded or pasted emails often lose it.</p>}
      </Card>
    </div>
  );
}
