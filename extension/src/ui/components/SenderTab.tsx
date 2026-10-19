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
  DKIM: 'Is the message digitally signed and unchanged?',
  DMARC: 'Does the From address match what was verified?',
};

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[92px_1fr] gap-2 px-3 py-2 text-xs">
      <div className="text-[var(--text-3)]">{label}</div>
      <div className="min-w-0 break-words">{children}</div>
    </div>
  );
}

export function SenderTab({
  report,
  domainAge,
  onCheckAge,
  onHoverSender,
}: {
  report: Report;
  domainAge: Async<DomainAge> | undefined;
  onCheckAge: () => void;
  /** Outline the sender in the Gmail message while hovered. */
  onHoverSender?: (on: boolean) => void;
}) {
  const { email, auth } = report;
  const from = email.from;
  const fromOrg = from ? registrableDomain(from.domain) : '';
  const senderFindings = report.findings.filter((f) => f.category === 'sender' && f.points > 0);

  return (
    <div>
      <SectionTitle>Who really sent it</SectionTitle>
      <Card className="!p-0 divide-y divide-[var(--border)]" onMouseEnter={() => onHoverSender?.(true)} onMouseLeave={() => onHoverSender?.(false)}>
        <Row label="Display name">{from?.name || <span className="text-[var(--text-3)]">(none)</span>}</Row>
        <Row label="Address">
          <Mono className="!text-[var(--text)]">{from?.address ?? 'missing'}</Mono>
        </Row>
        <Row label="Domain">
          <Mono>{fromOrg || '—'}</Mono>
        </Row>
        <Row label="Replies go to">
          {email.replyTo.length ? email.replyTo.map((r) => <Mono key={r.address} className="block">{r.address}</Mono>) : <span className="text-[var(--text-3)]">the sender</span>}
        </Row>
        <Row label="Bounces go to">{email.returnPath ? <Mono>{email.returnPath}</Mono> : <span className="text-[var(--text-3)]">—</span>}</Row>
        <Row label="Sent">{email.date ? new Date(email.date).toLocaleString() : '—'}</Row>
        <Row label="Domain age">
          {domainAge?.status === 'loading' && (
            <span className="inline-flex items-center gap-1.5 text-[var(--text-3)]">
              <Spinner /> Looking up…
            </span>
          )}
          {domainAge?.status === 'done' && domainAge.value.notFound && <span className="font-medium text-[var(--warn)]">No registration record found</span>}
          {domainAge?.status === 'done' &&
            !domainAge.value.notFound &&
            (domainAge.value.created ? (
              <span className={domainAge.value.ageDays! < 180 ? 'font-medium text-[var(--bad)]' : ''}>
                {domainAge.value.ageDays! < 365 ? `${domainAge.value.ageDays} days` : `${(domainAge.value.ageDays! / 365).toFixed(1)} years`}{' '}
                <span className="font-normal text-[var(--text-3)]">(since {domainAge.value.created.slice(0, 10)})</span>
              </span>
            ) : (
              <span className="text-[var(--text-3)]">The registry doesn’t publish it</span>
            ))}
          {domainAge?.status === 'error' && <ErrorText>{domainAge.error}</ErrorText>}
          {(!domainAge || domainAge.status === 'idle') && fromOrg && (
            <Button className="!py-0.5" onClick={onCheckAge}>
              Check domain age
            </Button>
          )}
        </Row>
      </Card>

      {senderFindings.length > 0 && (
        <>
          <SectionTitle>Problems with the sender</SectionTitle>
          <Card className="!p-0 divide-y divide-[var(--border)]">
            {senderFindings.map((f) => (
              <div key={f.id} className="flex gap-2 px-3 py-2">
                <Pill severity={f.severity}>{f.severity}</Pill>
                <div className="min-w-0 text-xs">
                  <div className="font-medium">{f.title}</div>
                  {f.detail && <div className="mt-0.5 text-[var(--text-2)]">{f.detail}</div>}
                </div>
              </div>
            ))}
          </Card>
        </>
      )}

      <SectionTitle>Authentication {auth.server && <span className="font-normal normal-case tracking-normal">· checked by {auth.server}</span>}</SectionTitle>
      <Card className="!p-0 divide-y divide-[var(--border)]">
        {(
          [
            ['SPF', auth.spf, auth.spfDomain],
            ['DKIM', auth.dkim, auth.dkimDomains.join(', ') || null],
            ['DMARC', auth.dmarc, auth.dmarcDomain],
          ] as const
        ).map(([name, result, domain]) => (
          <div key={name} className="flex items-start justify-between gap-3 px-3 py-2.5">
            <div>
              <div className="text-xs font-semibold">{name}</div>
              <div className="text-[11px] text-[var(--text-3)]">{AUTH_HELP[name]}</div>
            </div>
            <div className="shrink-0 text-right">
              <Pill severity={AUTH_SEVERITY[result]}>{result}</Pill>
              {domain && <div className="mt-0.5 max-w-[120px] truncate font-mono text-[10px] text-[var(--text-3)]">{domain}</div>}
            </div>
          </div>
        ))}
        {!auth.raw && <p className="px-3 py-2.5 text-xs text-[var(--text-2)]">No authentication results were found. Forwarded or pasted emails often lose them.</p>}
      </Card>
    </div>
  );
}
