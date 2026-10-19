import { useState, type ReactNode, type ButtonHTMLAttributes, type HTMLAttributes } from 'react';
import type { Severity } from '../../core/types';

/** Colour treatment per severity, all from the design tokens in style.css. */
export const SEVERITY_STYLE: Record<Severity, { dot: string; pill: string; label: string; bar: string }> = {
  critical: { dot: 'bg-[var(--bad)]', pill: 'bg-[var(--bad)] text-white', label: 'Critical', bar: 'bg-[var(--bad)]' },
  high: { dot: 'bg-[var(--bad)]', pill: 'bg-[var(--bad-soft)] text-[var(--bad)]', label: 'High', bar: 'bg-[var(--bad)]' },
  medium: { dot: 'bg-[var(--warn)]', pill: 'bg-[var(--warn-soft)] text-[var(--warn)]', label: 'Medium', bar: 'bg-[var(--warn)]' },
  low: { dot: 'bg-[var(--warn)] opacity-60', pill: 'bg-[var(--warn-soft)] text-[var(--warn)]', label: 'Low', bar: 'bg-[var(--warn)] opacity-60' },
  info: { dot: 'bg-[var(--info)]', pill: 'bg-[var(--info-soft)] text-[var(--info)]', label: 'Note', bar: 'bg-[var(--info)]' },
  good: { dot: 'bg-[var(--good)]', pill: 'bg-[var(--good-soft)] text-[var(--good)]', label: 'Good', bar: 'bg-[var(--good)]' },
};

export function Pill({ severity, children }: { severity: Severity; children: ReactNode }) {
  return <span className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-[11px] font-medium leading-tight ${SEVERITY_STYLE[severity].pill}`}>{children}</span>;
}

export function Card({ children, className = '', ...rest }: { children: ReactNode; className?: string } & HTMLAttributes<HTMLDivElement>) {
  return (
    <div {...rest} className={`rounded-xl border border-[var(--border)] bg-[var(--surface)] p-3 shadow-[var(--shadow)] ${className}`}>
      {children}
    </div>
  );
}

export function SectionTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-2 mt-5 flex items-center justify-between first:mt-0">
      <h3 className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-3)]">{children}</h3>
      {right}
    </div>
  );
}

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
const VARIANTS: Record<Variant, string> = {
  primary: 'bg-[var(--accent)] text-[var(--on-accent)] hover:bg-[var(--accent-hover)]',
  secondary: 'border border-[var(--border)] bg-[var(--surface)] text-[var(--text)] hover:border-[var(--border-strong)] hover:bg-[var(--surface-2)]',
  ghost: 'text-[var(--text-2)] hover:bg-[var(--surface-2)] hover:text-[var(--text)]',
  danger: 'bg-[var(--bad)] text-white hover:opacity-90',
};

export function Button({ variant = 'secondary', className = '', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type="button"
      {...props}
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50 ${VARIANTS[variant]} ${className}`}
    />
  );
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      variant="ghost"
      className="!px-1.5 !py-0.5 text-[11px]"
      onClick={() => {
        navigator.clipboard.writeText(value).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
    >
      {done ? 'Copied' : label}
    </Button>
  );
}

export function Spinner() {
  return <span className="inline-block h-3 w-3 animate-spin rounded-full border-2 border-current border-r-transparent" aria-hidden />;
}

export function Mono({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <code className={`break-all font-mono text-[11px] text-[var(--text-2)] ${className}`}>{children}</code>;
}

export function ErrorText({ children }: { children: ReactNode }) {
  return <p className="mt-1.5 text-xs text-[var(--bad)]">{children}</p>;
}

export function Label({ children }: { children: ReactNode }) {
  return <div className="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-3)]">{children}</div>;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** Async action state for buttons that call online services. */
export type Async<T> = { status: 'idle' } | { status: 'loading'; message?: string } | { status: 'done'; value: T } | { status: 'error'; error: string };
