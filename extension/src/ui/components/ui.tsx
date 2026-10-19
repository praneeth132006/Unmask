import { useState, type ReactNode, type ButtonHTMLAttributes } from 'react';
import type { Severity } from '../../core/types';

export const SEVERITY_STYLE: Record<Severity, { dot: string; pill: string; label: string }> = {
  critical: { dot: 'bg-red-600', pill: 'bg-red-600 text-white', label: 'Critical' },
  high: { dot: 'bg-red-500', pill: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200', label: 'High' },
  medium: { dot: 'bg-amber-500', pill: 'bg-amber-100 text-amber-900 dark:bg-amber-950 dark:text-amber-200', label: 'Medium' },
  low: { dot: 'bg-yellow-400', pill: 'bg-yellow-100 text-yellow-900 dark:bg-yellow-950 dark:text-yellow-200', label: 'Low' },
  info: { dot: 'bg-slate-400', pill: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300', label: 'Note' },
  good: { dot: 'bg-emerald-500', pill: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200', label: 'Good' },
};

export function Pill({ severity, children }: { severity: Severity; children: ReactNode }) {
  return <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-medium leading-tight ${SEVERITY_STYLE[severity].pill}`}>{children}</span>;
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`rounded-lg border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-900 ${className}`}>{children}</div>;
}

export function SectionTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-2 mt-4 flex items-center justify-between first:mt-0">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">{children}</h3>
      {right}
    </div>
  );
}

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
const VARIANTS: Record<Variant, string> = {
  primary: 'bg-indigo-600 text-white hover:bg-indigo-500 disabled:bg-indigo-300 dark:disabled:bg-indigo-900',
  secondary: 'border border-slate-300 bg-white text-slate-800 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:hover:bg-slate-800',
  ghost: 'text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800',
  danger: 'bg-red-600 text-white hover:bg-red-500',
};

export function Button({ variant = 'secondary', className = '', ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant }) {
  return (
    <button
      type="button"
      {...props}
      className={`inline-flex items-center justify-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${VARIANTS[variant]} ${className}`}
    />
  );
}

export function CopyButton({ value, label = 'Copy' }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      variant="ghost"
      className="!px-1.5 !py-0.5"
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
  return <code className={`break-all font-mono text-[11px] text-slate-700 dark:text-slate-300 ${className}`}>{children}</code>;
}

export function ErrorText({ children }: { children: ReactNode }) {
  return <p className="mt-1 text-xs text-red-600 dark:text-red-400">{children}</p>;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

/** Async action state for buttons that call online services. */
export type Async<T> = { status: 'idle' } | { status: 'loading'; message?: string } | { status: 'done'; value: T } | { status: 'error'; error: string };
