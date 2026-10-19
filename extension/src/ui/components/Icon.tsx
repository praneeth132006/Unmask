const PATHS = {
  mask: 'M3 9.5C3 7 5.5 6 8 6c1.6 0 2.9.6 4 1.4C13.1 6.6 14.4 6 16 6c2.5 0 5 1 5 3.5 0 3-2.2 5.5-5 5.5-1.6 0-2.9-.9-4-2.2-1.1 1.3-2.4 2.2-4 2.2-2.8 0-5-2.5-5-5.5Zm4.5-.5a1.5 1 0 1 0 0 2 1.5 1 0 0 0 0-2Zm9 0a1.5 1 0 1 0 0 2 1.5 1 0 0 0 0-2Z',
  gear: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7.5 7.5 0 0 0-2-1.2L14.5 3h-4l-.4 2.6a7.5 7.5 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7.5 7.5 0 0 0 2 1.2l.4 2.6h4l.4-2.6a7.5 7.5 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2Z',
  upload: 'M12 16V4m0 0-4 4m4-4 4 4M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3',
  refresh: 'M20 11a8 8 0 0 0-14.9-3M4 4v4h4m-4 5a8 8 0 0 0 14.9 3M20 20v-4h-4',
  external: 'M14 4h6v6m0-6L10 14M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5',
  close: 'M6 6l12 12M18 6 6 18',
  paste: 'M9 4h6m-6 0a1 1 0 0 0-1 1v1h8V5a1 1 0 0 0-1-1M9 4H7a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2h-2',
} as const;

export function Icon({ name, className = 'h-4 w-4' }: { name: keyof typeof PATHS; className?: string }) {
  const filled = name === 'mask';
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden fill={filled ? 'currentColor' : 'none'} stroke={filled ? 'none' : 'currentColor'} strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round" fillRule="evenodd">
      <path d={PATHS[name]} />
    </svg>
  );
}
