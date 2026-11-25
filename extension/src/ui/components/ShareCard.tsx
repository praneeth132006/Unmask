import { useState } from 'react';
import type { Report } from '../../core/types';
import { drawShareCard, shareText } from '../shareCard';
import { Button } from './ui';
import { Icon } from './Icon';

/** "Warn someone": a picture and a text of the verdict, to send to family or a team chat. */
export function ShareCard({ report }: { report: Report }) {
  const [state, setState] = useState<'idle' | 'copied' | 'saved' | 'text'>('idle');
  if (report.verdict === 'clear') return null;

  const image = async (): Promise<Blob | null> => {
    const canvas = document.createElement('canvas');
    drawShareCard(report, canvas);
    return new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
  };
  const copyImage = async () => {
    const blob = await image();
    try {
      if (!blob) throw new Error('no image');
      await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
      setState('copied');
    } catch {
      download(blob);
    }
  };
  const download = (blob: Blob | null) => {
    if (!blob) return;
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'unmask-warning.png';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    setState('saved');
  };
  const copyText = async () => {
    await navigator.clipboard.writeText(shareText(report));
    setState('text');
  };
  return (
    <div className="mt-3 rounded-xl border border-[var(--border)] bg-[var(--surface)] p-3 text-xs" data-testid="share-card">
      <p className="font-medium text-[var(--text)]">Warn someone about this email</p>
      <p className="mt-0.5 text-[var(--text-2)]">A picture of this verdict for your family or team chat. Addresses are written so they can’t be clicked.</p>
      <div className="mt-2 flex flex-wrap gap-2">
        <Button onClick={copyImage}><Icon name="copy" className="h-3.5 w-3.5" /> Copy picture</Button>
        <Button onClick={async () => download(await image())}>Save picture</Button>
        <Button onClick={copyText}>Copy as text</Button>
      </div>
      {state !== 'idle' && (
        <p className="mt-2 text-[var(--good)]" role="status">
          {state === 'copied' ? 'Picture copied. Paste it into a chat.' : state === 'saved' ? 'Saved as unmask-warning.png.' : 'Text copied.'}
        </p>
      )}
    </div>
  );
}
