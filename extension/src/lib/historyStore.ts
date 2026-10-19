import { browser } from 'wxt/browser';
import type { Report } from '../core/types';
import { EMPTY_HISTORY, recordSender, type SenderHistory } from '../analyzers/history';

const KEY = 'unmask:sender-history';

/** The sender history, kept only in this browser's extension storage. */
export async function loadHistory(): Promise<SenderHistory> {
  try {
    const stored = await browser.storage.local.get(KEY);
    return (stored[KEY] as SenderHistory | undefined) ?? EMPTY_HISTORY;
  } catch {
    return EMPTY_HISTORY;
  }
}

/**
 * Learns the sender of an analyzed email. High-risk emails are never learned,
 * so a phisher can't make themselves "known" by sending twice.
 */
export async function rememberSender(report: Report): Promise<void> {
  if (report.verdict === 'high' || !report.email.from) return;
  const history = await loadHistory();
  const next = recordSender(history, report.email);
  if (next !== history) await browser.storage.local.set({ [KEY]: next });
}

export async function clearHistory(): Promise<void> {
  await browser.storage.local.remove(KEY);
}

export function historySize(h: SenderHistory): number {
  return Object.keys(h.senders).length;
}
