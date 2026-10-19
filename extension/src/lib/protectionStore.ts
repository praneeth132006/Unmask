import { browser } from 'wxt/browser';
import { EMPTY_PROTECTION, sanitizeProtection, type ProtectionList } from '../analyzers/protection';

export const PROTECTION_KEY = 'unmask:protection';

/** Your protection list, kept only in this browser's extension storage. */
export async function loadProtection(): Promise<ProtectionList> {
  try {
    const stored = await browser.storage.local.get(PROTECTION_KEY);
    return stored[PROTECTION_KEY] ? sanitizeProtection(stored[PROTECTION_KEY]) : EMPTY_PROTECTION;
  } catch {
    return EMPTY_PROTECTION;
  }
}

export async function saveProtection(list: ProtectionList): Promise<ProtectionList> {
  const clean = sanitizeProtection(list);
  await browser.storage.local.set({ [PROTECTION_KEY]: clean });
  return clean;
}

export function isEmptyProtection(l: ProtectionList): boolean {
  return !l.brands.length && !l.contacts.length && !l.trusted.length;
}
