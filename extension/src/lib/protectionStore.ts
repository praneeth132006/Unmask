import { browser } from 'wxt/browser';
import { EMPTY_PROTECTION, mergeProtection, sanitizeProtection, type ProtectionList } from '../analyzers/protection';

export const PROTECTION_KEY = 'unmask:protection';
/** Policy key an IT admin sets for every browser in the organisation (see docs/TEAMS.md). */
export const MANAGED_KEY = 'protectionList';

/** The list this user built, kept only in this browser's extension storage. Edit this one. */
export async function loadOwnProtection(): Promise<ProtectionList> {
  try {
    const stored = await browser.storage.local.get(PROTECTION_KEY);
    return stored[PROTECTION_KEY] ? sanitizeProtection(stored[PROTECTION_KEY]) : EMPTY_PROTECTION;
  } catch {
    return EMPTY_PROTECTION;
  }
}

/**
 * The list the organisation pushes by policy (Google Admin, Group Policy, Intune).
 * Read-only for the user. Empty when the browser isn't managed or the browser has no managed storage.
 */
export async function loadManagedProtection(): Promise<ProtectionList> {
  try {
    const stored = await browser.storage.managed.get(MANAGED_KEY);
    return stored[MANAGED_KEY] ? sanitizeProtection(stored[MANAGED_KEY]) : EMPTY_PROTECTION;
  } catch {
    return EMPTY_PROTECTION;
  }
}

/** Everything the checks should use: your own list plus your organisation's. */
export async function loadProtection(): Promise<ProtectionList> {
  const [own, managed] = await Promise.all([loadOwnProtection(), loadManagedProtection()]);
  return isEmptyProtection(managed) ? own : mergeProtection(own, managed);
}

export async function saveProtection(list: ProtectionList): Promise<ProtectionList> {
  const clean = sanitizeProtection(list);
  await browser.storage.local.set({ [PROTECTION_KEY]: clean });
  return clean;
}

export function isEmptyProtection(l: ProtectionList): boolean {
  return !l.brands.length && !l.contacts.length && !l.trusted.length;
}
