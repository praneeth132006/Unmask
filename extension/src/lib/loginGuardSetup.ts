/**
 * Turns "Warn on fake sign-in pages anywhere" on and off. The content script is
 * registered at run time only while the setting is on, so Unmask runs on other
 * sites only when the user asked for it, and with the permission they granted.
 */
import { browser } from 'wxt/browser';

const ID = 'unmask-login-guard';
const PERMS = { permissions: ['scripting'], origins: ['<all_urls>'] } as const;

type Scripting = {
  registerContentScripts(s: { id: string; matches: string[]; js: string[]; runAt: string; allFrames: boolean; persistAcrossSessions?: boolean }[]): Promise<void>;
  unregisterContentScripts(f: { ids: string[] }): Promise<void>;
  getRegisteredContentScripts(f: { ids: string[] }): Promise<unknown[]>;
};
const scripting = () => (browser as unknown as { scripting?: Scripting }).scripting;

/** From a click in Settings: asks for the permission (only a user gesture may). */
export async function requestLoginGuard(): Promise<boolean> {
  try {
    return await browser.permissions.request({ permissions: [...PERMS.permissions], origins: [...PERMS.origins] } as never);
  } catch {
    return false;
  }
}

/** Makes the registration match the setting. Safe to call repeatedly. */
export async function syncLoginGuard(on: boolean): Promise<void> {
  const s = scripting();
  if (!s) return;
  const registered = (await s.getRegisteredContentScripts({ ids: [ID] }).catch(() => [])).length > 0;
  const allowed = on && (await browser.permissions.contains({ permissions: [...PERMS.permissions], origins: [...PERMS.origins] } as never).catch(() => false));
  if (allowed && !registered) await s.registerContentScripts([{ id: ID, matches: ['https://*/*', 'http://*/*'], js: ['content-scripts/login-guard.js'], runAt: 'document_idle', allFrames: false, persistAcrossSessions: true }]).catch(() => {});
  if (!allowed && registered) await s.unregisterContentScripts({ ids: [ID] }).catch(() => {});
}
