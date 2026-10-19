import { browser } from 'wxt/browser';

export interface Settings {
  /** Free key from virustotal.com → profile → API key. Stored only in this browser. */
  vtApiKey: string;
  /** Free key from urlscan.io → settings → API keys. */
  urlscanApiKey: string;
  /** "private" scans are not shared with other urlscan users (needs a plan that allows it). */
  urlscanVisibility: 'public' | 'unlisted' | 'private';
  /** Base URL of the Unmask redirect-trace backend, e.g. https://unmask-trace.vercel.app */
  backendUrl: string;
  /** Look up how old the sender's domain is (sends only the domain name to rdap.org). */
  autoDomainAge: boolean;
  /** Panel colour theme; "system" follows the operating system. */
  theme: Theme;
  /** How "Trace redirects" works: inside Unmask, or through a self-hosted server. */
  traceMode: 'builtin' | 'server';
}

export type Theme = 'system' | 'light' | 'dark';

export const DEFAULT_SETTINGS: Settings = {
  vtApiKey: '',
  urlscanApiKey: '',
  urlscanVisibility: 'unlisted',
  backendUrl: '',
  autoDomainAge: true,
  theme: 'system',
  traceMode: 'builtin',
};

const THEME_CACHE = 'unmask:theme';

/**
 * Applies the theme to <html>. Also mirrored in localStorage so the panel can
 * paint in the right theme before the async extension storage has loaded.
 */
export function applyTheme(theme: Theme): void {
  if (theme === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', theme);
  try {
    localStorage.setItem(THEME_CACHE, theme);
  } catch {
    // storage unavailable: the theme still applies for this session
  }
}

export function applyCachedTheme(): void {
  try {
    const t = localStorage.getItem(THEME_CACHE);
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch {
    // ignore
  }
}

const KEY = 'unmask:settings';

export async function loadSettings(): Promise<Settings> {
  const stored = await browser.storage.local.get(KEY);
  return { ...DEFAULT_SETTINGS, ...((stored[KEY] as Partial<Settings> | undefined) ?? {}) };
}

export async function saveSettings(settings: Settings): Promise<void> {
  await browser.storage.local.set({
    [KEY]: { ...settings, backendUrl: settings.backendUrl.trim().replace(/\/+$/, ''), vtApiKey: settings.vtApiKey.trim(), urlscanApiKey: settings.urlscanApiKey.trim() },
  });
}
