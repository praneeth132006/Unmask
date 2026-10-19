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
  /** Remember who emails you (on this device only) for "first contact" warnings. */
  senderHistory: boolean;
  /** Look up certificate history (crt.sh) and mail DNS records (dns.google) for the sender and link domains. */
  domainIntel: boolean;
  /** Red or amber banner above risky emails inside Gmail. */
  gmailBanner: boolean;
  /** Risk badge next to risky senders in the Gmail inbox list. */
  inboxBadges: boolean;
  /** "Wait, this goes to …" before risky links, and a warning when Reply goes elsewhere. */
  clickProtection: boolean;
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
  senderHistory: true,
  domainIntel: true,
  gmailBanner: true,
  inboxBadges: true,
  clickProtection: true,
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

export const SETTINGS_KEY = 'unmask:settings';
const KEY = SETTINGS_KEY;

export async function loadSettings(): Promise<Settings> {
  const stored = await browser.storage.local.get(KEY);
  return { ...DEFAULT_SETTINGS, ...((stored[KEY] as Partial<Settings> | undefined) ?? {}) };
}

export async function saveSettings(settings: Settings): Promise<void> {
  await browser.storage.local.set({
    [KEY]: { ...settings, backendUrl: settings.backendUrl.trim().replace(/\/+$/, ''), vtApiKey: settings.vtApiKey.trim(), urlscanApiKey: settings.urlscanApiKey.trim() },
  });
}
