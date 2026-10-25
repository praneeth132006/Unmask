import { browser } from 'wxt/browser';

export interface Settings {
  /** Free key from virustotal.com → profile → API key. Stored only in this browser. */
  vtApiKey: string;
  /** Free key from urlscan.io → settings → API keys. */
  urlscanApiKey: string;
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
  /** Look up who runs the sending server (reverse DNS, network) by sending its IP address to dns.google. */
  ipIntel: boolean;
  /** Red or amber banner above risky emails inside Gmail. */
  gmailBanner: boolean;
  /** Risk badge next to risky senders in the Gmail inbox list. */
  inboxBadges: boolean;
  /** "Wait, this goes to …" before risky links, and a warning when Reply goes elsewhere. */
  clickProtection: boolean;
  /** Plain words only: hides the technical tabs and details until asked for. */
  simpleMode: boolean;
  /** A "Peek" button on inbox rows to check an email without opening it. */
  peekButtons: boolean;
  /** Check new (unread) inbox emails automatically, before they are opened. */
  scanInbox: boolean;
  /** Settings layout version, for one-time upgrades of saved settings. */
  settingsVersion: number;
}

export type Theme = 'system' | 'light' | 'dark';

export const DEFAULT_SETTINGS: Settings = {
  vtApiKey: '',
  urlscanApiKey: '',
  backendUrl: '',
  autoDomainAge: true,
  theme: 'system',
  traceMode: 'builtin',
  senderHistory: true,
  domainIntel: true,
  ipIntel: false,
  gmailBanner: true,
  inboxBadges: true,
  clickProtection: true,
  simpleMode: false,
  peekButtons: true,
  scanInbox: true,
  settingsVersion: 2,
};

/** Every protection inside Gmail, all on by default. */
export const PROTECTION_KEYS = ['gmailBanner', 'inboxBadges', 'clickProtection', 'peekButtons', 'scanInbox'] as const;

/**
 * Brings saved settings up to date. Version 2 turned every in-Gmail
 * protection on; settings saved before it may have them off.
 */
export function migrateSettings(stored: Partial<Settings> | undefined): { settings: Settings; changed: boolean } {
  const s = { ...DEFAULT_SETTINGS, ...(stored ?? {}) };
  if (!stored || (stored.settingsVersion ?? 1) >= 2) return { settings: s, changed: false };
  for (const k of PROTECTION_KEYS) s[k] = true;
  s.settingsVersion = 2;
  return { settings: s, changed: true };
}

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
  const { settings, changed } = migrateSettings(stored[KEY] as Partial<Settings> | undefined);
  if (changed) await browser.storage.local.set({ [KEY]: settings });
  return settings;
}

export async function saveSettings(settings: Settings): Promise<void> {
  await browser.storage.local.set({
    [KEY]: { ...settings, backendUrl: settings.backendUrl.trim().replace(/\/+$/, ''), vtApiKey: settings.vtApiKey.trim(), urlscanApiKey: settings.urlscanApiKey.trim() },
  });
}
