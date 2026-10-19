import { defineConfig } from 'wxt';
import tailwindcss from '@tailwindcss/vite';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Chrome refuses a content script containing Unicode noncharacters such as
 * U+FFFF (it says the file "isn't UTF-8") and then won't load the extension
 * at all. Fail the build instead of shipping that.
 */
function assertNoNoncharacters(dir: string): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) assertNoNoncharacters(path);
    else if (entry.name.endsWith('.js')) {
      const bad = readFileSync(path, 'utf8').match(/[\uFDD0-\uFDEF\uFFFE\uFFFF]/);
      if (bad) throw new Error(`${path} contains U+${bad[0].charCodeAt(0).toString(16).toUpperCase()}; write it as an escape in the source.`);
    }
  }
}

export default defineConfig({
  srcDir: '.',
  // Visible folder at the repo root: load UNMASK/build/unmask-chrome via "Load unpacked".
  outDir: '../build',
  // UNMASK_E2E=1 builds a test copy (build/unmask-e2e) with host permission for the e2e test domain only.
  outDirTemplate: process.env.UNMASK_E2E ? 'unmask-e2e' : 'unmask-{{browser}}{{modeSuffix}}',
  // Release asset name, e.g. build/unmask-chrome-0.2.0.zip.
  zip: { artifactTemplate: 'unmask-{{browser}}-{{packageVersion}}.zip' },
  modules: ['@wxt-dev/module-react'],
  hooks: {
    'build:done': (wxt) => assertNoNoncharacters(wxt.config.outDir),
  },
  vite: () => ({
    plugins: [tailwindcss()],
    // tldts bundles the full public-suffix list; a large single chunk is fine for an extension page.
    build: { chunkSizeWarningLimit: 1500 },
  }),
  manifest: ({ browser }) => ({
    name: 'Unmask — Phishing Email Inspector',
    short_name: 'Unmask',
    description:
      'See what a suspicious email is really hiding: real sender, real links, hidden text and attachment checks.',
    // offscreen: HTML parsing for the in-Gmail checks if Gmail ever blocks it in the content script.
    permissions: ['storage', 'tabs', 'webRequest', ...(browser === 'firefox' ? [] : ['offscreen'])],
    // Asked for only when the user first clicks "Trace redirects" (built-in tracer).
    optional_host_permissions: ['<all_urls>'],
    host_permissions: [
      'https://mail.google.com/*',
      // "Download original" can redirect to Google's content host.
      'https://*.googleusercontent.com/*',
      'https://www.virustotal.com/*',
      'https://urlscan.io/*',
      // Domain intelligence: certificate history and mail DNS records (only domain names are sent).
      'https://crt.sh/*',
      'https://dns.google/*',
      ...(process.env.UNMASK_E2E ? ['*://*.unmask-e2e.test/*'] : []),
    ],
    action: {
      default_title: 'Open Unmask',
    },
    ...(browser === 'firefox'
      ? {
          browser_specific_settings: {
            gecko: {
              id: 'unmask@praneeth132006.github.io',
              // world: 'MAIN' content scripts (the Gmail session token reader) need Firefox 128.
              strict_min_version: '128.0',
              // No data goes to the developer. Lookups send public domain names or hashes
              // to the services named in Settings, only for the email being checked.
              data_collection_permissions: { required: ['none'] },
            },
          },
        }
      : {}),
  }),
});
