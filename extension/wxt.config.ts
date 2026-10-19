import { defineConfig } from 'wxt';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  srcDir: '.',
  // Visible folder at the repo root: load UNMASK/build/unmask-chrome via "Load unpacked".
  outDir: '../build',
  // UNMASK_E2E=1 builds a test copy (build/unmask-e2e) with host permission for the e2e test domain only.
  outDirTemplate: process.env.UNMASK_E2E ? 'unmask-e2e' : 'unmask-{{browser}}{{modeSuffix}}',
  // Release asset name, e.g. build/unmask-chrome-0.2.0.zip.
  zip: { artifactTemplate: 'unmask-{{browser}}-{{packageVersion}}.zip' },
  modules: ['@wxt-dev/module-react'],
  vite: () => ({
    plugins: [tailwindcss()],
    // tldts bundles the full public-suffix list; a large single chunk is fine for an extension page.
    build: { chunkSizeWarningLimit: 1500 },
    // ASCII-only output: Chrome refuses to load a content script containing Unicode
    // noncharacters such as U+FFFF (it reports the file as "not UTF-8").
    esbuild: { charset: 'ascii' },
  }),
  manifest: {
    name: 'Unmask — Phishing Email Inspector',
    short_name: 'Unmask',
    description:
      'See what a suspicious email is really hiding: real sender, real links, hidden text and attachment checks.',
    permissions: ['storage', 'tabs', 'webRequest'],
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
  },
});
