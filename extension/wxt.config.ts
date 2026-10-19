import { defineConfig } from 'wxt';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  srcDir: '.',
  // Visible folder at the repo root: load UNMASK/build/unmask-chrome via "Load unpacked".
  outDir: '../build',
  outDirTemplate: 'unmask-{{browser}}{{modeSuffix}}',
  // Release asset name, e.g. build/unmask-chrome-0.2.0.zip.
  zip: { artifactTemplate: 'unmask-{{browser}}-{{packageVersion}}.zip' },
  modules: ['@wxt-dev/module-react'],
  vite: () => ({
    plugins: [tailwindcss()],
    // tldts bundles the full public-suffix list; a large single chunk is fine for an extension page.
    build: { chunkSizeWarningLimit: 1500 },
  }),
  manifest: {
    name: 'Unmask — Phishing Email Inspector',
    short_name: 'Unmask',
    description:
      'See what a suspicious email is really hiding: real sender, real links, hidden text and attachment checks.',
    permissions: ['storage', 'tabs'],
    host_permissions: [
      'https://mail.google.com/*',
      // "Download original" can redirect to Google's content host.
      'https://*.googleusercontent.com/*',
      'https://www.virustotal.com/*',
      'https://urlscan.io/*',
    ],
    action: {
      default_title: 'Open Unmask',
    },
  },
});
