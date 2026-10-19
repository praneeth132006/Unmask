import { defineConfig } from 'wxt';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  srcDir: '.',
  modules: ['@wxt-dev/module-react'],
  vite: () => ({
    plugins: [tailwindcss()],
  }),
  manifest: {
    name: 'Unmask — Phishing Email Inspector',
    short_name: 'Unmask',
    description:
      'See what a suspicious email is really hiding: real sender, real links, hidden text and attachment checks.',
    permissions: ['storage', 'tabs'],
    host_permissions: [
      'https://mail.google.com/*',
      'https://www.virustotal.com/*',
      'https://urlscan.io/*',
    ],
    action: {
      default_title: 'Open Unmask',
    },
  },
});
