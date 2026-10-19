import { defineContentScript } from 'wxt/utils/define-content-script';

/**
 * Runs in Gmail's own JavaScript world (not the isolated content-script world)
 * for one reason: to read Gmail's per-session "ik" token from window.GLOBALS
 * and hand it to the isolated script through a DOM attribute. It reads
 * nothing else and sends nothing anywhere.
 */
export default defineContentScript({
  matches: ['https://mail.google.com/*'],
  world: 'MAIN',
  runAt: 'document_idle',
  main() {
    const publish = () => {
      const g = (window as unknown as { GLOBALS?: unknown[] }).GLOBALS;
      const ik = Array.isArray(g) && typeof g[9] === 'string' ? g[9] : null;
      if (ik) document.documentElement.setAttribute('data-unmask-ik', ik);
      return Boolean(ik);
    };
    if (!publish()) {
      // GLOBALS can appear a little after document_idle on slow loads.
      let tries = 0;
      const timer = setInterval(() => {
        if (publish() || ++tries > 20) clearInterval(timer);
      }, 500);
    }
  },
});
