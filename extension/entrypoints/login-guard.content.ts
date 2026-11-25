import { defineContentScript } from 'wxt/utils/define-content-script';
import { checkLoginPage } from '../src/lib/loginGuard';
import { confirmDialog } from '../src/lib/inpage';

/**
 * Registered at run time, only while "Warn on fake sign-in pages anywhere" is on.
 * Looks for a password box and, if the site pretends to be a brand it isn't,
 * warns before anything is typed. Reads only this page; nothing is sent.
 */
export default defineContentScript({
  matches: ['https://*/*', 'http://*/*'],
  registration: 'runtime',
  main() {
    if (/(^|\.)(mail\.google\.com|outlook\.(live|office|office365)\.com|outlook\.cloud\.microsoft)$/.test(location.hostname)) return;
    const key = `unmask-login-guard:${location.hostname}`;
    try { if (sessionStorage.getItem(key)) return; } catch { /* private mode */ }
    let done = false;
    const look = () => {
      if (done) return;
      const pw = document.querySelector<HTMLInputElement>('input[type="password"]');
      if (!pw) return;
      done = true;
      observer.disconnect();
      const form = pw.form;
      let formTarget: string | null = null;
      try { formTarget = form?.action ? new URL(form.action, location.href).hostname : null; } catch { formTarget = null; }
      const text = [...document.querySelectorAll('h1, h2, h3, label, button, [role="heading"], img[alt], legend')]
        .slice(0, 60)
        .map((el) => (el instanceof HTMLImageElement ? el.alt : el.textContent ?? ''))
        .join(' · ')
        .slice(0, 2000);
      const w = checkLoginPage({ host: location.hostname, title: document.title, text, hasPassword: true, formTarget });
      if (!w) return;
      void confirmDialog(document, {
        title: `This isn’t ${w.brand}’s sign-in page`,
        target: location.hostname,
        reasons: [...w.reasons, `${w.brand}’s real sign-in is on ${w.realDomains.join(' or ')}.`],
        proceedLabel: 'I trust this site',
        cancelLabel: 'Leave this page',
        note: 'Don’t type your password here. If you already did, change it on the real site.',
      }).then((stay) => {
        if (stay) {
          try { sessionStorage.setItem(key, '1'); } catch { /* ignore */ }
          return;
        }
        if (history.length > 1) history.back();
        else location.replace('about:blank');
      });
    };
    const observer = new MutationObserver(() => look());
    observer.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => observer.disconnect(), 15000);
    look();
  },
});
