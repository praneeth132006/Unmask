import { analyzeRawEmail } from '../src/core/analyze';
import { buildOutlookRaw, isOutlookUrl, OUTLOOK_SITE, readOutlookState } from '../src/lib/outlookDom';
import { startProtection } from '../src/lib/gmailProtect';
import { BANNER_ATTR } from '../src/lib/inpage';
import { EMPTY_HISTORY } from '../src/analyzers/history';

/** Roughly how Outlook on the web lays out an open message. */
const OWA = `
<div role="main">
  <div role="heading" aria-level="2">Your account is on hold</div>
  <div class="item">
    <div class="header"><button><span title="security@paypa1-support.xyz">PayPal Security</span></button></div>
    <div><div class="rps_1f2e"><div class="x_body"><p>Verify within 24 hours.</p>
      <a href="https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fpaypa1-secure.top%2Flogin&amp;data=x">https://www.paypal.com</a></div></div></div>
  </div>
</div>`;

describe('Outlook on the web', () => {
  afterEach(() => (document.body.innerHTML = ''));

  it('recognises Outlook hosts', () => {
    expect(isOutlookUrl('https://outlook.office.com/mail/inbox/id/AAMk')).toBe(true);
    expect(isOutlookUrl('https://outlook.live.com/mail/0/')).toBe(true);
    expect(isOutlookUrl('https://evil.com/outlook.live.com')).toBe(false);
  });

  it('finds the open message, its sender and subject', () => {
    document.body.innerHTML = OWA;
    const state = readOutlookState(document);
    expect(state.messages).toHaveLength(1);
    expect(state.messages[0]).toMatchObject({ fromEmail: 'security@paypa1-support.xyz', fromName: 'PayPal Security', subject: 'Your account is on hold' });
    // Stable key across re-reads.
    expect(readOutlookState(document).messages[0]!.permId).toBe(state.messages[0]!.permId);
  });

  it('rebuilds an email the normal analysis understands', async () => {
    document.body.innerHTML = OWA;
    const [ref] = readOutlookState(document).messages;
    const raw = buildOutlookRaw(document, ref!)!;
    const report = await analyzeRawEmail(raw);
    expect(report.email.from?.address).toBe('security@paypa1-support.xyz');
    expect(report.links[0]).toMatchObject({ host: 'paypa1-secure.top', unwrappedVia: ['Microsoft Safe Links'] });
    const ids = report.findings.map((f) => f.id);
    expect(ids).toEqual(expect.arrayContaining(['link-text-mismatch', 'sender-lookalike', 'auth-missing']));
    expect(report.findings.find((f) => f.id === 'auth-missing')?.points).toBe(0);
  });

  it('shows the banner inside Outlook too', async () => {
    document.body.innerHTML = OWA;
    const p = startProtection({
      site: OUTLOOK_SITE,
      doc: document,
      win: window,
      readState: () => readOutlookState(document),
      fetchRaw: async (ref) => ({ ok: true, raw: buildOutlookRaw(document, ref)!, via: 'page' }),
      analyze: (raw) => analyzeRawEmail(raw),
      settings: () => ({ gmailBanner: true, inboxBadges: false, clickProtection: true, senderHistory: false }),
      loadHistory: async () => EMPTY_HISTORY,
      rememberSender: async () => {},
      loadVerdicts: async () => ({}),
      saveVerdicts: async () => {},
      debounceMs: 10,
    });
    for (let i = 0; i < 100 && !document.querySelector(`[${BANNER_ATTR}]`); i++) await new Promise((r) => setTimeout(r, 20));
    const banner = document.querySelector(`[${BANNER_ATTR}]`);
    expect(banner?.nextElementSibling?.className).toBe('rps_1f2e');
    p.stop();
  });
});
