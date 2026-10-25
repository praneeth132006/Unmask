import { analyzeRawEmail } from '../src/core/analyze';
import { analystReport, buildJsonReport, buildPdfReport, composeUrl, defang, indicatorText, suspiciousUrls, urlReportPage } from '../src/lib/reporting';
import { buildPdf } from '../src/lib/pdf';
import { reportPhishingInGmail } from '../src/lib/gmailActions';
import { fixture } from './helpers';

const latin = (b: Uint8Array) => Array.from(b, (c) => String.fromCharCode(c)).join('');

describe('reports', () => {
  it('defangs URLs', () => {
    expect(defang('https://paypa1.com/a.b')).toBe('hxxps://paypa1[.]com/a[.]b');
  });

  it('builds a JSON report with indicators', async () => {
    const r = await analyzeRawEmail(fixture('phishing-paypal.eml'));
    const json = buildJsonReport(r, '1.2.3', new Date('2026-10-19T00:00:00Z'));
    expect(json).toMatchObject({ version: '1.2.3', verdict: 'high', email: { subject: r.email.subject } });
    expect(json.indicators.urls.length).toBeGreaterThan(0);
    expect(json.indicators.urls).toEqual(suspiciousUrls(r, 50));
    expect(JSON.parse(JSON.stringify(json)).authentication.raw).toBeUndefined();
  });

  it('writes an analyst write-up in SOC order, with defanged indicators', async () => {
    const r = await analyzeRawEmail(fixture('phishing-paypal.eml'));
    const text = analystReport(r, '1.2.3', new Date('2026-10-19T00:00:00Z'));
    const order = ['## Verdict', '## Message', '## Authentication', '## Delivery path', '## Findings', '## Indicators', '## Not checked', '## Recommended actions'].map((h) => text.indexOf(h));
    expect(order.every((n, i) => n > 0 && (i === 0 || n > order[i - 1]!))).toBe(true);
    expect(text).toContain('Impersonation (high confidence)');
    const iocs = indicatorText(r);
    expect(iocs).toContain('sender\tbilling[@]paypa1-support[.]xyz');
    expect(iocs).toContain('reply-to\tsecure-team[@]protonmail[.]com');
    expect(iocs).toContain('origin-ip\t185[.]220[.]101[.]4');
    expect(iocs).toMatch(/^url\thxxps:\/\//m);
    expect(iocs).not.toMatch(/https?:\/\//);
  });

  it('writes a structurally valid PDF', async () => {
    const r = await analyzeRawEmail(fixture('phishing-paypal.eml'));
    const pdf = latin(buildPdfReport(r, '1.2.3'));
    expect(pdf.startsWith('%PDF-1.4')).toBe(true);
    expect(pdf.trimEnd().endsWith('%%EOF')).toBe(true);
    // Every xref offset must point at "N 0 obj".
    const xrefAt = Number(pdf.match(/startxref\n(\d+)/)![1]);
    const entries = pdf.slice(xrefAt).split('\n').slice(3).filter((l) => / n $/.test(l));
    entries.forEach((e, i) => expect(pdf.slice(Number(e.slice(0, 10)), Number(e.slice(0, 10)) + 12)).toMatch(new RegExp(`^${i + 1} 0 obj`)));
    expect(pdf).toContain('Unmask email report');
    expect(pdf).toContain('hxxp');
  });

  it('paginates long reports and keeps text Latin-1', () => {
    const pdf = latin(buildPdf(Array.from({ length: 200 }, (_, i) => ({ kind: 'text' as const, text: `Line ${i} → “quoted” 日本` })), 'footer'));
    expect(Number(pdf.match(/\/Count (\d+)/)![1])).toBeGreaterThan(2);
    expect(pdf).toContain('Line 5 -> "quoted" ??');
  });

  it('prefills report destinations', async () => {
    const r = await analyzeRawEmail(fixture('phishing-paypal.eml'));
    const gmail = new URL(composeUrl('apwg', r, '1'));
    expect(gmail.pathname).toBe('/mail/u/1/');
    expect(gmail.searchParams.get('to')).toBe('reportphishing@apwg.org');
    expect(gmail.searchParams.get('body')).toContain('Suspicious URLs (defanged)');
    expect(composeUrl('netcraft', r, null)).toMatch(/^mailto:scam@netcraft\.com\?subject=/);
    expect(urlReportPage('google', 'https://x.top/a?b=1')).toBe('https://safebrowsing.google.com/safebrowsing/report_phish/?url=https%3A%2F%2Fx.top%2Fa%3Fb%3D1');
  });
});

describe("Gmail's report phishing menu", () => {
  const ref = { permId: 'msg-f:1', legacyId: null, fromName: '', fromEmail: '', subject: '' };

  it('opens the ⋮ menu and picks "Report phishing"', async () => {
    document.body.innerHTML = '<div data-message-id="#msg-f:1"><div role="button" aria-label="More message options"></div><div class="a3s">body</div></div>';
    let reported = false;
    document.querySelector('[aria-label="More message options"]')!.addEventListener('mousedown', () => {
      const menu = document.createElement('div');
      menu.setAttribute('role', 'menu');
      menu.innerHTML = '<div role="menuitem">Block sender</div><div role="menuitem">Report phishing</div>';
      menu.lastElementChild!.addEventListener('click', () => (reported = true));
      document.body.appendChild(menu);
    });
    expect(await reportPhishingInGmail(document, ref)).toEqual({ ok: true });
    expect(reported).toBe(true);
  });

  it('explains what to do when the menu is missing', async () => {
    document.body.innerHTML = '<div data-message-id="#msg-f:1"><div class="a3s">body</div></div>';
    const r = await reportPhishingInGmail(document, ref);
    expect(r.ok).toBe(false);
  });
});
