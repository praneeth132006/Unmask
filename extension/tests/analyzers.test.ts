import { parseEmail } from '../src/core/parse';
import { analyzeAuth, parseAuthResults } from '../src/analyzers/auth';
import { analyzeSender } from '../src/analyzers/sender';
import { analyzeContent } from '../src/analyzers/content';
import { analyzeLinks, inspectLink, unwrapUrl } from '../src/analyzers/links';
import { analyzeAttachments, isEncryptedZip } from '../src/analyzers/attachments';
import { fixture } from './helpers';

const ids = (fs: { id: string }[]) => fs.map((f) => f.id);

describe('auth', () => {
  it('parses Gmail and Outlook style headers', () => {
    const g = parseAuthResults('mx.google.com; dkim=pass header.i=@github.com header.s=x; spf=pass (comment; with semicolon) smtp.mailfrom=a@github.com; dmarc=pass (p=REJECT) header.from=github.com');
    expect(g.server).toBe('mx.google.com');
    expect(g.results.map((r) => `${r.method}=${r.result}`)).toEqual(['dkim=pass', 'spf=pass', 'dmarc=pass']);
    const o = parseAuthResults('spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=x.com; dkim=pass (signature was verified) header.d=x.com;dmarc=pass action=none header.from=x.com;compauth=pass reason=100');
    expect(o.server).toBeNull();
    expect(o.results.find((r) => r.method === 'dmarc')?.result).toBe('pass');
  });

  it('flags failures on the phishing sample', async () => {
    const { auth, findings } = analyzeAuth(await parseEmail(fixture('phishing-paypal.eml')));
    expect(auth).toMatchObject({ spf: 'softfail', dkim: 'none', dmarc: 'fail', dmarcDomain: 'paypa1-support.xyz' });
    expect(ids(findings)).toEqual(expect.arrayContaining(['dmarc-fail', 'spf-softfail', 'dkim-none']));
  });

  it('rewards a clean pass', async () => {
    const { auth, findings } = analyzeAuth(await parseEmail(fixture('legit-newsletter.eml')));
    expect(auth.dkimDomains).toEqual(['github.com']);
    expect(ids(findings)).toEqual(['dmarc-pass']);
  });
});

describe('sender', () => {
  it('catches display-name tricks, lookalikes and reply-to', async () => {
    const findings = analyzeSender(await parseEmail(fixture('phishing-paypal.eml')));
    expect(ids(findings)).toEqual(
      expect.arrayContaining(['display-name-email', 'sender-lookalike', 'reply-to-mismatch', 'return-path-mismatch']),
    );
    expect(findings.find((f) => f.id === 'reply-to-mismatch')?.severity).toBe('high'); // protonmail
  });

  it('is quiet for a legitimate sender', async () => {
    expect(analyzeSender(await parseEmail(fixture('legit-newsletter.eml')))).toEqual([]);
  });

  it('flags a brand writing from free webmail', async () => {
    const email = await parseEmail('From: "Netflix Billing" <netflix.billing2026@gmail.com>\nTo: a@b.com\nSubject: hi\n\nbody');
    expect(ids(analyzeSender(email))).toEqual(expect.arrayContaining(['brand-impersonation', 'freemail-org']));
  });
});

describe('content', () => {
  it('finds hidden text, pressure language and links', async () => {
    const r = analyzeContent(await parseEmail(fixture('phishing-paypal.eml')));
    expect(r.hidden.map((h) => h.reason)).toEqual(['display:none', 'text colour matches the background']);
    expect(r.annotatedHtml).toContain('data-unmask-hidden');
    expect(ids(r.findings)).toEqual(expect.arrayContaining(['hidden-text', 'urgency', 'credential-request']));
    expect(r.links.some((l) => l.text === 'https://www.paypal.com/signin')).toBe(true);
  });

  it('detects forms with password fields', async () => {
    const email = await parseEmail('From: a@b.com\nContent-Type: text/html\n\n<form action="https://x.top/p"><input type="password"></form>');
    expect(analyzeContent(email).findings.find((f) => f.id === 'html-form')?.severity).toBe('critical');
  });
});

describe('links', () => {
  it('unwraps redirect wrappers', () => {
    expect(unwrapUrl('https://www.google.com/url?q=https://evil.top/x&sa=D')).toEqual({ url: 'https://evil.top/x', via: ['Google redirect'] });
    expect(unwrapUrl('https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.top%2Fa&data=1').url).toBe('https://evil.top/a');
    expect(unwrapUrl('https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.top_login&d=x').url).toBe('https://evil.top/login');
  });

  it('flags a text/destination mismatch', () => {
    const l = inspectLink({ href: 'http://www.google.com/url?q=https://paypa1-secure.top/login', text: 'https://www.paypal.com/signin', source: 'html' });
    expect(l.resolved).toBe('https://paypa1-secure.top/login');
    expect(l.flags.map((f) => f.id)).toEqual(expect.arrayContaining(['text-mismatch', 'lookalike', 'suspicious-tld']));
  });

  it('treats mail trackers as low risk', () => {
    const l = inspectLink({ href: 'https://u123.ct.sendgrid.net/ls/click?upn=abc', text: 'www.github.com', source: 'html' });
    expect(l.flags.map((f) => f.id)).toEqual(['tracker-mismatch']);
  });

  it('aggregates findings for the phishing sample', async () => {
    const content = analyzeContent(await parseEmail(fixture('phishing-paypal.eml')));
    const { links, findings } = analyzeLinks(content.links);
    expect(links.length).toBeGreaterThanOrEqual(4);
    expect(ids(findings)).toEqual(
      expect.arrayContaining(['link-text-mismatch', 'link-lookalike', 'link-shortener', 'link-ip-host', 'link-punycode']),
    );
  });

  it('is quiet for legitimate links', async () => {
    const content = analyzeContent(await parseEmail(fixture('legit-newsletter.eml')));
    expect(analyzeLinks(content.links).findings).toEqual([]);
  });

  it('flags javascript: links', () => {
    expect(inspectLink({ href: 'javascript:alert(1)', text: 'Click', source: 'html' }).flags[0]?.id).toBe('dangerous-scheme');
  });
});

describe('attachments', () => {
  it('flags double-extension HTML attachments with password forms', async () => {
    const email = await parseEmail(fixture('phishing-paypal.eml'));
    const { attachments, findings } = await analyzeAttachments(email.attachments);
    expect(attachments[0]?.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(attachments[0]?.flags.map((f) => f.id)).toEqual(expect.arrayContaining(['html', 'double-extension', 'html-credential']));
    expect(findings[0]?.severity).toBe('critical');
  });

  it('detects encrypted zips and bidi tricks', async () => {
    const zip = new Uint8Array(40);
    zip.set([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x01, 0x00]);
    expect(isEncryptedZip(zip)).toBe(true);
    const { attachments } = await analyzeAttachments([
      { filename: 'invoice‮fdp.exe', mimeType: 'application/octet-stream', size: 1, disposition: 'attachment', related: false, content: new Uint8Array([1]) },
    ]);
    expect(attachments[0]?.flags.map((f) => f.id)).toEqual(expect.arrayContaining(['bidi', 'executable']));
  });
});

describe('false-positive tuning (from real inbox testing)', () => {
  it("does not flag the sender's own click-tracking redirect", () => {
    const own = inspectLink({ href: 'https://click.acme.com/r?url=https%3A%2F%2Fshop.example.org%2Fsale', text: 'Shop now', source: 'html' }, 'news.acme.com');
    expect(own.flags.map((f) => f.id)).not.toContain('open-redirect');
    const foreign = inspectLink({ href: 'https://click.acme.com/r?url=https%3A%2F%2Fshop.example.org%2Fsale', text: 'Shop now', source: 'html' }, 'other.net');
    expect(foreign.flags.map((f) => f.id)).toContain('open-redirect');
  });

  it('treats .html pages as pages, not downloads', () => {
    expect(inspectLink({ href: 'https://example.com/help/page.html', text: 'Help', source: 'html' }, '').flags).toEqual([]);
    expect(inspectLink({ href: 'https://example.com/files/x.zip', text: 'Get', source: 'html' }, '').flags.map((f) => f.id)).toEqual(['download']);
  });

  it('weights a single urgency phrase lightly', async () => {
    const one = analyzeContent(await parseEmail('From: a@b.com\nSubject: Update\n\nPlease review this immediately.'));
    expect(one.findings.find((f) => f.id === 'urgency')).toMatchObject({ severity: 'low', points: 5 });
  });

  it('does not score a short hidden preheader', async () => {
    const r = analyzeContent(await parseEmail('From: a@b.com\nContent-Type: text/html\n\n<div style="display:none">Your weekly digest is here</div><p>Hi</p>'));
    expect(r.findings.find((f) => f.id === 'hidden-text')?.points).toBe(0);
  });
});
