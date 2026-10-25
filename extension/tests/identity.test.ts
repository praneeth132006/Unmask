import { analyzeRawEmail } from '../src/core/analyze';
import { fixture } from './helpers';

const ids = async (raw: string) => (await analyzeRawEmail(raw)).findings.map((f) => f.id);
const mail = (...headers: string[]) => `${headers.join('\n')}\n\nHello`;

describe('identity consistency', () => {
  it('spots a gmail.com address that never went through Gmail', async () => {
    const raw = mail('Authentication-Results: mx.google.com; dmarc=fail header.from=gmail.com', 'From: Boss <ceo.office@gmail.com>', 'Message-ID: <20261019.abc@vps-1234.example.net>', 'Subject: quick task');
    expect(await ids(raw)).toContain('webmail-forged');
    const real = mail('Authentication-Results: mx.google.com; dmarc=pass header.from=gmail.com', 'From: Boss <ceo.office@gmail.com>', 'Message-ID: <CAFx=abc@mail.gmail.com>', 'Subject: quick task');
    expect(await ids(real)).not.toContain('webmail-forged');
  });

  it('flags two From headers, spam tools and web scripts', async () => {
    expect(await ids(mail('From: a@example.com', 'Message-ID: <x.SMTPIN_ADDED_MISSING@mx.google.com>'))).toContain('message-id-missing');
    expect(await ids(mail('From: a@example.com', 'From: b@evil.top', 'Subject: x', 'Message-ID: <1@example.com>'))).toContain('multiple-from');
    expect(await ids(mail('From: a@example.com', 'X-Mailer: Leaf PHPMailer 2.7', 'Subject: x', 'Message-ID: <1@example.com>'))).toContain('mailer-spam-tool');
    const script = (await analyzeRawEmail(mail('From: "PayPal Security" <alert@pp-alerts.top>', 'X-PHP-Originating-Script: 33:mailer.php', 'Subject: x', 'Message-ID: <1@pp-alerts.top>'))).findings.find((f) => f.id === 'mailer-script');
    expect(script?.severity).toBe('medium');
  });

  it('flags a "Re:" that replies to nothing, not a real reply', async () => {
    expect(await ids(mail('From: a@example.com', 'Subject: RE: Invoice overdue', 'Message-ID: <1@example.com>'))).toContain('fake-reply');
    expect(await ids(mail('From: a@example.com', 'Subject: Re: lunch', 'In-Reply-To: <0@example.com>', 'Message-ID: <1@example.com>'))).not.toContain('fake-reply');
    expect(await ids(mail('From: a@example.com', 'Subject: Fwd: lunch', 'Message-ID: <1@example.com>'))).not.toContain('fake-reply');
  });

  it('notices a genuine brand email written for someone else', async () => {
    const raw = mail('Delivered-To: victim@example.org', 'Authentication-Results: mx.google.com; dkim=pass header.d=accounts.google.com; dmarc=pass header.from=accounts.google.com', 'From: Google <no-reply@accounts.google.com>', 'To: attacker123@gmail.com', 'Subject: Security alert', 'Message-ID: <x@accounts.google.com>');
    expect(await ids(raw)).toContain('replay-addressee');
    expect(await ids(raw.replace('Delivered-To: victim@example.org', 'Delivered-To: attacker123@gmail.com'))).not.toContain('replay-addressee');
  });

  it('stays quiet on the legitimate samples', async () => {
    for (const f of ['legit-newsletter.eml', 'marketing-newsletter.eml']) {
      const found = await ids(fixture(f));
      expect(found.filter((id) => ['multiple-from', 'webmail-forged', 'mailer-spam-tool', 'mailer-script', 'fake-reply', 'replay-addressee', 'message-id-missing'].includes(id))).toEqual([]);
    }
  });
});

describe('Unicode look-alikes and invisible characters', () => {
  it('uses Unicode confusables beyond the hand-made list', async () => {
    const { skeleton, detectLookalike } = await import('../src/analyzers/lookalike');
    const { toASCII } = await import('punycode/');
    expect(skeleton('ⲣaypal')).toBe('paypal'); // Coptic ⲣ
    expect(skeleton('Ꮲaypal')).toBe('paypal'); // Cherokee Ꮲ
    expect(detectLookalike(toASCII('ⲣaypal.com'))?.brand.name).toBe('PayPal');
  });

  it('flags a brand name spelt with Cyrillic letters or broken by zero-width spaces', async () => {
    const cyr = (await analyzeRawEmail(mail('From: "PаyPal Support" <help@pp-help.top>', 'Subject: hi', 'Message-ID: <1@pp-help.top>'))).findings.find((f) => f.id === 'disguised-from');
    expect(cyr).toMatchObject({ severity: 'medium', title: 'The sender name spells "PayPal" with disguised letters' });
    expect(await ids(mail('From: a@example.com', 'Subject: Net​flix payment failed', 'Message-ID: <1@example.com>'))).toContain('disguised-subject');
    expect(await ids(mail('From: "Zoë Müller" <z@example.de>', 'Subject: Grüße', 'Message-ID: <1@example.de>'))).not.toEqual(expect.arrayContaining(['disguised-from']));
  });
});
