/**
 * Rule fuzzing: every YAML rule must survive the small changes scammers make
 * (case, spacing, line endings, HTML, padding, a different sender) and must
 * stay quiet on a few hundred generated, ordinary emails that use the same
 * everyday words. Seeded, so a failure is reproducible.
 */
import { analyzeRawEmail } from '../src/core/analyze';
import { RULE_LIST } from '../src/analyzers/rules';

let seed = 1337;
const rand = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31);
const pick = <T,>(a: readonly T[]) => a[Math.floor(rand() * a.length)]!;

function split(example: string): { subject: string; body: string } {
  const [first, ...rest] = example.split('\n');
  return first!.startsWith('Subject:') ? { subject: first!.slice(8).trim(), body: rest.join('\n').replace(/^\n/, '') } : { subject: '', body: example };
}

function eml(subject: string, body: string, { html = false, from = 'Someone <someone@sender.example>' } = {}): string {
  const type = html ? 'text/html' : 'text/plain';
  const content = html ? `<div style="font-family:Arial">${body.split('\n').map((l) => `<p>${l.replace(/(https?:\/\/\S+)/g, '<a href="$1">$1</a>')}</p>`).join('')}</div>` : body;
  return [`From: ${from}`, 'To: me@example.org', `Subject: ${subject}`, `Content-Type: ${type}; charset=utf-8`, '', content].join('\r\n');
}

/** The ways a scam's text gets varied, keeping its meaning. */
const MUTATIONS: [string, (s: string, b: string) => [string, string, { html?: boolean; from?: string }?]][] = [
  ['upper case', (s, b) => [s.toUpperCase(), b.toUpperCase()]],
  ['lower case', (s, b) => [s.toLowerCase(), b.toLowerCase()]],
  ['double spaces', (s, b) => [s, b.replace(/ /g, '  ')]],
  ['Windows line endings', (s, b) => [s, b.replace(/\n/g, '\r\n')]],
  ['greeting and signature', (s, b) => [s, `Dear Customer,\n\n${b}\n\nRegards,\nCustomer Care Team`]],
  ['as HTML', (s, b) => [s, b, { html: true }]],
  ['different sender', (s, b) => [s, b, { from: '"Support" <support@notice-center.example>' }]],
  ['trailing noise', (s, b) => [`${s} [#${Math.floor(rand() * 9e5)}]`, `${b}\nRef: ${Math.floor(rand() * 9e9)}`]],
];

describe('rule fuzzing', () => {
  it.each(RULE_LIST.map((r) => [r.id, r] as const))('%s still fires on varied versions of its scam', async (id, r) => {
    const { subject, body } = split(r.examples.phish);
    const missed: string[] = [];
    for (const [name, mutate] of MUTATIONS) {
      const [s, b, opts] = mutate(subject, body);
      const report = await analyzeRawEmail(eml(s, b, opts));
      if (!report.findings.some((f) => f.id === `rule-${id}`)) missed.push(name);
    }
    expect(missed, `rule-${id} missed: ${missed.join(', ')}`).toEqual([]);
  });

  it('no rule fires on ordinary emails that use the same everyday words', async () => {
    const people = ['Priya', 'Tom', 'Ana', 'Wei', 'Sam', 'Fatima', 'Lukas'];
    const templates = [
      (n: string) => [`Your parcel was delivered`, `Hi ${n}, your package was delivered today at 2pm and left with reception. Thanks for shopping with us.`],
      (n: string) => [`Tax return received`, `Hello ${n}, we received your tax return for 2025. No action is needed. You can view the status in your account.`],
      (n: string) => [`Your KYC is complete`, `Dear ${n}, your KYC verification was completed successfully at the branch. Thank you for banking with us.`],
      (n: string) => [`Mailbox storage`, `Hi ${n}, you're using 40% of your mailbox storage. You don't need to do anything.`],
      (n: string) => [`Voicemail from the dentist`, `${n}, the dentist left a voicemail to confirm your appointment on Thursday. Call back if you need to change it.`],
      (n: string) => [`Crypto meetup on Friday`, `Hey ${n}, the bitcoin meetup is at 7pm Friday at the library. Bring a friend!`],
      (n: string) => [`Inheritance paperwork`, `${n}, the solicitor sent the inheritance paperwork for grandma's house. Can we go through it on Sunday?`],
      (n: string) => [`Delivery rescheduled`, `Hi ${n}, as you asked, your delivery was rescheduled to Monday. No fee applies. Track it here: https://www.ups.com/track`],
      (n: string) => [`Refund issued`, `Hello ${n}, your refund of $24.99 has been issued to your card and should appear in 3-5 days.`],
      (n: string) => [`Password changed`, `${n}, your password was changed. If this was you, you can ignore this email.`],
      (n: string) => [`Team update`, `Hi all, ${n} here. The quarterly review is moved to the 24th. Please update your slides in the shared folder by Friday.`],
      (n: string) => [`School trip fee`, `Dear parents, the school trip fee of $15 is due by Friday. Pay at the office or through the parent portal as usual. — ${n}`],
    ];
    const fired: string[] = [];
    let n = 0;
    for (let i = 0; i < 300; i++) {
      const [s, b] = pick(templates)(pick(people));
      const report = await analyzeRawEmail(eml(s!, b!, { html: rand() < 0.4 }));
      n++;
      const hits = report.findings.filter((f) => f.id.startsWith('rule-')).map((f) => f.id);
      if (hits.length) fired.push(`${hits.join(',')} on "${s}"`);
    }
    expect(n).toBe(300);
    expect([...new Set(fired)], 'rules fired on ordinary emails').toEqual([]);
  }, 60_000);
});
