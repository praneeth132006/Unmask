/**
 * Accuracy corpus. Legitimate links and senders must stay clean (no high or
 * critical flags, no brand claims); real phishing patterns must still be
 * caught. Add every false alarm or miss reported by users here.
 */
import { inspectLink } from '../src/analyzers/links';
import { detectLookalike } from '../src/analyzers/lookalike';
import { brandsMentionedIn } from '../src/analyzers/brands';
import { analyzeRawEmail } from '../src/core/analyze';

const serious = (flags: { severity: string }[]) => flags.filter((f) => f.severity === 'high' || f.severity === 'critical');
const brandFlags = (flags: { id: string }[]) => flags.filter((f) => f.id === 'lookalike' || f.id === 'brand-in-domain');

const LEGIT_LINKS = [
  'https://research.meta.ai/blog/muse-spark-open',
  'https://ai.meta.com/llama/',
  'https://about.fb.com/news/',
  'https://www.threads.net/@zuck',
  'https://www.google.co.in/search?q=x',
  'https://accounts.google.com/signin',
  'https://mail.google.com/mail/u/0/',
  'https://www.amazon.in/gp/your-account/order-history',
  'https://www.amazon.de/dp/B0',
  'https://aws.amazon.com/console/',
  'https://www.apple.com/in/iphone/',
  'https://apps.apple.com/app/id1',
  'https://apple.co/3abc',
  'https://support.microsoft.com/en-us/account',
  'https://learn.microsoft.com/azure',
  'https://www.bing.com/search?q=x',
  'https://www.linkedin.com/jobs/view/1',
  'https://github.com/praneeth132006/Unmask/pull/1',
  'https://www.paypal.com/myaccount/summary',
  'https://www.paypal.de/signin',
  'https://www.netflix.com/browse',
  'https://www.youtube.com/watch?v=1',
  'https://x.com/home',
  'https://zoom.us/j/123',
  'https://us02web.zoom.us/j/123',
  'https://app.slack.com/client/T1',
  'https://www.dropbox.com/s/abc',
  'https://www.icicibank.com/personal-banking',
  'https://www.hdfcbank.com/',
  'https://www.onlinesbi.sbi/',
  'https://www.flipkart.com/account',
  'https://www.airtel.in/',
  'https://www.jio.com/selfcare',
  'https://www.ups.com/track?tracknum=1',
  'https://www.fedex.com/fedextrack',
  'https://www.dhl.com/in-en/home.html',
  'https://www.chase.com/personal',
  'https://store.steampowered.com/app/1',
  'https://open.spotify.com/track/1',
  'https://www.ebay.com/itm/1',
  'https://www.irs.gov/refunds',
  'https://www.coinbase.com/price',
  'https://wise.com/in/send-money',
  'https://medium.com/@x/post',
  'https://www.reddit.com/r/TeenIndia',
  'https://groww.in/stocks',
  'https://www.screener.in/company/TCS/',
  'https://www.educative.io/courses/x',
  'https://economictimes.indiatimes.com/markets',
  'https://www.hindustantimes.com/india-news',
  'https://www.bbc.co.uk/news',
  'https://vercel.com/dashboard',
  // Ordinary sites whose names contain everyday words that are also brands.
  'https://www.applebees.com/',
  'https://apple-farm-orchard.com/',
  'https://www.wise-owl.org/',
  'https://steam-cleaning.co.uk/',
  'https://www.zoominfo.com/',
  'https://finance-weekly.com/markets',
  'https://www.morton-salt.com/',
  'https://chase-thompson.dev/',
  'https://www.metabase.com/',
  'https://meta-analysis.org/',
  'https://cloud.google.com/',
  'https://revolt.tv/',
];

const PHISHING_LINKS = [
  'https://paypa1.com/signin',
  'https://xn--pypal-4ve.com/verify',
  'https://amazn.com/account',
  'https://apple-id-verify.top/login',
  'https://chase-secure-login.com/',
  'https://micros0ft-login.click/',
  'https://binance-support.top/',
  'https://revolut-verify.xyz/',
  'https://meta-support-center.com/appeal',
  'https://secure-zoom-verify.top/',
  'https://paypal.com.account-verify.top/',
  'https://www.paypal-security-alert.com/',
  'https://faceb00k.com/login',
  'https://netfliix.com/billing',
];

describe('accuracy: legitimate links stay clean', () => {
  it.each(LEGIT_LINKS)('%s', (href) => {
    const l = inspectLink({ href, text: href, source: 'html' });
    expect(brandFlags(l.flags)).toEqual([]);
    expect(serious(l.flags)).toEqual([]);
  });

  it('does not read file names as websites (CLAUDE.md, setup.py)', () => {
    for (const text of ['CLAUDE.md', 'README.md', 'setup.py', 'index.ts', 'report.pdf']) {
      const l = inspectLink({ href: 'https://link.mail.beehiiv.com/v2/c/abc', text, source: 'html' });
      expect(l.flags.filter((f) => f.id === 'text-mismatch' || f.id === 'tracker-mismatch')).toEqual([]);
    }
    // A real domain in the text is still compared.
    const l = inspectLink({ href: 'https://evil.top/x', text: 'www.paypal.com', source: 'html' });
    expect(l.flags.map((f) => f.id)).toContain('text-mismatch');
  });
});

describe('accuracy: phishing links are still caught', () => {
  it.each(PHISHING_LINKS)('%s', (href) => {
    const l = inspectLink({ href, text: '', source: 'html' });
    expect(brandFlags(l.flags).length + l.flags.filter((f) => f.id === 'punycode').length).toBeGreaterThan(0);
  });
});

describe('accuracy: brand claims in sender names', () => {
  it('ignores everyday words used as names', () => {
    for (const name of ['Chase Thompson', 'Apple Tree Nursery', 'Zoom Car', 'Steam Cleaning Co', 'Slack Line Club', 'Meta Analysis Weekly', 'Kip Boyle via LinkedIn', 'Margaret with GuruFocus', 'AI Finance Community', 'Wise Owl Tutors']) {
      expect(brandsMentionedIn(name).map((b) => b.name).filter((b) => b !== 'LinkedIn')).toEqual([]);
    }
  });
  it('still sees official-sounding brand names', () => {
    expect(brandsMentionedIn('Chase Bank Alerts').map((b) => b.name)).toEqual(['Chase']);
    expect(brandsMentionedIn('Apple Support').map((b) => b.name)).toEqual(['Apple']);
    expect(brandsMentionedIn('Apple').map((b) => b.name)).toEqual(['Apple']);
    expect(brandsMentionedIn('PayPal Service').map((b) => b.name)).toEqual(['PayPal']);
    expect(brandsMentionedIn('Amazon.in Customer Service').map((b) => b.name)).toContain('Amazon');
  });
  it('no lookalike for big brands’ own country and product domains', () => {
    for (const d of ['google.co.in', 'amazon.de', 'paypal.de', 'meta.ai', 'apple.co', 'amazon.co.uk']) expect(detectLookalike(d)).toBeNull();
  });
});

/** Emails like the ones in a real inbox: authenticated newsletters and notifications. */
const INBOX: [string, string, string][] = [
  ['vercel[bot]', 'notifications@github.com', '<a href="https://vercel.com/dashboard">Visit Preview</a>'],
  ['Kip Boyle via LinkedIn', 'newsletters-noreply@linkedin.com', '<a href="https://www.linkedin.com/pulse/x">Read</a>'],
  ['That1AI Newsletter', 'that1ai@mail.beehiiv.com', '<a href="https://link.mail.beehiiv.com/v2/c/abc">CLAUDE.md</a> <a href="https://research.meta.ai/blog/muse-spark-open">https://research.meta.ai/blog/muse-spark-open</a>'],
  ['Reddit', 'noreply@redditmail.com', '<a href="https://www.reddit.com/r/TeenIndia">Hiii</a>'],
  ['Margaret with GuruFocus', 'margaret@gurufocus.com', '<a href="https://www.gurufocus.com/news">News</a>'],
  ['Groww Digest', 'digest@groww.in', '<a href="https://groww.in/stocks">Stocks</a>'],
  ['AI Finance Community', 'hello@aifinance.community', '<a href="https://finance-weekly.com/markets">Markets</a>'],
  ['BBC News Briefing', 'newsletters@bbc.co.uk', '<a href="https://www.bbc.co.uk/news">News</a>'],
  ['The Economic Times', 'newsletter@economictimes.com', '<a href="https://economictimes.indiatimes.com/markets">Markets</a>'],
  ['Fahim at Educative', 'fahim@educative.io', '<a href="https://www.educative.io/courses/x">Course</a>'],
  ['Medium Daily Digest', 'noreply@medium.com', '<a href="https://medium.com/@x/post">Post</a>'],
  ['Google', 'no-reply@accounts.google.com', '<a href="https://accounts.google.com/signin">Check activity</a>'],
  ['ICICI Bank', 'credit_cards@icicibank.com', '<a href="https://www.icicibank.com/personal-banking">Details</a>'],
];

describe('accuracy: everyday inbox emails are not flagged', () => {
  it.each(INBOX)('%s <%s>', async (name, address, body) => {
    const domain = address.split('@')[1]!;
    const raw = [
      `Authentication-Results: mx.google.com; dkim=pass header.d=${domain}; spf=pass smtp.mailfrom=${domain}; dmarc=pass header.from=${domain}`,
      `From: "${name}" <${address}>`,
      'To: me@example.com',
      'Subject: Your weekly update',
      'Content-Type: text/html; charset=utf-8',
      '',
      `<p>Hello,</p><p>${body}</p>`,
    ].join('\r\n');
    const r = await analyzeRawEmail(raw);
    expect(serious(r.findings)).toEqual([]);
    expect(r.verdict).toBe('clear');
  });
});
