import { analyzeTrackers, serviceForUrl } from '../src/analyzers/trackers';
import { analyzeRawEmail } from '../src/core/analyze';
import type { LinkInfo } from '../src/core/types';
import { fixture } from './helpers';

const link = (href: string): LinkInfo => ({ href, text: '', resolved: href, unwrappedVia: [], host: new URL(href).hostname, domain: '', scheme: 'https', source: 'html', flags: [] });

describe('serviceForUrl', () => {
  it.each([
    ['https://u123.ct.sendgrid.net/wf/open?upn=x', 'SendGrid'],
    ['https://acme.us5.list-manage.com/track/open.php?u=1', 'Mailchimp'],
    ['https://mailtrack.io/trace/mail/abc.png', 'Mailtrack'],
    ['https://r.superhuman.com/abc.gif', 'Superhuman'],
    ['https://www.facebook.com/tr?id=1&ev=PageView', 'Meta Pixel'],
    ['https://t.yesware.com/t/abc', 'Yesware'],
  ])('%s → %s', (url, name) => expect(serviceForUrl(url)).toBe(name));

  it('returns null for ordinary sites', () => {
    expect(serviceForUrl('https://github.com/logo.png')).toBeNull();
  });
});

describe('analyzeTrackers', () => {
  it('finds 1×1, hidden, tracking-path and background pixels but not real images', () => {
    const html = `
      <img src="https://cdn.example.com/logo.png" width="120" height="40">
      <img src="https://t.example.net/x.gif" width="1" height="1">
      <img src="https://img.example.org/a.png" style="display:none">
      <img src="https://news.example.com/open/abc123">
      <img src="https://mailtrack.io/trace/mail/abc.png" style="width:0px;height:0px">
      <table><tr><td style="background-image:url('https://u1.ct.sendgrid.net/wf/open?upn=z')"></td></tr></table>`;
    const { trackers, findings } = analyzeTrackers(html, [link('https://u1.ct.sendgrid.net/ls/click?upn=a'), link('https://github.com/x')]);
    expect(trackers.pixels.map((p) => p.reason)).toEqual([
      '1×1 pixel image',
      'hidden image',
      'image at a tracking address',
      '0×0 pixel image',
      'background image from a tracking address',
    ]);
    expect(trackers.remoteImages).toBe(5);
    expect(trackers.trackedLinkCount).toBe(1);
    expect(trackers.services).toEqual(['Mailtrack', 'SendGrid']);
    expect(findings.map((f) => [f.id, f.points])).toEqual([['tracking-pixel', 0], ['tracked-links', 0]]);
  });

  it('reports nothing for an email without remote content', () => {
    expect(analyzeTrackers('<p>Hello</p>', []).findings).toEqual([]);
  });

  it('runs inside the full pipeline without changing the score', async () => {
    const r = await analyzeRawEmail(fixture('marketing-newsletter.eml'));
    expect(r.trackers.pixels).toHaveLength(1);
    expect(r.trackers.services).toEqual(['SendGrid']);
    expect(r.verdict).toBe('clear');
  });
});
