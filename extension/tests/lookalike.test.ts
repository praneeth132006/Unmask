import { detectLookalike, skeleton, levenshtein } from '../src/analyzers/lookalike';

describe('lookalike detection', () => {
  it('normalises confusable characters', () => {
    expect(skeleton('pаypal')).toBe('paypal'); // Cyrillic а
    expect(skeleton('paypa1')).toBe('paypal');
    expect(skeleton('rnicrosoft')).toBe('microsoft');
  });

  it('computes edit distance', () => {
    expect(levenshtein('amazon', 'amazn')).toBe(1);
    expect(levenshtein('github', 'github')).toBe(0);
  });

  it.each([
    ['paypa1.com', 'PayPal', 'homoglyph'],
    ['xn--pypal-4ve.com', 'PayPal', 'homoglyph'],
    ['rnicrosoft.com', 'Microsoft', 'homoglyph'],
    ['arnazon.com', 'Amazon', 'homoglyph'],
    ['amazn.com', 'Amazon', 'typo'],
    ['paypal-secure-login.com', 'PayPal', 'brand-in-domain'],
    ['paypa1-support.xyz', 'PayPal', 'homoglyph'],
    ['paypal.com.account-verify.net', 'PayPal', 'brand-in-subdomain'],
  ])('flags %s as %s (%s)', (host, brand, kind) => {
    const m = detectLookalike(host);
    expect(m?.brand.name).toBe(brand);
    expect(m?.kind).toBe(kind);
  });

  it.each(['paypal.com', 'www.paypal.com', 'mail.google.com', 'github.com', 'example.com', 'stackoverflow.com', 'amazon.co.uk', 'docs.github.com'])(
    'does not flag %s',
    (host) => {
      expect(detectLookalike(host)).toBeNull();
    },
  );
});
