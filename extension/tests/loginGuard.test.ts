import { describe, expect, it } from 'vitest';
import { checkLoginPage } from '../src/lib/loginGuard';

const page = (host: string, title: string, text = '', hasPassword = true, formTarget: string | null = null) => ({ host, title, text, hasPassword, formTarget });

describe('fake sign-in pages anywhere', () => {
  it('warns on a look-alike domain with a password box', () => {
    const w = checkLoginPage(page('paypa1-secure.top', 'Log in to your PayPal account'));
    expect(w?.brand).toBe('PayPal');
    expect(w?.realDomains).toContain('paypal.com');
    expect(w?.reasons.join(' ')).toMatch(/paypa1-secure\.top/);
  });
  it('warns when an unrelated site claims to be Microsoft sign-in', () => {
    const w = checkLoginPage(page('docs-share-portal.net', 'Sign in to your account', 'Microsoft · Sign in · Enter password'));
    expect(w?.brand).toBe('Microsoft');
  });
  it('mentions where the form sends the password', () => {
    const w = checkLoginPage(page('paypa1-login.com', 'PayPal login', '', true, 'collect.evil.example'));
    expect(w?.reasons.join(' ')).toMatch(/evil\.example/);
  });
  it('stays quiet on the real site, without a password box, and on "Sign in with Google"', () => {
    expect(checkLoginPage(page('www.paypal.com', 'Log in to your PayPal account'))).toBeNull();
    expect(checkLoginPage(page('login.microsoftonline.com', 'Sign in to your Microsoft account'))).toBeNull();
    expect(checkLoginPage(page('paypa1-secure.top', 'PayPal', '', false))).toBeNull();
    expect(checkLoginPage(page('notion.so', 'Log in to Notion', 'Continue with Google · Continue with Apple · Password'))).toBeNull();
    expect(checkLoginPage(page('localhost', 'PayPal login'))).toBeNull();
  });
});
