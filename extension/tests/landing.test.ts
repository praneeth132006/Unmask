import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { inspectLanding } from '../src/lib/landing';
import { landingFindings } from '../src/analyzers/landing';

const MS_FAKE = '<html><head><title>Sign in to your account</title></head><body><img src="https://aadcdn.msauth.net/shared/1.0/content/images/microsoft_logo.svg"><form><input type="email" name="loginfmt"><input type="password" name="passwd"></form></body></html>';
const TURNSTILE = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script><div class="cf-turnstile" data-sitekey="0x4AAA"></div>';
// Microsoft's real sign-in page carries its own $Config with urlPost and a long canary; a reverse proxy passes it on unchanged.
const MS_RELAYED = '<html><head><title>Sign in to your account</title></head><body><script>//<![CDATA[\n$Config={"fShowPersistentCookiesWarning":false,"urlMsaSignUp":"https://login.live.com/oauth20_authorize.srf","urlPost":"/common/login","sCanaryTokenName":"canary","canary":"' + 'A'.repeat(60) + '"};\n//]]></script></body></html>';

describe('landing page', () => {
  it('spots a fake Microsoft sign-in behind Turnstile on a stranger’s host', () => {
    const r = inspectLanding(TURNSTILE + MS_FAKE, 'https://secure-doc-view.top/s/ab12');
    expect(r).toEqual({ captcha: 'Cloudflare Turnstile', fakeLogin: 'Microsoft', relayedLogin: null, passwordField: true, host: 'secure-doc-view.top' });
    const [f] = landingFindings(2, r);
    expect(f).toMatchObject({ id: 'landing-fake-login-2', severity: 'critical', target: { kind: 'links', indexes: [2] } });
    expect(f!.title).toBe('Lands on a fake Microsoft sign-in page at secure-doc-view.top, behind Cloudflare Turnstile');
  });

  it('spots Microsoft’s own sign-in code relayed through another host (adversary in the middle)', () => {
    const r = inspectLanding(MS_RELAYED, 'https://login.microsoftonline.com.auth-session.top/common/oauth2');
    expect(r.relayedLogin).toBe('Microsoft');
    expect(landingFindings(0, r)[0]).toMatchObject({ severity: 'critical', points: 40 });
  });

  it('trusts the real sign-in pages on their own domains', () => {
    expect(inspectLanding(MS_RELAYED, 'https://login.microsoftonline.com/common/oauth2')).toMatchObject({ fakeLogin: null, relayedLogin: null });
    expect(inspectLanding(MS_FAKE, 'https://login.live.com/')).toMatchObject({ fakeLogin: null, relayedLogin: null });
    const google = '<title>Sign in - Google Accounts</title><input type="email" id="identifierId"><script src="https://www.gstatic.com/_/mss/boq-identity/_/js/k=boq"></script>';
    expect(inspectLanding(google, 'https://accounts.google.com/v3/signin')).toMatchObject({ fakeLogin: null, relayedLogin: null });
    expect(inspectLanding(google, 'https://accounts-google.com-verify.click/v3/signin').relayedLogin).toBe('Google');
  });

  it('does not call an ordinary page with a "Sign in with Microsoft" button a fake login', () => {
    const shop = '<a href="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=1">Sign in with Microsoft</a><p>Welcome to our shop</p>';
    expect(landingFindings(0, inspectLanding(shop, 'https://shop.example/'))).toEqual([]);
  });

  it('notes a CAPTCHA on its own lightly, and a password page behind one strongly', () => {
    expect(landingFindings(1, inspectLanding(TURNSTILE + '<p>Checking your browser</p>', 'https://x.example/'))[0]).toMatchObject({ severity: 'low', points: 5 });
    expect(landingFindings(1, inspectLanding('<div class="h-captcha"></div><input type="password">', 'https://x.example/'))[0]).toMatchObject({ severity: 'high' });
    expect(landingFindings(1, undefined)).toEqual([]);
  });

  it('stays identical to the backend copy', () => {
    const a = readFileSync(join(__dirname, '../src/lib/landing.ts'), 'utf8');
    const b = readFileSync(join(__dirname, '../../backend/src/landing.ts'), 'utf8');
    expect(b).toBe(a);
  });
});
