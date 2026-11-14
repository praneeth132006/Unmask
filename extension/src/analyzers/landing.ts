/**
 * Red flags from the page a link finally lands on, after "Trace redirects".
 * The page is read by the tracer (see lib/landing.ts); nothing here fetches.
 */
import type { Finding, FindingTarget } from '../core/types';
import type { LandingReport } from '../lib/landing';

export function landingFindings(index: number, landing: LandingReport | undefined): Finding[] {
  if (!landing) return [];
  const target: FindingTarget = { kind: 'links', indexes: [index] };
  const where = landing.host || 'the final page';
  const gate = landing.captcha ? `, behind ${landing.captcha}` : '';
  if (landing.relayedLogin) {
    return [
      {
        id: `landing-relay-${index}`,
        category: 'links',
        severity: 'critical',
        points: 40,
        title: `Relays the real ${landing.relayedLogin} sign-in page through ${where}${gate}`,
        detail: `The page at ${where} contains ${landing.relayedLogin}’s own sign-in code, which only ${landing.relayedLogin}’s servers produce. It is being passed through the attacker’s server (an adversary-in-the-middle kit such as Tycoon2FA or Evilginx), which captures your password and your session, so even MFA codes don’t protect you. Close it; if you signed in, change your password and sign out of all sessions.`,
        plain: `The link opens a copy of the ${landing.relayedLogin} login that steals your password and your login session.`,
        target,
      },
    ];
  }
  if (landing.fakeLogin) {
    return [
      {
        id: `landing-fake-login-${index}`,
        category: 'links',
        severity: 'critical',
        points: 35,
        title: `Lands on a fake ${landing.fakeLogin} sign-in page at ${where}${gate}`,
        detail: `The final page looks like ${landing.fakeLogin}’s sign-in${landing.passwordField ? ' and asks for a password' : ''}, but ${where} doesn’t belong to ${landing.fakeLogin}.${landing.captcha ? ` The ${landing.captcha} in front of it is there to keep security scanners out.` : ''}`,
        plain: `The link ends on a fake ${landing.fakeLogin} login page.`,
        target,
      },
    ];
  }
  if (landing.captcha && landing.passwordField) {
    return [{ id: `landing-captcha-${index}`, category: 'links', severity: 'high', points: 22, title: `Password page behind ${landing.captcha} at ${where}`, detail: 'Phishing kits put a "prove you are human" check in front of their login pages so security scanners can’t see them.', plain: 'The link ends on a login page hidden behind a CAPTCHA.', target }];
  }
  if (landing.captcha) {
    return [{ id: `landing-captcha-${index}`, category: 'links', severity: 'low', points: 5, title: `The final page shows ${landing.captcha}`, detail: 'A CAPTCHA can be normal, but phishing kits use one to hide their pages from scanners. Unmask could not see what is behind it.', target }];
  }
  return [];
}
