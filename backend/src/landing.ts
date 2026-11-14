/**
 * What the page at the end of a redirect chain looks like, read from its HTML
 * without running it. Kept identical to backend/src/landing.ts (a test checks
 * that the two files match).
 *
 * Phishing kits in 2025-2026 (Tycoon2FA, EvilProxy, Evilginx and their
 * clones) put a CAPTCHA in front of a fake Microsoft or Google sign-in page so
 * security scanners never reach it, and many relay the real sign-in page
 * through their own server to steal the session, which defeats MFA. Real
 * sign-in pages only live on their owners' domains, so the same page on any
 * other host is the giveaway.
 */

export interface LandingReport {
  /** The CAPTCHA service on the page, e.g. "Cloudflare Turnstile". */
  captcha: string | null;
  /** A sign-in page imitating this brand, on a host the brand doesn't own. */
  fakeLogin: string | null;
  /** The brand's own sign-in page markup, relayed from a host it doesn't own (adversary-in-the-middle). */
  relayedLogin: string | null;
  /** The page asks for a password. */
  passwordField: boolean;
  host: string;
}

const CAPTCHAS: [RegExp, string][] = [
  [/challenges\.cloudflare\.com\/turnstile|class\s*=\s*["'][^"']*\bcf-turnstile\b/i, 'Cloudflare Turnstile'],
  [/hcaptcha\.com\/1\/api\.js|class\s*=\s*["'][^"']*\bh-captcha\b/i, 'hCaptcha'],
  [/(?:www\.google\.com|www\.recaptcha\.net)\/recaptcha\/|class\s*=\s*["'][^"']*\bg-recaptcha\b/i, 'Google reCAPTCHA'],
  [/\b(?:verify (?:that )?(?:you are|you're) (?:a )?human|i'?m not a robot|human verification|checking (?:if the site connection is secure|your browser))\b/i, 'a "prove you are human" check'],
];

interface LoginBrand {
  name: string;
  /** Hosts (and their subdomains) where the brand's real sign-in page lives. */
  owns: string[];
  /** Words and assets a page imitating its sign-in uses. */
  looks: RegExp;
  /** Markup only the brand's own servers produce: seen on another host, the page is being relayed. */
  relayed: RegExp;
}

const BRANDS: LoginBrand[] = [
  {
    name: 'Microsoft',
    owns: ['microsoftonline.com', 'microsoftonline-p.com', 'live.com', 'microsoft.com', 'office.com', 'office365.com', 'msauth.net', 'msftauth.net', 'cloud.microsoft', 'microsoft365.com', 'outlook.com', 'sharepoint.com'],
    looks: /aadcdn\.(?:msauth|msftauth)\.net|logincdn\.msauth\.net|login\.microsoftonline\.com|sign in to your account|(?:microsoft|office ?365|outlook|onedrive|sharepoint)[^<]{0,80}(?:sign in|log ?in|password)|name\s*=\s*["']loginfmt["']/i,
    relayed: /\$Config\s*=\s*\{[^]{0,4000}?"(?:urlPost|sCanaryTokenName|urlMsaSignUp)"|ConvergedSignIn|"sFT"\s*:\s*"|"canary"\s*:\s*"[A-Za-z0-9_-]{40,}/,
  },
  {
    name: 'Google',
    owns: ['google.com', 'gstatic.com', 'youtube.com', 'googleusercontent.com'],
    looks: /accounts\.google\.com|ssl\.gstatic\.com\/accounts|sign in\s*[-–]\s*google accounts|id\s*=\s*["']identifierId["']|(?:gmail|google)[^<]{0,60}(?:sign in|password)/i,
    relayed: /gstatic\.com\/_\/mss\/boq-identity|data-initial-sign-in-data|"identifierId"[^]{0,400}?jsname=/,
  },
  {
    name: 'Okta',
    owns: ['okta.com', 'oktapreview.com', 'okta-emea.com', 'oktacdn.com'],
    looks: /okta-sign-in|ok\d+static\.oktacdn\.com|okta[^<]{0,40}sign in/i,
    relayed: /var\s+oktaData\s*=|"orgSyncToAccountChooserEnabled"/,
  },
];

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

const owned = (host: string, domains: string[]) => domains.some((d) => host === d || host.endsWith(`.${d}`));

export function inspectLanding(html: string, url: string): LandingReport {
  const page = html.slice(0, 512 * 1024);
  const host = hostOf(url);
  const captcha = CAPTCHAS.find(([re]) => re.test(page))?.[1] ?? null;
  const passwordField = /<input\b[^>]{0,400}type\s*=\s*["']?password/i.test(page);
  let fakeLogin: string | null = null;
  let relayedLogin: string | null = null;
  for (const b of BRANDS) {
    if (owned(host, b.owns)) continue;
    if (b.relayed.test(page)) {
      relayedLogin = b.name;
      break;
    }
    // Brand words alone are everywhere ("Sign in with Microsoft"); they count with a login form or a CAPTCHA gate.
    if (!fakeLogin && b.looks.test(page) && (passwordField || captcha || /<input\b[^>]{0,400}type\s*=\s*["']?email|name\s*=\s*["'](?:login|email|username|loginfmt|identifier)["']/i.test(page))) fakeLogin = b.name;
  }
  return { captcha, fakeLogin, relayedLogin, passwordField, host };
}
