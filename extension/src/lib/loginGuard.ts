/**
 * "Warn on fake sign-in pages anywhere": on a page with a password box, is
 * the site pretending to be a brand it isn't? Decided only from the page's
 * own address, title and headings, on this device. Pure, so it is tested
 * without a browser.
 */
import { BRANDS, brandOwningDomain, brandsMentionedIn, isBrandDomain, type Brand } from '../analyzers/brands';
import { detectLookalike } from '../analyzers/lookalike';
import { registrableDomain } from './domain';

export interface PageFacts {
  host: string;
  title: string;
  /** Headings, button labels, logo alt text and the form's nearby text. */
  text: string;
  hasPassword: boolean;
  /** The form posts to another site. */
  formTarget?: string | null;
}

export interface LoginWarning {
  brand: string;
  realDomains: string[];
  reasons: string[];
}

/** Sites people sign in to with a brand's account (Sign in with Google…) aren't impersonating it. */
const SSO_WORDS = /\b(?:(?:sign|log) ?(?:in|up)|continue|connect) (?:with|using|via) [\p{L}\d]+(?: [\p{L}\d]+)?/giu;

export function checkLoginPage(p: PageFacts, brands: Brand[] = BRANDS): LoginWarning | null {
  if (!p.hasPassword) return null;
  const host = p.host.toLowerCase().replace(/^www\./, '');
  if (!host || /^(localhost|\d+\.\d+\.\d+\.\d+)$/.test(host) || host.endsWith('.localhost') || host.endsWith('.test')) return null;
  const reg = registrableDomain(host);
  if (brandOwningDomain(reg)) return null;

  const reasons: string[] = [];
  const look = detectLookalike(host, brands);
  let brand: Brand | null = look?.brand ?? null;
  if (look) reasons.push(`The address ${host} ${look.explanation}.`);

  const claim = `${p.title} ${p.text.replace(SSO_WORDS, ' ')}`;
  const claimed = brandsMentionedIn(claim).filter((b) => !isBrandDomain(b, reg));
  if (!brand && claimed.length && /\b(sign ?in|log ?in|password|verify|account)\b/i.test(claim)) brand = claimed[0]!;
  if (brand && claimed.some((b) => b.name === brand!.name)) reasons.push(`The page says it is ${brand.name}, but this site isn’t one of ${brand.name}’s.`);
  if (!brand) return null;
  if (p.formTarget) {
    const to = registrableDomain(p.formTarget);
    if (to && to !== reg && !isBrandDomain(brand, to)) reasons.push(`What you type is sent to ${to}.`);
  }
  if (!reasons.length) return null;
  return { brand: brand.name, realDomains: brand.domains.slice(0, 2), reasons };
}
