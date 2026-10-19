/**
 * Gmail enforces Trusted Types. Depending on the browser version that can
 * also block DOMParser in extension content scripts, which the analyzers
 * need. This first checks whether parsing works; if not, it tries a Trusted
 * Types policy used only by Unmask's own isolated world. Returns false when
 * the page forbids both, so the caller can analyze somewhere else.
 */
let state: boolean | null = null;

function parses(): boolean {
  try {
    new DOMParser().parseFromString('<p>ok</p>', 'text/html');
    return true;
  } catch {
    return false;
  }
}

export function ensureHtmlParsing(): boolean {
  if (state !== null) return state;
  // Test builds can force the fallback path (VITE_UNMASK_FORCE_REMOTE=1).
  if (import.meta.env.VITE_UNMASK_FORCE_REMOTE === '1') return (state = false);
  if (parses()) return (state = true);
  const tt = (globalThis as unknown as { trustedTypes?: { createPolicy(name: string, rules: { createHTML(s: string): string }): { createHTML(s: string): unknown } } }).trustedTypes;
  try {
    const policy = tt?.createPolicy('unmask-analysis', { createHTML: (s) => s });
    if (policy) {
      // Content scripts have their own copy of the DOM prototypes, so this changes nothing for the page.
      const original = DOMParser.prototype.parseFromString;
      DOMParser.prototype.parseFromString = function (this: DOMParser, html: string, type: DOMParserSupportedType) {
        return original.call(this, policy.createHTML(html) as string, type);
      };
    }
  } catch {
    // The page's CSP doesn't allow our policy name.
  }
  return (state = parses());
}
