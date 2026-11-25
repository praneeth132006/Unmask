import { browser } from 'wxt/browser';
import type { PreviewLinkRequest, PreviewLinkResponse } from './messages';

/** Content script side of "Preview safely": the background runs the private scan with the user's key. */
export async function previewLink(url: string): Promise<{ image: string; caption: string } | { error: string; link?: string }> {
  try {
    const res = (await browser.runtime.sendMessage({ type: 'unmask:preview-link', url } satisfies PreviewLinkRequest)) as PreviewLinkResponse | undefined;
    if (!res) return { error: 'Unmask could not reach the sandbox. Try again.' };
    if (!res.ok) return { error: res.error, link: res.reportUrl };
    const where = res.finalUrl ? (() => { try { return new URL(res.finalUrl).hostname; } catch { return res.finalUrl; } })() : 'an unknown page';
    return { image: res.image, caption: `${res.malicious ? 'urlscan.io rates this page malicious. ' : ''}The link ended on ${where}. Taken in a sandbox: nothing was loaded in your browser.` };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}
