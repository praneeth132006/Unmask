/**
 * Drives Gmail's own menus for actions Unmask offers, such as "Report
 * phishing". Gmail's class names change often, so everything is found by
 * ARIA roles, labels and visible text. Gmail shows its own confirmation
 * dialog afterwards, so the user always confirms the final step.
 */
import type { GmailMessageRef, ReportPhishingResponse } from './messages';
import { findMessageRoot } from './highlight';

/** Gmail menus open on mousedown/mouseup, not just click. */
export function press(el: Element): void {
  const view = el.ownerDocument.defaultView;
  for (const type of ['mouseover', 'mousedown', 'mouseup', 'click']) {
    el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: view ?? undefined }));
  }
}

function visible(el: Element): boolean {
  const r = (el as HTMLElement).getBoundingClientRect?.();
  return !r || r.width > 0 || r.height > 0;
}

/** Gmail keeps hidden copies of some controls; prefer one that is on screen. */
function pick(list: Element[]): Element | null {
  return list.find(visible) ?? list[0] ?? null;
}

async function waitFor<T>(find: () => T | null, ms = 2000, step = 50): Promise<T | null> {
  for (let t = 0; t <= ms; t += step) {
    const v = find();
    if (v) return v;
    await new Promise((r) => setTimeout(r, step));
  }
  return null;
}

const MORE_BUTTON = '[aria-label="More message options" i], [aria-label="More" i][role="button"], [data-tooltip="More" i][role="button"], [aria-label="More options" i][role="button"]';

export async function reportPhishingInGmail(doc: Document, ref: GmailMessageRef): Promise<ReportPhishingResponse> {
  const root = findMessageRoot(doc, ref);
  if (!root) return { ok: false, error: 'Open the email in Gmail first.' };
  const more = pick(Array.from(root.querySelectorAll(MORE_BUTTON)));
  if (!more) return { ok: false, error: 'Could not find the ⋮ menu on this email. In Gmail, open ⋮ → "Report phishing".' };
  press(more);
  const item = await waitFor(() =>
    pick(Array.from(doc.querySelectorAll('[role="menuitem"]')).filter((el) => /report phishing/i.test(el.textContent ?? ''))),
  );
  if (!item) {
    doc.body.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    return { ok: false, error: 'Gmail’s menu has no "Report phishing" item for this email. In Gmail, open ⋮ → "Report phishing".' };
  }
  press(item);
  return { ok: true };
}
