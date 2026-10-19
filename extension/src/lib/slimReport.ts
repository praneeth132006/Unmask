import type { Report } from '../core/types';

/**
 * A report small enough to pass between extension contexts: attachment bytes
 * and the annotated HTML are dropped. Enough for banners, badges and the
 * link and reply checks.
 */
export function slimReport(r: Report): Report {
  return { ...r, annotatedHtml: null, email: { ...r.email, html: null, text: null, attachments: [] } };
}
