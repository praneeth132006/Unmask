import { browser } from 'wxt/browser';
import { analyzeRawEmail } from '../../src/core/analyze';
import { decodeImageInBrowser } from '../../src/lib/imageDecode';
import { slimReport } from '../../src/lib/slimReport';
import type { AnalyzeRequest, AnalyzeResponse } from '../../src/lib/messages';

/**
 * Chrome offscreen document (purpose: DOM_PARSER). Used only when a mail page
 * blocks HTML parsing in the content script: the background worker forwards
 * the raw email here and returns the verdict. Runs locally, sends nothing.
 */
browser.runtime.onMessage.addListener((req: AnalyzeRequest & { target?: string }, sender, sendResponse) => {
  if (req?.type !== 'unmask:analyze' || req.target !== 'offscreen' || sender.id !== browser.runtime.id) return;
  analyzeRawEmail(req.raw, { history: req.history, decodeImage: decodeImageInBrowser }).then(
    (report) => sendResponse({ ok: true, report: slimReport(report) } satisfies AnalyzeResponse),
    (err: unknown) => sendResponse({ ok: false, error: err instanceof Error ? err.message : String(err) } satisfies AnalyzeResponse),
  );
  return true;
});
