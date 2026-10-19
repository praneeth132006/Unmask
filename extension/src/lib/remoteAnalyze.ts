import { browser } from 'wxt/browser';
import { analyzeRawEmail } from '../core/analyze';
import type { Report } from '../core/types';
import type { SenderHistory } from '../analyzers/history';
import type { AnalyzeRequest, AnalyzeResponse } from './messages';
import { ensureHtmlParsing } from './htmlParsing';
import { decodeImageInBrowser } from './imageDecode';

/**
 * Analyzes in the content script when the page allows HTML parsing, and
 * otherwise in an extension-owned page via the background worker.
 */
export async function analyzeInPage(raw: string, history: SenderHistory | undefined): Promise<Report> {
  if (ensureHtmlParsing()) return analyzeRawEmail(raw, { history, decodeImage: decodeImageInBrowser });
  const res = (await browser.runtime.sendMessage({ type: 'unmask:analyze', raw, history } satisfies AnalyzeRequest)) as AnalyzeResponse | undefined;
  if (!res?.ok) throw new Error(res?.error ?? 'Unmask could not analyze this email here.');
  return res.report;
}
