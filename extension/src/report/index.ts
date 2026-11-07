/** Investigation reports in every format, all drawn from one model. */
import type { Report } from '../core/types';
import { buildCaseReport, type Audience, type CaseDoc, type Evidence, type ReportMeta } from './model';
import { renderDocx } from './docx';
import { renderHtml } from './html';
import { renderPdf } from './pdfWriter';
import { buildStixBundle } from './stix';

export { buildCaseReport, collectIocs, docText, autoCaseId, type Audience, type CaseDoc, type Evidence, type ReportMeta, type Tlp } from './model';
export { renderDocx } from './docx';
export { renderHtml } from './html';
export { renderPdf } from './pdfWriter';
export { buildStixBundle, stixPattern } from './stix';

export type ReportFormat = 'pdf' | 'docx' | 'html' | 'stix';

export const FORMAT_INFO: Record<ReportFormat, { label: string; ext: string; mime: string }> = {
  pdf: { label: 'PDF', ext: 'pdf', mime: 'application/pdf' },
  docx: { label: 'Word', ext: 'docx', mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' },
  html: { label: 'HTML', ext: 'html', mime: 'text/html' },
  stix: { label: 'STIX 2.1', ext: 'stix.json', mime: 'application/json' },
};

export interface BuildOptions {
  version: string;
  now?: Date;
  meta?: ReportMeta;
  audience?: Audience;
  evidence?: Evidence;
}

/** Builds the report in one format. */
export async function buildReportFile(report: Report, format: ReportFormat, opts: BuildOptions): Promise<{ data: BlobPart; mime: string; ext: string }> {
  const doc: CaseDoc = buildCaseReport(report, opts);
  const info = FORMAT_INFO[format];
  if (format === 'pdf') return { data: renderPdf(doc) as BlobPart, mime: info.mime, ext: info.ext };
  if (format === 'docx') return { data: renderDocx(doc) as BlobPart, mime: info.mime, ext: info.ext };
  if (format === 'html') return { data: renderHtml(doc), mime: info.mime, ext: info.ext };
  return { data: JSON.stringify(await buildStixBundle(report, doc, opts.now), null, 2), mime: info.mime, ext: info.ext };
}

/** The PDF report (executive and technical parts). */
export function buildPdfReport(report: Report, version: string, now = new Date(), meta?: ReportMeta, audience?: Audience, evidence?: Evidence): Uint8Array {
  return renderPdf(buildCaseReport(report, { version, now, meta, audience, evidence }));
}
