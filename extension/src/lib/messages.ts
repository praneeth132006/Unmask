/** Messages exchanged between the Gmail content script and the side panel. */

export interface GmailMessageRef {
  /** Gmail's permanent message id, e.g. "msg-f:1780954093844218223". */
  permId: string | null;
  /** Legacy hex id used by older "Show original" URLs. */
  legacyId: string | null;
  fromName: string;
  fromEmail: string;
  subject: string;
}

export interface GmailState {
  accountIndex: string;
  messages: GmailMessageRef[];
}

export type PanelRequest =
  | { type: 'unmask:get-state' }
  | { type: 'unmask:fetch-raw'; message: GmailMessageRef }
  /** Outline the part of the open email a finding refers to; target null clears it. */
  | { type: 'unmask:highlight'; message: GmailMessageRef; target: import('./highlight').HighlightTarget | null }
  /** Open Gmail's own "Report phishing" for this message; Gmail then asks the user to confirm. */
  | { type: 'unmask:report-phishing'; message: GmailMessageRef };

export type ReportPhishingResponse = { ok: true } | { ok: false; error: string };

export type FetchRawResponse =
  | { ok: true; raw: string; via: string }
  | { ok: false; error: string; /** What each URL attempt returned, for the "technical details" box. */ attempts?: { label: string; outcome: string }[] };

/** Content script → background: fetch a Gmail URL with extension privileges (no CORS) when the page fetch fails. */
export interface BackgroundFetchRequest {
  type: 'unmask:bg-fetch';
  url: string;
}
export type BackgroundFetchResponse =
  | { ok: true; status: number; finalUrl: string; contentType: string; body: string }
  | { ok: false; error: string };

/** Broadcast by the content script whenever the open email changes. */
export interface StateChanged {
  type: 'unmask:state-changed';
  state: GmailState;
}

/** Side panel → background: trace a link's redirects with the built-in tracer. */
export interface TraceRequest {
  type: 'unmask:trace';
  url: string;
}
export type TraceResponse = { ok: true; result: import('../integrations/trace').TraceResult } | { ok: false; error: string };
