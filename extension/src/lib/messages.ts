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
  | { type: 'unmask:fetch-raw'; message: GmailMessageRef };

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
