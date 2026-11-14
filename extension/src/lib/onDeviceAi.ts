/**
 * Reading the email with Chrome's built-in model (Gemini Nano, the Prompt
 * API). It runs on this computer: nothing is sent anywhere. Off by default,
 * and only offered where Chrome has the model (desktop Chrome 138+ with enough
 * memory and disk); Firefox and other browsers never see it.
 *
 * It does not try to tell whether a text was written by AI: most phishing is
 * now, and so is a lot of real mail. It reads what the email asks you to do
 * (pay, change bank details, sign in, call a number…) and explains the
 * verdict in plain words. Its findings are capped at Medium, so the model on
 * its own can never make an email "High risk".
 * Docs: https://developer.chrome.com/docs/ai/prompt-api
 */
import type { Finding, Report } from '../core/types';

export const ASKS = ['pay-money', 'change-bank-details', 'buy-gift-cards', 'sign-in', 'share-code-or-password', 'share-personal-details', 'call-a-number', 'install-or-run-something', 'open-attachment', 'reply-with-information', 'nothing'] as const;
export type Ask = (typeof ASKS)[number];

export interface AiReading {
  asks: Ask[];
  urgent: boolean;
  pretendsToBe: string;
  explanation: string;
}

export type AiAvailability = 'unavailable' | 'downloadable' | 'downloading' | 'available';

/** The parts of Chrome's LanguageModel that Unmask uses. */
export interface LanguageModelLike {
  availability(opts?: object): Promise<AiAvailability>;
  create(opts?: object): Promise<{ prompt(input: string, opts?: { responseConstraint?: object; signal?: AbortSignal }): Promise<string>; destroy(): void }>;
}

/** Languages the model reads and writes today. */
const LANGS = ['en', 'es', 'de', 'fr', 'ja'] as const;

export function languageModel(): LanguageModelLike | null {
  const lm = (globalThis as { LanguageModel?: LanguageModelLike }).LanguageModel;
  return lm && typeof lm.availability === 'function' && typeof lm.create === 'function' ? lm : null;
}

export function outputLanguage(locale: string | undefined): (typeof LANGS)[number] {
  const l = (locale ?? 'en').slice(0, 2).toLowerCase();
  return (LANGS as readonly string[]).includes(l) ? (l as (typeof LANGS)[number]) : 'en';
}

const sessionOptions = (lang: string) => ({
  expectedInputs: [{ type: 'text', languages: ['en', ...(lang === 'en' ? [] : [lang])] }],
  expectedOutputs: [{ type: 'text', languages: [lang] }],
});

export async function aiAvailability(lm: LanguageModelLike | null, lang = 'en'): Promise<AiAvailability> {
  if (!lm) return 'unavailable';
  try {
    return await lm.availability(sessionOptions(lang));
  } catch {
    return 'unavailable';
  }
}

export const SCHEMA = {
  type: 'object',
  properties: {
    asks: { type: 'array', items: { type: 'string', enum: [...ASKS] }, maxItems: 5 },
    urgent: { type: 'boolean' },
    pretendsToBe: { type: 'string', maxLength: 60 },
    explanation: { type: 'string', maxLength: 400 },
  },
  required: ['asks', 'urgent', 'pretendsToBe', 'explanation'],
  additionalProperties: false,
} as const;

const LANG_NAME: Record<string, string> = { en: 'English', es: 'Spanish', de: 'German', fr: 'French', ja: 'Japanese' };

export function buildPrompt(report: Report, lang: string): string {
  const from = report.email.from;
  const flags = report.findings.filter((f) => f.points > 0).slice(0, 6).map((f) => `- ${f.title}`).join('\n') || '- none';
  const verdict = { high: 'High risk', suspicious: 'Suspicious', clear: 'No red flags found' }[report.verdict];
  return [
    'You help an ordinary person decide whether an email is a scam. Read the email below and answer in JSON.',
    '"asks": what the email wants the reader to do, from the allowed list ("nothing" if it only informs).',
    '"urgent": true if it pressures the reader to act fast or threatens a consequence.',
    '"pretendsToBe": the company or person it claims to be from, or "" if none.',
    `"explanation": two short sentences in ${LANG_NAME[lang] ?? 'English'}, in everyday words, saying why the verdict "${verdict}" fits and what to do. Do not invent facts that are not in the email or the checks.`,
    '',
    `Checks already done on this computer found:\n${flags}`,
    '',
    `From: ${from ? `${from.name} <${from.address}>` : 'unknown'}`,
    `Subject: ${report.email.subject.slice(0, 200)}`,
    'Body:',
    report.previewText.slice(0, 3000) || '(no text)',
  ].join('\n');
}

export function parseReading(text: string): AiReading | null {
  try {
    const v = JSON.parse(text) as Partial<AiReading>;
    const asks = Array.isArray(v.asks) ? v.asks.filter((a): a is Ask => (ASKS as readonly string[]).includes(a)) : [];
    return { asks: [...new Set(asks)], urgent: v.urgent === true, pretendsToBe: typeof v.pretendsToBe === 'string' ? v.pretendsToBe.slice(0, 60) : '', explanation: typeof v.explanation === 'string' ? v.explanation.slice(0, 400) : '' };
  } catch {
    return null;
  }
}

export async function readWithAi(lm: LanguageModelLike, report: Report, lang: string, signal?: AbortSignal): Promise<AiReading | null> {
  const session = await lm.create({ ...sessionOptions(lang), signal });
  try {
    return parseReading(await session.prompt(buildPrompt(report, lang), { responseConstraint: SCHEMA, signal }));
  } finally {
    session.destroy();
  }
}

/** Intents, and the local findings that already cover each one. */
const INTENTS: { asks: Ask[]; label: string; plain: string; covered: RegExp }[] = [
  { asks: ['change-bank-details', 'pay-money', 'buy-gift-cards'], label: 'asks you to send money, change bank details or buy gift cards', plain: 'It asks for money or payment details.', covered: /^(bec-|money-lure|job-scam|callback|platform-abuse)/ },
  { asks: ['sign-in', 'share-code-or-password'], label: 'asks you to sign in or share a code or password', plain: 'It asks you to sign in or share a code.', covered: /^(credential-request|html-form|link-lookalike|link-text-mismatch|device-code|oauth-consent|qr-code|landing-|calendar-lure)/ },
  { asks: ['call-a-number'], label: 'asks you to phone a number', plain: 'It asks you to phone a number.', covered: /^(callback|calendar-callback|platform-abuse)/ },
  { asks: ['install-or-run-something'], label: 'asks you to install or run something', plain: 'It asks you to install or run something.', covered: /^(clickfix|attachment-|link-download)/ },
  { asks: ['share-personal-details'], label: 'asks for personal or identity details', plain: 'It asks for personal details.', covered: /^(job-scam|credential-request)/ },
];

/**
 * Turns a reading into at most one finding: a risky request the local checks
 * didn't already catch. Medium at most, and only a note for senders you know
 * and that were verified, so the model alone never decides a verdict.
 */
export function aiFindings(reading: AiReading | null, report: Report): Finding[] {
  if (!reading) return [];
  // Only a finding with real weight counts as caught: a 3-point "are you at your desk?" note doesn't cover a money request.
  const has = (re: RegExp) => report.findings.some((f) => f.points >= 10 && re.test(f.id));
  const known = report.findings.some((f) => f.id === 'known-sender' || (f.id === 'trusted-sender' && f.points < 0));
  const intent = INTENTS.find((i) => i.asks.some((a) => reading.asks.includes(a)) && !has(i.covered));
  if (!intent) return [];
  const mild = known && report.auth.dmarc === 'pass';
  return [
    {
      id: 'ai-intent',
      category: 'content',
      severity: mild ? 'info' : reading.urgent ? 'medium' : 'low',
      points: mild ? 0 : reading.urgent ? 12 : 6,
      title: `On-device AI: the email ${intent.label}${reading.urgent ? ', with pressure to act fast' : ''}`,
      detail: `Chrome’s built-in model read the email on this computer (nothing was sent). ${reading.pretendsToBe ? `It claims to be from ${reading.pretendsToBe}. ` : ''}Check any such request with the sender another way, using a number or address you already have.`,
      plain: intent.plain,
      target: { kind: 'body' },
    },
  ];
}
