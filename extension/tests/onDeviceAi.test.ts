import { analyzeRawEmail } from '../src/core/analyze';
import { aiAvailability, aiFindings, buildPrompt, languageModel, outputLanguage, parseReading, readWithAi, SCHEMA, type LanguageModelLike } from '../src/lib/onDeviceAi';

const bec = ['Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass header.from=gmail.com', 'From: "Dana Whitfield" <dana.whitfield.ceo@gmail.com>', 'To: me@example.org', 'Subject: quick one', 'Content-Type: text/plain', '', 'Hi, are you at your desk? I am stuck in a meeting and need you to handle something for me before 3pm. Reply here.'].join('\r\n');

function fake(answer: string, availability: Awaited<ReturnType<LanguageModelLike['availability']>> = 'available') {
  const calls: { prompt: string; opts?: object; created?: object }[] = [];
  const lm: LanguageModelLike = {
    availability: async () => availability,
    create: async (created) => ({
      prompt: async (prompt, opts) => { calls.push({ prompt, opts, created }); return answer; },
      destroy: () => {},
    }),
  };
  return { lm, calls };
}

describe('on-device AI', () => {
  it('is absent where Chrome has no built-in model, and unavailable on errors', async () => {
    expect(languageModel()).toBeNull();
    expect(await aiAvailability(null)).toBe('unavailable');
    expect(await aiAvailability({ availability: async () => { throw new Error('x'); }, create: async () => { throw new Error('x'); } })).toBe('unavailable');
  });

  it('answers in a language the model supports, else English', () => {
    expect(outputLanguage('es-MX')).toBe('es');
    expect(outputLanguage('hi-IN')).toBe('en');
    expect(outputLanguage(undefined)).toBe('en');
  });

  it('asks for structured output, and sends the email text only to the local model', async () => {
    const r = await analyzeRawEmail(bec);
    const { lm, calls } = fake(JSON.stringify({ asks: ['reply-with-information', 'pay-money'], urgent: true, pretendsToBe: 'Dana Whitfield', explanation: 'Your boss would not ask from Gmail. Call them before doing anything.' }));
    const reading = await readWithAi(lm, r, 'en');
    expect(calls[0]!.opts).toMatchObject({ responseConstraint: SCHEMA });
    expect(calls[0]!.created).toMatchObject({ expectedOutputs: [{ type: 'text', languages: ['en'] }] });
    expect(calls[0]!.prompt).toContain('stuck in a meeting');
    expect(reading).toMatchObject({ asks: ['reply-with-information', 'pay-money'], urgent: true });
  });

  it('adds one capped finding for a request the local checks missed', async () => {
    const r = await analyzeRawEmail(bec);
    const f = aiFindings({ asks: ['pay-money'], urgent: true, pretendsToBe: 'Dana', explanation: '' }, r);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ id: 'ai-intent', severity: 'medium', points: 12 });
    // Nothing for "just informs", and nothing twice for what the local checks already caught.
    expect(aiFindings({ asks: ['nothing'], urgent: false, pretendsToBe: '', explanation: '' }, r)).toEqual([]);
    const caught = { ...r, findings: [...r.findings, { id: 'bec-gift-card', category: 'content' as const, severity: 'high' as const, points: 22, title: 'x' }] };
    expect(aiFindings({ asks: ['buy-gift-cards'], urgent: true, pretendsToBe: '', explanation: '' }, caught)).toEqual([]);
  });

  it('only notes it, with no points, for a verified sender you know', async () => {
    const r = await analyzeRawEmail(bec);
    const known = { ...r, auth: { ...r.auth, dmarc: 'pass' as const }, findings: [...r.findings, { id: 'known-sender', category: 'sender' as const, severity: 'good' as const, points: -5, title: 'x' }] };
    expect(aiFindings({ asks: ['sign-in'], urgent: true, pretendsToBe: '', explanation: '' }, known)[0]).toMatchObject({ severity: 'info', points: 0 });
  });

  it('ignores answers that are not the expected JSON', () => {
    expect(parseReading('not json')).toBeNull();
    expect(parseReading(JSON.stringify({ asks: ['steal-everything', 'sign-in'], urgent: 'yes', explanation: 42 }))).toEqual({ asks: ['sign-in'], urgent: false, pretendsToBe: '', explanation: '' });
  });

  it('puts the checks already done in the prompt, so the model explains rather than guesses', async () => {
    const r = await analyzeRawEmail(bec);
    const p = buildPrompt(r, 'fr');
    expect(p).toContain('two short sentences in French');
    expect(p).toContain('Subject: quick one');
  });
});
