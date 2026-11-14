/** The sender history is saved in this browser only, learns link habits and hours, and never learns high-risk senders. */
const local: Record<string, unknown> = {};

vi.mock('wxt/browser', () => ({
  browser: {
    storage: {
      local: {
        get: async (k: string) => (k in local ? { [k]: local[k] } : {}),
        set: async (o: Record<string, unknown>) => void Object.assign(local, o),
        remove: async (k: string) => void delete local[k],
      },
    },
  },
}));

const { analyzeRawEmail } = await import('../src/core/analyze');
const store = await import('../src/lib/historyStore');

const raw = (body: string) => ['Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=friend.example; dkim=pass header.d=friend.example; dmarc=pass header.from=friend.example', 'From: Pat <pat@friend.example>', 'To: me@example.org', 'Subject: Hi', 'Date: Wed, 11 Nov 2026 03:40:00 +0100', 'Message-ID: <a1@friend.example>', 'Content-Type: text/plain', '', body].join('\r\n');

beforeEach(() => {
  for (const k of Object.keys(local)) delete local[k];
});

describe('sender history store', () => {
  it('remembers the sender with their link habit and the hour on their own clock', async () => {
    await store.rememberSender(await analyzeRawEmail(raw('Lunch on Friday?')));
    const rec = (await store.loadHistory()).senders['pat@friend.example'];
    expect(rec?.count).toBe(1);
    expect(rec?.traits?.link).toEqual({ none: 1 });
    expect(rec?.traits?.hour).toEqual({ night: 1 });
  });

  it('never learns a high-risk sender, and forgets everything on request', async () => {
    const report = await analyzeRawEmail(raw('Lunch on Friday?'));
    await store.rememberSender({ ...report, verdict: 'high' });
    expect(store.historySize(await store.loadHistory())).toBe(0);
    await store.rememberSender(report);
    await store.clearHistory();
    expect(store.historySize(await store.loadHistory())).toBe(0);
  });
});
