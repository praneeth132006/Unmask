import { blockedReason, findClientRedirect } from '../src/lib/redirects';
import { traceBuiltin, type TraceEnv } from '../src/lib/builtinTrace';

describe('blockedReason', () => {
  it.each([
    'http://localhost/x',
    'http://router.local/',
    'http://127.0.0.1/',
    'http://10.0.0.5/',
    'http://192.168.1.1/admin',
    'http://172.20.1.1/',
    'http://169.254.169.254/latest/meta-data',
    'http://[::1]/',
    'http://[fd00::1]/',
    'http://example.com:22/',
    'file:///etc/passwd',
    'javascript:alert(1)',
  ])('blocks %s', (url) => expect(blockedReason(url)).not.toBeNull());

  it.each(['https://example.com/', 'http://8.8.8.8/', 'https://bit.ly/abc', 'http://example.com:8080/x'])('allows %s', (url) => expect(blockedReason(url)).toBeNull());
});

describe('findClientRedirect', () => {
  it('finds meta refresh and JS redirects, ignoring relative JS', () => {
    expect(findClientRedirect('<meta http-equiv="refresh" content="0; url=https://a.top/x">')?.target).toBe('https://a.top/x');
    expect(findClientRedirect('<script>location.replace("https://b.top/y")</script>')).toEqual({ target: 'https://b.top/y', via: 'javascript' });
    expect(findClientRedirect('<script>location.href = "#top"</script>')).toBeNull();
  });

  it('is linear on crafted input', () => {
    const t = performance.now();
    expect(findClientRedirect('<meta '.repeat(60_000))).toBeNull();
    expect(performance.now() - t).toBeLessThan(300);
  });
});

describe('traceBuiltin', () => {
  /** A fake fetch + webRequest pair that simulates two HTTP redirects. */
  function env(): TraceEnv {
    type L = (d: { requestId: string; url: string; tabId: number; initiator?: string; statusCode?: number; redirectUrl?: string }) => void;
    const req: L[] = [];
    const red: L[] = [];
    return {
      origin: 'chrome-extension://abc',
      onBeforeRequest: { addListener: (cb) => req.push(cb), removeListener: (cb) => req.splice(req.indexOf(cb), 1) },
      onBeforeRedirect: { addListener: (cb) => red.push(cb), removeListener: (cb) => red.splice(red.indexOf(cb), 1) },
      fetch: (async (url: string) => {
        const base = { requestId: '7', tabId: -1, initiator: 'chrome-extension://abc' };
        req.forEach((cb) => cb({ ...base, url }));
        red.forEach((cb) => cb({ ...base, url, statusCode: 301, redirectUrl: 'https://track.example/c' }));
        red.forEach((cb) => cb({ ...base, url: 'https://track.example/c', statusCode: 302, redirectUrl: 'https://final.example/' }));
        const res = new Response('<h1>hi</h1>', { status: 200, headers: { 'content-type': 'text/html' } });
        Object.defineProperty(res, 'url', { value: 'https://final.example/' });
        return res;
      }) as typeof fetch,
    };
  }

  it('records each redirect hop and the final page', async () => {
    const r = await traceBuiltin(env(), 'https://short.example/a');
    expect(r.hops.map((h) => [h.url, h.status])).toEqual([
      ['https://short.example/a', 301],
      ['https://track.example/c', 302],
      ['https://final.example/', 200],
    ]);
    expect(r.finalUrl).toBe('https://final.example/');
  });

  it('refuses to start on a local address', async () => {
    expect((await traceBuiltin(env(), 'http://192.168.0.1/')).error).toMatch(/local network/);
  });
});
