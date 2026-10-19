import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { findClientRedirect, traceUrl } from '../src/trace';
import { assertAllowedUrl, isBlockedAddress } from '../src/guard';
import { app } from '../src/app';

let server: Server;
let base = '';

beforeAll(async () => {
  server = createServer((req, res) => {
    const routes: Record<string, () => void> = {
      '/a': () => res.writeHead(301, { location: '/b' }).end(),
      '/b': () => res.writeHead(302, { location: `${base}/c` }).end(),
      '/c': () => res.writeHead(200, { 'content-type': 'text/html' }).end('<html><head><meta http-equiv="refresh" content="0; url=/d"></head></html>'),
      '/d': () => res.writeHead(200, { 'content-type': 'text/html' }).end('<script>window.location.href = "http://127.0.0.1:1/never"</script>'),
      '/loop': () => res.writeHead(302, { location: '/loop' }).end(),
      '/final': () => res.writeHead(200, { 'content-type': 'text/html' }).end('<h1>Login</h1>'),
    };
    (routes[req.url ?? ''] ?? (() => res.writeHead(404).end()))();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => server.close());

describe('traceUrl', () => {
  it('follows HTTP, meta refresh and JS redirects', async () => {
    const r = await traceUrl(`${base}/a`, { allowPrivate: true });
    expect(r.hops.map((h) => [new URL(h.url).pathname, h.status, h.via])).toEqual([
      ['/a', 301, 'http'],
      ['/b', 302, 'http'],
      ['/c', 200, 'meta-refresh'],
      ['/d', 200, 'javascript'],
      ['/never', 0, undefined],
    ]);
    expect(r.error).toMatch(/Could not connect/);
  });

  it('stops redirect loops', async () => {
    const r = await traceUrl(`${base}/loop`, { allowPrivate: true, maxHops: 5 });
    expect(r.truncated).toBe(true);
  });

  it('returns the final page', async () => {
    const r = await traceUrl(`${base}/final`, { allowPrivate: true });
    expect(r).toMatchObject({ finalUrl: `${base}/final`, truncated: false });
  });

  it('refuses private addresses by default', async () => {
    const r = await traceUrl("http://127.0.0.1/a");
    expect(r.error).toMatch(/private|reserved/);
    expect(r.hops).toEqual([]);
  });
});

describe('guard', () => {
  it.each(['127.0.0.1', '10.1.2.3', '192.168.1.1', '169.254.169.254', '::1', 'fe80::1', '::ffff:10.0.0.1', '100.64.0.1'])('blocks %s', (ip) => {
    expect(isBlockedAddress(ip)).toBe(true);
  });
  it.each(['8.8.8.8', '1.1.1.1', '2606:4700::1111'])('allows %s', (ip) => {
    expect(isBlockedAddress(ip)).toBe(false);
  });
  it('rejects odd schemes, ports and local names', () => {
    expect(() => assertAllowedUrl(new URL('file:///etc/passwd'))).toThrow();
    expect(() => assertAllowedUrl(new URL('http://example.com:22/'))).toThrow(/Port/);
    expect(() => assertAllowedUrl(new URL('http://metadata.internal/'))).toThrow();
    expect(() => assertAllowedUrl(new URL('https://example.com/'))).not.toThrow();
  });
});

describe('findClientRedirect', () => {
  it('ignores relative JS assignments', () => {
    expect(findClientRedirect('<script>location.href = "#top"</script>')).toBeNull();
    expect(findClientRedirect('<script>location.replace("https://x.top/p")</script>')).toEqual({ target: 'https://x.top/p', via: 'javascript' });
  });
});

describe('http api', () => {
  it('validates input and sends CORS headers', async () => {
    const missing = await app.request('/api/trace');
    expect(missing.status).toBe(400);
    const res = await app.request('/api/trace?url=http://127.0.0.1/', { headers: { origin: 'chrome-extension://abc' } });
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(((await res.json()) as { error: string }).error).toMatch(/private|reserved/);
  });
});
