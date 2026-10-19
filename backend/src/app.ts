import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { traceUrl } from './trace.js';

/** Per-IP fixed-window rate limit. In-memory, so it resets per instance; enough to stop casual abuse. */
const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = Number(process.env.UNMASK_RATE_LIMIT ?? 30);
const hits = new Map<string, { count: number; reset: number }>();

function rateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = hits.get(ip);
  if (!entry || entry.reset < now) {
    hits.set(ip, { count: 1, reset: now + WINDOW_MS });
    if (hits.size > 10_000) for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
    return false;
  }
  entry.count++;
  return entry.count > MAX_PER_WINDOW;
}

export const app = new Hono();

// The extension calls from a chrome-extension:// origin. No cookies are involved, so * is fine.
app.use('/api/*', cors({ origin: '*', allowMethods: ['GET'] }));

app.get('/', (c) => c.json({ name: 'unmask-backend', endpoints: ['/api/health', '/api/trace?url='] }));
app.get('/api/health', (c) => c.json({ ok: true }));

app.get('/api/trace', async (c) => {
  const url = c.req.query('url');
  if (!url) return c.json({ error: 'Missing ?url=' }, 400);
  if (url.length > 4096) return c.json({ error: 'URL too long' }, 400);

  const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? c.req.header('x-real-ip') ?? 'local';
  if (rateLimited(ip)) return c.json({ error: 'Too many requests, slow down.' }, 429);

  // Nothing is logged or stored: the result goes straight back to the caller.
  const result = await traceUrl(url);
  c.header('cache-control', 'no-store');
  return c.json(result);
});
