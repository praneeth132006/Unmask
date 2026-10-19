# Redirect-trace server

The optional **Trace redirects** button asks a small server to follow a link's chain of redirects, so your browser never opens the link. This server is the `backend/` folder: a [Hono](https://hono.dev) app that runs on Node locally or on Vercel.

> Most people don't need this. The **Sandbox scan** button (urlscan.io) also shows where a link ends up, and needs only a free key.

## Run it locally

```bash
pnpm install          # once, from the project root
pnpm backend          # http://localhost:8787
```

Then in Unmask: **Settings → Advanced → Redirect tracing → Set up → Use local server**. Or click **Trace redirects** on any link and choose **Use local server**. Unmask checks `/api/health` before saving.

Use a different port with `PORT=9000 pnpm backend`.

## Deploy to Vercel

The `backend/src/index.ts` file default-exports the Hono app, so Vercel detects it with no configuration.

```bash
cd backend
npx vercel deploy --prod
```

Use the URL it prints (for example `https://unmask-trace.vercel.app`) in Unmask's settings.

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `UNMASK_RATE_LIMIT` | `30` | Requests per IP per minute |
| `PORT` | `8787` | Local port (Node only) |

## API

### `GET /api/health`

```json
{ "ok": true }
```

### `GET /api/trace?url=<url>`

Follows up to 10 hops: HTTP 3xx redirects, `<meta http-equiv="refresh">`, and simple JavaScript redirects (`location.href = "…"`, `location.replace("…")`). No page code is ever executed.

```json
{
  "hops": [
    { "url": "http://github.com/", "status": 301, "via": "http" },
    { "url": "https://github.com/", "status": 200 }
  ],
  "finalUrl": "https://github.com/",
  "truncated": false
}
```

`error` is set when a hop is refused or fails, for example `"Refusing to connect to a private or reserved address"`. `truncated` is `true` when the 10-hop limit was hit.

Responses carry `Access-Control-Allow-Origin: *` (no cookies are involved) and `Cache-Control: no-store`.

## Safety

A public "fetch any URL" service is an obvious abuse target, so the tracer:

- **Blocks private and reserved addresses**: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16 (cloud metadata), 100.64/10, IPv6 loopback, link-local and ULA, and IPv4-mapped forms. The check runs on the **resolved address at connect time**, through a custom DNS lookup in the HTTP agent, so DNS rebinding (`localtest.me` → 127.0.0.1) is blocked too.
- Refuses `localhost`, `*.local`, `*.internal`, non-HTTP schemes and ports other than 80, 443, 8080 and 8443.
- Strips `user:password@` from URLs.
- Reads at most 256 KB of each page, with 5 s connect and 8 s response timeouts.
- Rate-limits per IP.
- Logs and stores nothing.

The tracer uses a browser-like User-Agent, because many phishing kits show scanners a harmless page. Even so, a kit may still detect it. Treat the result as a lead, not proof.

## Tests

```bash
pnpm --filter unmask-backend test
```

The tests run a local HTTP server to check HTTP, meta-refresh and JavaScript redirects, loop protection, private-address blocking and the HTTP API.
