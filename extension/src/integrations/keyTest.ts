/** Checks that a key or server works before it is saved, so users get "Connected" or a clear reason. */

export type KeyTestResult = { ok: true; message: string } | { ok: false; message: string };

// SHA-256 of the harmless EICAR test file: every VirusTotal account can look it up.
const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

export async function testVirusTotalKey(key: string): Promise<KeyTestResult> {
  const k = key.trim();
  if (!/^[0-9a-f]{64}$/i.test(k)) return { ok: false, message: 'A VirusTotal key is 64 letters and numbers. Copy it again from your API key page.' };
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/files/${EICAR_SHA256}`, { headers: { 'x-apikey': k } });
    if (res.ok) return { ok: true, message: 'Connected to VirusTotal.' };
    if (res.status === 401 || res.status === 403) return { ok: false, message: 'VirusTotal says this key is not valid.' };
    if (res.status === 429) return { ok: true, message: 'Key accepted (VirusTotal rate limit reached for now).' };
    return { ok: false, message: `VirusTotal answered HTTP ${res.status}. Try again in a minute.` };
  } catch {
    return { ok: false, message: 'Could not reach VirusTotal. Check your internet connection.' };
  }
}

export async function testUrlscanKey(key: string): Promise<KeyTestResult> {
  const k = key.trim();
  if (!/^[0-9a-f-]{36}$/i.test(k)) return { ok: false, message: 'A urlscan.io key looks like 1a2b3c4d-…, 36 characters with dashes. Copy it again.' };
  try {
    const res = await fetch('https://urlscan.io/user/quotas/', { headers: { 'API-Key': k } });
    if (res.ok) return { ok: true, message: 'Connected to urlscan.io.' };
    if (res.status === 401 || res.status === 403) return { ok: false, message: 'urlscan.io says this key is not valid.' };
    return { ok: false, message: `urlscan.io answered HTTP ${res.status}. Try again in a minute.` };
  } catch {
    return { ok: false, message: 'Could not reach urlscan.io. Check your internet connection.' };
  }
}

export async function testBackend(url: string): Promise<KeyTestResult> {
  const base = url.trim().replace(/\/+$/, '');
  if (!/^https?:\/\/\S+$/i.test(base)) return { ok: false, message: 'Enter the full address, starting with http:// or https://' };
  try {
    const res = await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(5000) });
    const body = (await res.json().catch(() => null)) as { ok?: boolean } | null;
    if (res.ok && body?.ok) return { ok: true, message: 'Redirect-trace server is running.' };
    return { ok: false, message: `That address answered, but it is not an Unmask server (HTTP ${res.status}).` };
  } catch {
    return { ok: false, message: base.includes('localhost') ? 'Nothing is running there. Start it with "pnpm backend" in the UNMASK folder.' : 'Could not reach that server.' };
  }
}

export async function testHybridKey(key: string): Promise<KeyTestResult> {
  const k = key.trim();
  if (k.length < 20) return { ok: false, message: 'That key looks too short. Copy it again from your Hybrid Analysis profile page.' };
  try {
    const res = await fetch(`https://www.hybrid-analysis.com/api/v2/overview/${EICAR_SHA256}`, { headers: { 'api-key': k, accept: 'application/json' } });
    if (res.ok || res.status === 404) return { ok: true, message: 'Connected to Hybrid Analysis.' };
    if (res.status === 401 || res.status === 403) return { ok: false, message: 'Hybrid Analysis says this key is not valid, or has not been approved for API use yet.' };
    if (res.status === 429) return { ok: true, message: 'Key accepted (Hybrid Analysis rate limit reached for now).' };
    return { ok: false, message: `Hybrid Analysis answered HTTP ${res.status}. Try again in a minute.` };
  } catch {
    return { ok: false, message: 'Could not reach Hybrid Analysis. Allow access when asked, then check your internet connection.' };
  }
}

export async function testAbuseChKey(key: string): Promise<KeyTestResult> {
  const k = key.trim();
  if (k.length < 16) return { ok: false, message: 'That key looks too short. Copy the Auth-Key again from auth.abuse.ch.' };
  try {
    const res = await fetch('https://mb-api.abuse.ch/api/v1/', { method: 'POST', headers: { 'Auth-Key': k, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ query: 'get_info', hash: EICAR_SHA256 }).toString() });
    const j = (await res.json().catch(() => ({}))) as { query_status?: string };
    if (res.status === 401 || res.status === 403 || /auth/i.test(j.query_status ?? '')) return { ok: false, message: 'abuse.ch says this Auth-Key is not valid.' };
    if (res.ok) return { ok: true, message: 'Connected to abuse.ch.' };
    return { ok: false, message: `abuse.ch answered HTTP ${res.status}. Try again in a minute.` };
  } catch {
    return { ok: false, message: 'Could not reach abuse.ch. Allow access when asked, then check your internet connection.' };
  }
}
