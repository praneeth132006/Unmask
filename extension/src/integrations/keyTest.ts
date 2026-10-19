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
