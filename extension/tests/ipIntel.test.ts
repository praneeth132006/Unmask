import { ipFindings, lookupIp } from '../src/integrations/ipIntel';

function mockDns(answers: Record<string, { type: number; data: string }[]>) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
    const u = new URL(String(input));
    return new Response(JSON.stringify({ Status: 0, Answer: answers[`${u.searchParams.get('name')}/${u.searchParams.get('type')}`] }), { status: 200 });
  });
}

describe('sending server lookups', () => {
  it('reads reverse DNS, forward confirmation and the network from DNS only', async () => {
    const m = mockDns({
      '4.101.220.185.in-addr.arpa/PTR': [{ type: 12, data: 'host.example.net.' }],
      'host.example.net/A': [{ type: 1, data: '185.220.101.4' }],
      '4.101.220.185.origin.asn.cymru.com/TXT': [{ type: 16, data: '"14061 | 185.220.101.0/24 | US | arin | 2012-09-25"' }],
      'AS14061.asn.cymru.com/TXT': [{ type: 16, data: '"14061 | US | arin | 2012-09-25 | DIGITALOCEAN-ASN, US"' }],
    });
    const info = await lookupIp('185.220.101.4');
    m.mockRestore();
    expect(info).toEqual({ ip: '185.220.101.4', ptr: 'host.example.net', confirmed: true, asn: '14061', network: 'DIGITALOCEAN-ASN, US', country: 'US' });
    expect(ipFindings(info, true).map((f) => [f.id, f.severity])).toEqual([['ip-rented-server', 'medium']]);
  });

  it('builds IPv6 nibble names', async () => {
    const seen: string[] = [];
    const m = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      seen.push(new URL(String(input)).searchParams.get('name')!);
      return new Response(JSON.stringify({ Status: 3 }), { status: 200 });
    });
    await lookupIp('2001:db8::1');
    m.mockRestore();
    expect(seen).toContain('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa');
  });

  it('flags home connections and unconfirmed names, not normal mail servers', () => {
    const base = { ip: '203.0.113.9', confirmed: true, asn: '7922', network: 'COMCAST-7922, US', country: 'US' };
    expect(ipFindings({ ...base, ptr: 'c-203-0-113-9.hsd1.ca.comcast.net.dynamic.comcast.net' }, false).map((f) => f.id)).toEqual(['ip-home-connection']);
    expect(ipFindings({ ...base, ptr: 'a8-30.smtp-out.amazonses.com', network: 'AMAZON-02, US' }, true)).toEqual([]);
    expect(ipFindings({ ...base, ptr: 'mail-sor-f41.google.com', network: 'GOOGLE, US', confirmed: false }, false).map((f) => f.id)).toEqual(['ip-ptr-unconfirmed']);
  });
});
