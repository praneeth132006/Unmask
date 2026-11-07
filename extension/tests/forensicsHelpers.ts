/** Builders for synthetic (harmless) Office files used by the forensics tests. */

export interface CfbNode {
  name: string;
  /** Present for streams. */
  data?: Uint8Array;
  /** Present for storages. */
  children?: CfbNode[];
}

const SECTOR = 512;
const le32 = (v: number) => [v & 255, (v >>> 8) & 255, (v >>> 16) & 255, (v >>> 24) & 255];

/** A minimal OLE2 container. Every stream is stored in regular sectors (the header's mini-stream cutoff is 1). */
export function makeCfb(root: CfbNode[]): Uint8Array {
  type Flat = { node: CfbNode; id: number; left: number; right: number; child: number; start: number };
  const flat: Flat[] = [{ node: { name: 'Root Entry', children: root }, id: 0, left: -1, right: -1, child: -1, start: 0xfffffffe }];
  const place = (nodes: CfbNode[]): number => {
    const ids = nodes.map((n) => { const f: Flat = { node: n, id: flat.length, left: -1, right: -1, child: -1, start: 0xfffffffe }; flat.push(f); return f; });
    ids.forEach((f, i) => { f.right = i + 1 < ids.length ? ids[i + 1]!.id : -1; if (f.node.children) f.child = place(f.node.children); });
    return ids.length ? ids[0]!.id : -1;
  };
  flat[0]!.child = place(root);

  const dirSectors = Math.ceil(flat.length / 4);
  const streams = flat.filter((f) => f.node.data);
  const sectorsOf = (n: number) => Math.max(1, Math.ceil(n / SECTOR));
  let next = 1 + dirSectors; // sector 0 is the FAT
  const fat: number[] = [0xfffffffd];
  for (let i = 0; i < dirSectors; i++) fat.push(i + 1 < dirSectors ? 1 + i + 1 : 0xfffffffe);
  for (const s of streams) {
    const n = sectorsOf(s.node.data!.length);
    s.start = next;
    for (let i = 0; i < n; i++) fat.push(i + 1 < n ? next + i + 1 : 0xfffffffe);
    next += n;
  }
  const total = next;
  const out = new Uint8Array((total + 1) * SECTOR);
  out.set([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  const header = new DataView(out.buffer);
  header.setUint16(24, 0x3e, true);
  header.setUint16(26, 3, true);
  header.setUint16(28, 0xfffe, true);
  header.setUint16(30, 9, true);
  header.setUint16(32, 6, true);
  header.setUint32(44, 1, true); // one FAT sector
  header.setUint32(48, 1, true); // directory starts at sector 1
  header.setUint32(56, 1, true); // mini cutoff 1: nothing uses the mini stream
  header.setUint32(60, 0xfffffffe, true);
  header.setUint32(68, 0xfffffffe, true);
  for (let i = 0; i < 109; i++) header.setUint32(76 + i * 4, i === 0 ? 0 : 0xffffffff, true);
  fat.forEach((v, i) => header.setUint32(SECTOR + i * 4, v >>> 0, true)); // FAT is sector 0
  flat.forEach((f, i) => {
    const o = (2 + (i >> 2)) * SECTOR + (i & 3) * 128; // directory begins at sector 1
    const name = f.node.name;
    for (let k = 0; k < name.length; k++) header.setUint16(o + k * 2, name.charCodeAt(k), true);
    header.setUint16(o + 64, name.length * 2 + 2, true);
    out[o + 66] = i === 0 ? 5 : f.node.data ? 2 : 1;
    header.setUint32(o + 68, f.left >>> 0, true);
    header.setUint32(o + 72, f.right >>> 0, true);
    header.setUint32(o + 76, f.child >>> 0, true);
    header.setUint32(o + 116, (f.node.data ? f.start : 0xfffffffe) >>> 0, true);
    header.setUint32(o + 120, f.node.data ? f.node.data.length : 0, true);
  });
  for (const s of streams) out.set(s.node.data!, (s.start + 1) * SECTOR);
  return out;
}

/** MS-OVBA compression using literal tokens only (valid for our reader; chunks stay small). */
export function vbaCompress(src: Uint8Array): Uint8Array {
  const out: number[] = [1];
  for (let off = 0; off < src.length; off += 2000) {
    const chunk = src.subarray(off, off + 2000);
    const body: number[] = [];
    for (let i = 0; i < chunk.length; i += 8) { body.push(0); body.push(...chunk.subarray(i, i + 8)); }
    const header = 0xb000 | ((body.length + 2 - 3) & 0x0fff);
    out.push(header & 255, header >> 8, ...body);
  }
  return Uint8Array.from(out);
}

const rec = (id: number, data: number[]) => [id & 255, id >> 8, ...le32(data.length), ...data];
const ascii = (s: string) => [...s].map((c) => c.charCodeAt(0));

/** A vbaProject.bin with the given module sources. */
export function makeVbaProject(modules: { name: string; code: string }[]): Uint8Array {
  const dir: number[] = [...rec(0x0003, [0xe4, 0x04]), ...rec(0x0004, ascii('VBAProject')), ...rec(0x000f, [modules.length & 255, 0]), ...rec(0x0013, [0xff, 0xff])];
  for (const m of modules) dir.push(...rec(0x0019, ascii(m.name)), ...rec(0x001a, ascii(m.name)), ...rec(0x0031, [0, 0, 0, 0]), ...rec(0x0021, []), ...rec(0x002b, []));
  dir.push(...rec(0x0010, []));
  const enc = new TextEncoder();
  return makeCfb([
    { name: 'VBA', children: [{ name: 'dir', data: vbaCompress(Uint8Array.from(dir)) }, { name: '_VBA_PROJECT', data: Uint8Array.from([0xcc, 0x61, 0xff, 0xff, 0, 0, 0]) }, ...modules.map((m) => ({ name: m.name, data: vbaCompress(enc.encode(m.code)) }))] },
  ]);
}
