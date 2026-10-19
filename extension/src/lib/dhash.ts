/**
 * Perceptual "difference hash" for logo matching. The image is trimmed to its
 * content (dropping plain borders), shrunk to 9×8 gray cells, and each bit
 * records whether a cell is brighter than its right neighbour. Similar-looking
 * images get hashes a few bits apart regardless of size or file format.
 * Plain TypeScript with no browser APIs, so the build script can share it.
 */

export interface RgbaImage {
  data: Uint8ClampedArray | Uint8Array;
  width: number;
  height: number;
}

function gray(img: RgbaImage, x: number, y: number): number {
  const i = (y * img.width + x) * 4;
  const a = img.data[i + 3]! / 255;
  // Transparent pixels count as white, like an email on a white background.
  return (0.299 * img.data[i]! + 0.587 * img.data[i + 1]! + 0.114 * img.data[i + 2]!) * a + 255 * (1 - a);
}

/** Bounding box of pixels that differ from the corner colour. */
function contentBox(img: RgbaImage): { x0: number; y0: number; x1: number; y1: number } | null {
  const bg = gray(img, 0, 0);
  let x0 = img.width, y0 = img.height, x1 = -1, y1 = -1;
  for (let y = 0; y < img.height; y++) {
    for (let x = 0; x < img.width; x++) {
      if (Math.abs(gray(img, x, y) - bg) > 40) {
        if (x < x0) x0 = x;
        if (x > x1) x1 = x;
        if (y < y0) y0 = y;
        if (y > y1) y1 = y;
      }
    }
  }
  return x1 < 0 ? null : { x0, y0, x1: x1 + 1, y1: y1 + 1 };
}

/** 64-bit difference hash as 16 hex characters, or null for blank images. */
export function dHash(img: RgbaImage): string | null {
  if (img.width < 8 || img.height < 8) return null;
  const box = contentBox(img);
  if (!box || box.x1 - box.x0 < 4 || box.y1 - box.y0 < 4) return null;
  const cols = 9, rows = 8;
  const cells: number[] = [];
  const w = box.x1 - box.x0, h = box.y1 - box.y0;
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const sx = box.x0 + Math.floor((c * w) / cols), ex = box.x0 + Math.max(Math.floor(((c + 1) * w) / cols), Math.floor((c * w) / cols) + 1);
      const sy = box.y0 + Math.floor((r * h) / rows), ey = box.y0 + Math.max(Math.floor(((r + 1) * h) / rows), Math.floor((r * h) / rows) + 1);
      let sum = 0, n = 0;
      // Sample at most ~16×16 points per cell to stay fast on big images.
      const stepX = Math.max(1, Math.floor((ex - sx) / 16)), stepY = Math.max(1, Math.floor((ey - sy) / 16));
      for (let y = sy; y < ey; y += stepY) for (let x = sx; x < ex; x += stepX) (sum += gray(img, x, y)), n++;
      cells.push(sum / n);
    }
  }
  let hex = '';
  for (let r = 0; r < rows; r++) {
    let byte = 0;
    for (let c = 0; c < 8; c++) byte = (byte << 1) | (cells[r * cols + c]! > cells[r * cols + c + 1]! ? 1 : 0);
    hex += byte.toString(16).padStart(2, '0');
  }
  // All-equal cells (a flat rectangle) carry no shape information.
  return /^0+$/.test(hex) ? null : hex;
}

export function hamming(a: string, b: string): number {
  let d = 0;
  for (let i = 0; i < a.length; i += 2) {
    let x = parseInt(a.slice(i, i + 2), 16) ^ parseInt(b.slice(i, i + 2), 16);
    while (x) (d += x & 1), (x >>= 1);
  }
  return d;
}
