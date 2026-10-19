import type { ImageDecoder, Pixels } from '../analyzers/qr';

/** Largest side QR scanning and logo matching look at; bigger images are scaled down first. */
const MAX_SIDE = 1600;

/**
 * Decodes image bytes with the browser's own image decoder. Runs entirely
 * locally; works in the side panel and in content scripts.
 */
export const decodeImageInBrowser: ImageDecoder = async (bytes, mimeType): Promise<Pixels | null> => {
  if (typeof createImageBitmap !== 'function') return null;
  let bitmap: ImageBitmap | null = null;
  try {
    bitmap = await createImageBitmap(new Blob([bytes as BlobPart], { type: mimeType }));
    const scale = Math.min(1, MAX_SIDE / Math.max(bitmap.width, bitmap.height));
    const width = Math.max(1, Math.round(bitmap.width * scale));
    const height = Math.max(1, Math.round(bitmap.height * scale));
    const canvas: OffscreenCanvas | HTMLCanvasElement =
      typeof OffscreenCanvas !== 'undefined' ? new OffscreenCanvas(width, height) : Object.assign(document.createElement('canvas'), { width, height });
    const ctx = canvas.getContext('2d', { willReadFrequently: true }) as OffscreenCanvasRenderingContext2D | CanvasRenderingContext2D | null;
    if (!ctx) return null;
    // White behind transparent PNGs, so a black-on-transparent QR code stays readable.
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, width, height);
    ctx.drawImage(bitmap, 0, 0, width, height);
    const img = ctx.getImageData(0, 0, width, height);
    return { data: img.data, width, height };
  } catch {
    return null;
  } finally {
    bitmap?.close();
  }
};
