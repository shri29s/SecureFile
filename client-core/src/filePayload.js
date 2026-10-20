import { concat, utf8 } from './crypto.js';

// This header is inside the AES-GCM ciphertext and covered by the content MAC.
const MAGIC = utf8('SFS-FILE-v1\0');
const MAX_HEADER = 16384;
export function safeFilename(name, fallback = 'download.bin') {
  const leaf = String(name || '').split(/[\\/]/).pop()
    .replace(/[\u0000-\u001f\u007f<>:"|?*]/g, '_').replace(/[. ]+$/g, '');
  return leaf && leaf !== '.' && leaf !== '..' ? leaf : fallback;
}
export function packFile(bytes, { filename, mimeType = '' }) {
  const header = utf8(JSON.stringify({ filename: safeFilename(filename), mimeType }));
  if (header.length > MAX_HEADER) throw new Error('File metadata is too large');
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, header.length);
  return concat(MAGIC, length, header, bytes);
}
export function unpackFile(payload, recordId) {
  const fallback = { plain: payload, filename: `securefile-${recordId}.bin`, mimeType: 'application/octet-stream' };
  if (!MAGIC.every((byte, i) => payload[i] === byte)) return fallback;
  if (payload.length < MAGIC.length + 4) throw new Error('Invalid encrypted file header');
  const length = new DataView(payload.buffer, payload.byteOffset + MAGIC.length, 4).getUint32(0);
  const start = MAGIC.length + 4, end = start + length;
  if (length > MAX_HEADER || end > payload.length) throw new Error('Invalid encrypted file header');
  const metadata = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(payload.subarray(start, end)));
  if (typeof metadata?.filename !== 'string' || typeof metadata.mimeType !== 'string') throw new Error('Invalid encrypted file metadata');
  return {
    plain: payload.slice(end),
    filename: safeFilename(metadata.filename, fallback.filename),
    mimeType: /^[\w.+-]+\/[\w.+-]+$/.test(metadata.mimeType) ? metadata.mimeType : fallback.mimeType
  };
}
