import { b64, encryptBlob, hash, hmac, random, sign, toHex, unwrap, utf8 } from './crypto.js';
import { canonicalManifest } from './manifest.js';
import { packFile } from './filePayload.js';
export class ApiError extends Error {
  constructor(status, data) { super(data.message || data.code); this.status = status; this.code = data.code; }
}
export async function signedRequest(id, method, path, body) {
  const raw = body === undefined ? '' : JSON.stringify(body);
  const ts = String(Date.now()), nonce = toHex(random(16));
  const signature = await sign(id.signPriv, `SFS-REQ-v1\n${method}\n${path}\n${ts}\n${nonce}\n${await hash(utf8(raw))}`);
  return { method, headers: { 'Content-Type': 'application/json', 'X-User-Id': id.userId, 'X-Timestamp': ts, 'X-Nonce': nonce, 'X-Signature': signature }, ...(raw ? { body: raw } : {}) };
}
export async function signedFetch(id, method, path, body, base = '') {
  const response = await fetch(base + path, await signedRequest(id, method, path, body));
  if (!response.ok) throw new ApiError(response.status, await response.json());
  return response.headers.get('content-type')?.includes('application/json') ? response.json() : new Uint8Array(await response.arrayBuffer());
}
export async function fetchKey(id, groupId, version = 'current', base = '') {
  const result = await signedFetch(id, 'GET', `/groups/${groupId}/keys/${version}`, undefined, base);
  return { version: result.version, ...await unwrap(id, result.wrapped) };
}
export async function prepareUpload(id, groupId, keys, plain) {
  const blob = await encryptBlob(keys.aesKey, plain, groupId, keys.version);
  const m = { groupId, uploaderId: id.userId, contentMac: await hmac(keys.hmacKey, plain), ctHash: await hash(blob), keyVersion: keys.version, size: blob.length, clientTs: Date.now(), nonce: toHex(random(16)) };
  return { ...m, uploaderSig: await sign(id.signPriv, canonicalManifest(m)), blob: b64(blob) };
}
export async function upload(id, groupId, plain, base = '', onStage = () => {}, onKey = () => {}, metadata) {
  const payload = metadata ? packFile(plain, metadata) : plain;
  for (let attempt = 0; attempt < 2; attempt++) {
    onStage(attempt ? 'Retrying with current key' : 'Fetching key');
    const keys = await fetchKey(id, groupId, 'current', base); await onKey(keys);
    onStage('Encrypting and signing');
    const body = await prepareUpload(id, groupId, keys, payload);
    try {
      onStage('Uploading ciphertext');
      const result = await signedFetch(id, 'POST', `/groups/${groupId}/files`, body, base);
      onStage(`Recorded on chain · v${keys.version}`); return result;
    } catch (e) { if (attempt || e.code !== 'STALE_KEY_VERSION') throw e; }
  }
}
