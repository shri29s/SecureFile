const subtle = globalThis.crypto.subtle;
export const utf8 = s => new TextEncoder().encode(s);
export const toHex = b => Array.from(new Uint8Array(b), v => v.toString(16).padStart(2, '0')).join('');
export const fromHex = s => {
  if (!/^(?:[0-9a-f]{2})*$/i.test(s)) throw new Error('Invalid hex');
  return Uint8Array.from(s.match(/../g) || [], x => parseInt(x, 16));
};
export const b64 = b => {
  let s = ''; for (let i = 0; i < b.length; i += 32768) s += String.fromCharCode(...b.subarray(i, i + 32768));
  return btoa(s);
};
export const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
export const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { out.set(p, i); i += p.length; } return out; };
export const random = n => crypto.getRandomValues(new Uint8Array(n));
export const hash = async b => toHex(await subtle.digest('SHA-256', b));
export const sign = async (key, message) => b64(new Uint8Array(await subtle.sign('Ed25519', key, utf8(message))));
export async function verify(publicKey, signature, message) {
  const key = await subtle.importKey('spki', unb64(publicKey), 'Ed25519', false, ['verify']);
  return subtle.verify('Ed25519', key, unb64(signature), utf8(message));
}
export async function identity(name) {
  const signing = await subtle.generateKey('Ed25519', false, ['sign', 'verify']);
  const encryption = await subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, ['encrypt', 'decrypt']);
  const signPubBytes = new Uint8Array(await subtle.exportKey('spki', signing.publicKey));
  const signPub = b64(signPubBytes), encPub = b64(new Uint8Array(await subtle.exportKey('spki', encryption.publicKey)));
  const userId = await hash(signPubBytes);
  return { name, userId, signPub, encPub, signPriv: signing.privateKey, encPriv: encryption.privateKey };
}
export async function registration(id) {
  return { name: id.name, signPub: id.signPub, encPub: id.encPub, selfSig: await sign(id.signPriv, `SFS-REG-v1|${id.userId}|${id.encPub}`) };
}
export async function unwrap(id, wrapped) {
  const bytes = new Uint8Array(await subtle.decrypt({ name: 'RSA-OAEP' }, id.encPriv, unb64(wrapped)));
  if (bytes.length !== 64) throw new Error('Invalid wrapped key length');
  return {
    aesKey: await subtle.importKey('raw', bytes.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']),
    hmacKey: await subtle.importKey('raw', bytes.slice(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  };
}
export function aad(groupId, version) {
  const v = new Uint8Array(4); new DataView(v.buffer).setUint32(0, version);
  return concat(utf8('SFS-BLOB-v1'), fromHex(groupId), v);
}
export async function encryptBlob(key, plain, groupId, version) {
  const iv = random(12);
  return concat(new Uint8Array([1]), iv, new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(groupId, version), tagLength: 128 }, key, plain)));
}
export class TagError extends Error { constructor() { super('Ciphertext was tampered with or the key does not match'); this.name = 'TagError'; } }
export async function decryptBlob(key, blob, groupId, version) {
  if (blob.length < 29 || blob[0] !== 1) throw new TagError();
  try { return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: blob.slice(1, 13), additionalData: aad(groupId, version), tagLength: 128 }, key, blob.slice(13))); }
  catch { throw new TagError(); }
}
export const hmac = async (key, plain) => toHex(await subtle.sign('HMAC', key, plain));
