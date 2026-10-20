import { createCipheriv, createDecipheriv, createHash, createHmac, createPublicKey, publicEncrypt, randomBytes, verify } from 'node:crypto';
import { aad } from '../../client-core/src/crypto.js';
export const sha = b => createHash('sha256').update(b).digest('hex');
export const pub = (key, type) => {
  const parsed = createPublicKey({ key: Buffer.from(key, 'base64'), format: 'der', type: 'spki' });
  if (parsed.asymmetricKeyType !== type) throw new Error('Wrong public key type');
  if (type === 'rsa' && parsed.asymmetricKeyDetails.modulusLength !== 3072) throw new Error('RSA must be 3072 bits');
  return parsed;
};
export const signatureOK = (key, message, signature) => {
  try { return verify(null, Buffer.from(message), pub(key, 'ed25519'), Buffer.from(signature, 'base64')); } catch { return false; }
};
export const seal = (key, plain, binding = '') => {
  const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(binding));
  return Buffer.concat([iv, c.update(plain), c.final(), c.getAuthTag()]);
};
export const unseal = (key, blob, binding = '') => {
  const d = createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
  d.setAAD(Buffer.from(binding)); d.setAuthTag(blob.subarray(-16));
  return Buffer.concat([d.update(blob.subarray(12, -16)), d.final()]);
};
export const wrap = (encPub, bytes) => publicEncrypt({ key: pub(encPub, 'rsa'), oaepHash: 'sha256' }, bytes).toString('base64');
export const encrypt = (key, plain, group, version) => Buffer.concat([Buffer.from([1]), seal(key, plain, aad(group, version))]);
export const decrypt = (key, blob, group, version) => {
  if (blob.length < 29 || blob[0] !== 1) throw new Error('Invalid blob');
  return unseal(key, blob.subarray(1), aad(group, version));
};
export const mac = (key, bytes) => createHmac('sha256', key).update(bytes).digest('hex');
