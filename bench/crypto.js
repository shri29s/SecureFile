import { mkdirSync, writeFileSync } from 'node:fs';
import { cpus, platform, release } from 'node:os';
import assert from 'node:assert/strict';
import { encryptBlob, decryptBlob, hmac } from '../client-core/src/crypto.js';

const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
const hmacKey = await crypto.subtle.generateKey({ name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
const group = 'ab'.repeat(16), repeats = 10, results = [];
for (const size of [1024, 65536, 1048576, 10485760]) {
  const plain = new Uint8Array(size);
  for (let offset = 0; offset < size; offset += 65536) crypto.getRandomValues(plain.subarray(offset, offset + 65536));
  // One unreported warmup for each payload size.
  await decryptBlob(aesKey, await encryptBlob(aesKey, plain, group, 1), group, 1);
  await hmac(hmacKey, plain);
  for (let repeat = 1; repeat <= repeats; repeat++) {
    let start = performance.now();
    const blob = await encryptBlob(aesKey, plain, group, 1);
    const encryptMs = performance.now() - start;
    start = performance.now();
    const restored = await decryptBlob(aesKey, blob, group, 1);
    const decryptMs = performance.now() - start;
    start = performance.now();
    await hmac(hmacKey, plain);
    const hmacMs = performance.now() - start;
    assert.deepEqual(restored, plain);
    results.push({ size, repeat, encryptMs, decryptMs, hmacMs, blobBytes: blob.length });
  }
}
mkdirSync('docs', { recursive: true });
writeFileSync('docs/crypto-results.json', JSON.stringify({
  generatedAt: new Date().toISOString(),
  environment: { node: process.version, os: `${platform()} ${release()}`, cpu: cpus()[0]?.model, repeats, note: 'Node WebCrypto using shared client code; one warmup per size. Excludes key generation, metadata packing, HTTP, IPFS, and blockchain.' },
  results
}, null, 2));
console.log(`Verified ${results.length} byte-exact crypto roundtrips; wrote docs/crypto-results.json.`);
