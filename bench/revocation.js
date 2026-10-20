import { mkdirSync, writeFileSync } from 'node:fs';
import { identity, registration } from '../client-core/src/crypto.js';
import { signedFetch, upload } from '../client-core/src/api.js';
import { cpus, platform, release } from 'node:os';
const base = `http://127.0.0.1:${process.env.PORT || 3001}`;
const sizes = (process.env.BENCH_COUNTS || '1,5,10').split(',').map(Number);
const fileBytes = Number(process.env.BENCH_FILE_BYTES || 65536);
const repeats = Number(process.env.BENCH_REPEATS || 3);
if (!Number.isInteger(repeats) || repeats < 1 || repeats > 20) throw Error('BENCH_REPEATS must be between 1 and 20');
if (sizes.some(n => !Number.isInteger(n) || n < 1 || n > 100) || !Number.isSafeInteger(fileBytes) || fileBytes < 1 || fileBytes > 50 * 1024 * 1024) throw Error('Invalid benchmark inputs');
const results = [];
for (const n of sizes) for (let repeat = 1; repeat <= repeats; repeat++) for (const mode of (repeat % 2 ? ['lazy', 'eager'] : ['eager', 'lazy'])) {
  const [owner, member] = await Promise.all([identity(`Bench owner ${mode}`), identity(`Bench member ${mode}`)]);
  for (const id of [owner, member]) {
    const r = await fetch(base + '/users/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(await registration(id)) });
    if (!r.ok) throw Error('Benchmark registration failed');
  }
  const call = (id, method, path, body) => signedFetch(id, method, path, body, base);
  const { groupId: g } = await call(owner, 'POST', '/groups', { name: `Benchmark ${mode} N=${n}` });
  await call(member, 'POST', `/groups/${g}/join-requests`);
  await call(owner, 'POST', `/groups/${g}/members`, { userId: member.userId, decision: 'approve' });
  const data = new Uint8Array(fileBytes);
  for (let offset = 0; offset < data.length; offset += 65536) crypto.getRandomValues(data.subarray(offset, offset + 65536));
  for (let i = 0; i < n; i++) await upload(owner, g, data, base);
  const start = performance.now();
  const result = await call(owner, 'DELETE', `/groups/${g}/members/${member.userId}?mode=${mode}`);
  const row = { n, fileBytes, repeat, mode, wallMs: performance.now() - start, ...result };
  results.push(row); console.log(JSON.stringify(row));
}
mkdirSync('docs', { recursive: true });
writeFileSync('docs/benchmark-results.json', JSON.stringify({ generatedAt: new Date().toISOString(), environment: { node: process.version, os: `${platform()} ${release()}`, cpu: cpus()[0]?.model, storage: 'Local offline Kubo', chain: 'Local Hardhat, immediate mining', repeats, note: 'Alternating mode order; no warmup discarded. Scratch groups share a growing chain and IPFS repository.' }, results }, null, 2));
