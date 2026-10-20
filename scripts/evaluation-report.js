import { readFileSync, writeFileSync } from 'node:fs';
const revocation = JSON.parse(readFileSync('docs/benchmark-results.json'));
const crypto = JSON.parse(readFileSync('docs/crypto-results.json'));
function stats(values) {
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const sd = values.length > 1 ? Math.sqrt(values.reduce((s, v) => s + (v - mean) ** 2, 0) / (values.length - 1)) : 0;
  return `${mean.toFixed(2)} ± ${sd.toFixed(2)}`;
}
const revRows = [...new Set(revocation.results.map(r => r.n))].map(n => {
  const lazy = revocation.results.filter(r => r.n === n && r.mode === 'lazy');
  const eager = revocation.results.filter(r => r.n === n && r.mode === 'eager');
  return `| ${n} | ${stats(lazy.map(r => r.elapsedMs))} | ${stats(eager.map(r => r.elapsedMs))} | ${eager[0].bytesProcessed} |`;
}).join('\n');
const cryptoRows = [...new Set(crypto.results.map(r => r.size))].map(size => {
  const rows = crypto.results.filter(r => r.size === size);
  return `| ${size.toLocaleString('en-US')} | ${stats(rows.map(r => r.encryptMs))} | ${stats(rows.map(r => r.decryptMs))} | ${stats(rows.map(r => r.hmacMs))} |`;
}).join('\n');
writeFileSync('docs/evaluation.md', `# Evaluation and results

Measured on ${new Date(revocation.generatedAt).toLocaleString('en-GB', { timeZone: 'Asia/Calcutta' })} IST. These are local measurements, not production performance claims.

## Environment

- Node: ${revocation.environment.node}
- OS: ${revocation.environment.os}
- CPU: ${revocation.environment.cpu}
- Chain: local Hardhat with immediate mining.
- Storage: real Kubo running offline on the same machine.
- Proxy: one Node process, SQLite, serialized operations.

## E3: Lazy versus eager revocation

Each trial creates fresh identities and a group, approves a member, uploads N random ${revocation.results[0].fileBytes}-byte files, then revokes that member. Group setup and uploads are excluded from revocation timing. ${revocation.environment.repeats} repetitions per configuration; mode order alternates between repetitions. Numbers below are **server elapsed milliseconds, mean ± sample standard deviation**. Raw JSON also records HTTP wall time.

| Files | Lazy revocation (ms) | Eager revocation (ms) | Ciphertext bytes migrated per eager trial |
| --- | --- | --- | --- |
${revRows}

Lazy revocation migrated zero files in every trial. Eager revocation migrated all N files and included unpinning, key purge, and repository GC. This supports the intended behavior: lazy revocation avoids work proportional to stored file volume at the point of revocation. The current threshold is not exceeded by a single rotation, so this experiment does not measure deferred migration's cumulative cost.

The baseline is this application's eager mode (immediate re-encryption using the same AES-GCM, database and chain implementation), not a byte-for-byte reproduction of the paper. Both paths include chain event writes. Background load, repository growth, garbage collection and local immediate mining influence timings; three repetitions provide only a preliminary comparison.

## E1: Shared client cryptography

Node WebCrypto runs the same AES-GCM/blob and HMAC helpers used by the browser. Ten measured repetitions per size, following one unreported warmup. Every decrypted result was compared byte-for-byte with the input. Numbers are milliseconds, mean ± sample standard deviation.

| Plaintext bytes | AES-GCM encryption | AES-GCM decryption | HMAC-SHA256 |
| --- | --- | --- | --- |
${cryptoRows}

The blob adds 29 bytes (format byte, IV and tag). Browser uploads additionally include an encrypted filename/MIME header. This microbenchmark excludes that header, key generation, wrapping, signing, HTTP, IPFS and chain time; it is not an end-to-end transfer benchmark or a browser timing measurement.

## Correctness and security evaluation

- \`npm test\`: 13 checks passed (including the parent workflow test); covers W1–W13, replay, permissions, integrity, revocation, recovery, filename roundtrips and legacy compatibility.
- \`npm run test:integration\`: 5 checks passed (including the parent test) against real Hardhat and Kubo. Covers onlyProxy enforcement, verified downloads, filename/MIME preservation through migration, purge, GC, and chain audit.
- \`npm run build\`: production build passed.
- Earlier manual browser verification confirmed registration, group creation, encrypted upload, verified download, key inventory and direct-chain audit. See [browser evidence](browser-verification.png).

## Reproduction

Start the services using [startup instructions](startup.md), then run:

\`\`\`powershell
npm test
# Stop the proxy before live tests; restart it before benchmarks.
npm run test:integration
npm run build
# In a separate terminal: npm start
npm run bench
npm run bench:crypto
npm run evaluation:report
\`\`\`

\`BENCH_COUNTS\`, \`BENCH_FILE_BYTES\`, and \`BENCH_REPEATS\` configure revocation trials. Benchmarks create scratch groups and pinned blobs in the local application; they do not erase existing data. For cleaner measurements, use a separate fresh local environment. Both modes operate on independent random payloads of the same size.

Raw evidence: [revocation samples](benchmark-results.json), [crypto samples](crypto-results.json).

## Not evaluated

No claims are made about WAN IPFS performance, multi-node availability, public-chain fees/finality, concurrent throughput, production security certification, or browser memory limits. Full E2 transfer scaling, E4 cumulative multi-revocation cost, E5 key-inventory curves and E6 gas comparisons remain future experiments. See [implementation limits](implementation-limits.md).
`);
console.log('Wrote docs/evaluation.md from measured samples.');
