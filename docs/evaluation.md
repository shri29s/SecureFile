# Evaluation and results

Measured on 20/10/2026, 23:10:50 IST. These are local measurements, not production performance claims.

## Environment

- Node: v24.15.0
- OS: win32 10.0.26200
- CPU: 13th Gen Intel(R) Core(TM) i5-13420H
- Chain: local Hardhat with immediate mining.
- Storage: real Kubo running offline on the same machine.
- Proxy: one Node process, SQLite, serialized operations.

## E3: Lazy versus eager revocation

Each trial creates fresh identities and a group, approves a member, uploads N random 65536-byte files, then revokes that member. Group setup and uploads are excluded from revocation timing. 3 repetitions per configuration; mode order alternates between repetitions. Numbers below are **server elapsed milliseconds, mean ± sample standard deviation**. Raw JSON also records HTTP wall time.

| Files | Lazy revocation (ms) | Eager revocation (ms) | Ciphertext bytes migrated per eager trial |
| --- | --- | --- | --- |
| 1 | 256.55 ± 7.27 | 638.99 ± 24.44 | 65565 |
| 5 | 272.21 ± 5.75 | 1476.83 ± 73.18 | 327825 |
| 10 | 273.40 ± 9.00 | 2767.22 ± 129.47 | 655650 |

Lazy revocation migrated zero files in every trial. Eager revocation migrated all N files and included unpinning, key purge, and repository GC. This supports the intended behavior: lazy revocation avoids work proportional to stored file volume at the point of revocation. The current threshold is not exceeded by a single rotation, so this experiment does not measure deferred migration's cumulative cost.

The baseline is this application's eager mode (immediate re-encryption using the same AES-GCM, database and chain implementation), not a byte-for-byte reproduction of the paper. Both paths include chain event writes. Background load, repository growth, garbage collection and local immediate mining influence timings; three repetitions provide only a preliminary comparison.

## E1: Shared client cryptography

Node WebCrypto runs the same AES-GCM/blob and HMAC helpers used by the browser. Ten measured repetitions per size, following one unreported warmup. Every decrypted result was compared byte-for-byte with the input. Numbers are milliseconds, mean ± sample standard deviation.

| Plaintext bytes | AES-GCM encryption | AES-GCM decryption | HMAC-SHA256 |
| --- | --- | --- | --- |
| 1,024 | 0.19 ± 0.18 | 0.10 ± 0.03 | 0.08 ± 0.03 |
| 65,536 | 0.16 ± 0.04 | 0.17 ± 0.03 | 0.13 ± 0.02 |
| 1,048,576 | 1.73 ± 0.11 | 1.75 ± 0.14 | 1.39 ± 0.05 |
| 10,485,760 | 14.99 ± 1.92 | 14.16 ± 1.04 | 12.02 ± 0.63 |

The blob adds 29 bytes (format byte, IV and tag). Browser uploads additionally include an encrypted filename/MIME header. This microbenchmark excludes that header, key generation, wrapping, signing, HTTP, IPFS and chain time; it is not an end-to-end transfer benchmark or a browser timing measurement.

## Correctness and security evaluation

- `npm test`: 13 checks passed (including the parent workflow test); covers W1–W13, replay, permissions, integrity, revocation, recovery, filename roundtrips and legacy compatibility.
- `npm run test:integration`: 5 checks passed (including the parent test) against real Hardhat and Kubo. Covers onlyProxy enforcement, verified downloads, filename/MIME preservation through migration, purge, GC, and chain audit.
- `npm run build`: production build passed.
- Earlier manual browser verification confirmed registration, group creation, encrypted upload, verified download, key inventory and direct-chain audit. See [browser evidence](browser-verification.png).

## Reproduction

Start the services using [startup instructions](startup.md), then run:

```powershell
npm test
# Stop the proxy before live tests; restart it before benchmarks.
npm run test:integration
npm run build
# In a separate terminal: npm start
npm run bench
npm run bench:crypto
npm run evaluation:report
```

`BENCH_COUNTS`, `BENCH_FILE_BYTES`, and `BENCH_REPEATS` configure revocation trials. Benchmarks create scratch groups and pinned blobs in the local application; they do not erase existing data. For cleaner measurements, use a separate fresh local environment. Both modes operate on independent random payloads of the same size.

Raw evidence: [revocation samples](benchmark-results.json), [crypto samples](crypto-results.json).

## Not evaluated

No claims are made about WAN IPFS performance, multi-node availability, public-chain fees/finality, concurrent throughput, production security certification, or browser memory limits. Full E2 transfer scaling, E4 cumulative multi-revocation cost, E5 key-inventory curves and E6 gas comparisons remain future experiments. See [implementation limits](implementation-limits.md).
