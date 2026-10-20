# SecureFile Evaluation Results

Evaluation date: **20 October 2026 (IST)**.

This report summarizes the recorded local evaluation of SecureFile. It includes 18 revocation benchmark trials, 40 cryptographic roundtrip trials, and automated functional checks. The measurements demonstrate behavior in a local research environment; they are not production performance guarantees.

## 1. Evaluation environment

| Component | Configuration |
| --- | --- |
| CPU | 13th Gen Intel Core i5-13420H |
| Operating system | Windows, build 10.0.26200 |
| Node.js | v24.15.0 |
| Blockchain | Local Hardhat node with immediate mining |
| File storage | Real Kubo IPFS node running offline |
| Proxy | Single Node.js process with SQLite and serialized operations |
| Cryptography | Shared client WebCrypto implementation |

## 2. Member revocation performance

The experiment compared two modes:

- **Lazy revocation:** revoke membership and rotate the group key without immediately migrating existing files.
- **Eager revocation:** revoke membership, rotate the key, immediately re-encrypt existing files, unpin old ciphertext, purge unused keys, and run local garbage collection.

Each trial used a new group containing 1, 5, or 10 files of **64 KiB each**. Each configuration was measured three times, alternating mode order between repetitions. Timings exclude identity creation, group setup, and file uploads.

Values below are **server elapsed time in milliseconds, mean ± sample standard deviation**.

| Number of files | Lazy revocation | Eager revocation | Files migrated: lazy / eager |
| --- | --- | --- | --- |
| 1 | 256.55 ± 7.27 ms | 638.99 ± 24.44 ms | 0 / 1 |
| 5 | 272.21 ± 5.75 ms | 1,476.83 ± 73.18 ms | 0 / 5 |
| 10 | 273.40 ± 9.00 ms | 2,767.22 ± 129.47 ms | 0 / 10 |

### Interpretation

Lazy revocation remained between approximately 257 and 273 ms across the tested file counts. Eager revocation increased from approximately 639 ms for one file to 2,767 ms for ten files.

For ten files, the eager-to-lazy ratio of mean revocation times was approximately **10.1×**. Lazy revocation avoided immediate file migration in all trials.

These results support the intended reduction in work at revocation time. They do **not** establish a formal complexity bound from three file counts, or show that lazy revocation eliminates migration costs: threshold-triggered migration performs that work later. This experiment did not measure cumulative costs across repeated revocations.

The eager baseline uses SecureFile's own cryptography and storage implementation. It represents immediate re-encryption behavior, rather than an exact reproduction of the reference paper.

## 3. Cryptographic performance

The cryptographic experiment used the same AES-256-GCM and HMAC-SHA256 helpers as the browser client, executed through **Node WebCrypto**. Each file size had one unreported warmup followed by ten measured repetitions. All 40 decrypted results matched their original input bytes.

Values below are **milliseconds, mean ± sample standard deviation**.

| Plaintext size | AES-GCM encryption | AES-GCM decryption | HMAC-SHA256 |
| --- | --- | --- | --- |
| 1 KiB | 0.19 ± 0.18 | 0.10 ± 0.03 | 0.08 ± 0.03 |
| 64 KiB | 0.16 ± 0.04 | 0.17 ± 0.03 | 0.13 ± 0.02 |
| 1 MiB | 1.73 ± 0.11 | 1.75 ± 0.14 | 1.39 ± 0.05 |
| 10 MiB | 14.99 ± 1.92 | 14.16 ± 1.04 | 12.02 ± 0.63 |

The encrypted blob adds **29 bytes**: one format byte, a 12-byte IV, and a 16-byte authentication tag. Browser uploads also include an encrypted filename and MIME-type header.

These timings exclude metadata packing, key generation, key wrapping, request signing, network requests, IPFS storage, and blockchain transactions. They are not browser timings or end-to-end upload/download measurements.

## 4. Functional and security checks

| Verification | Recorded outcome |
| --- | --- |
| `npm test` | 13 checks passed, including the parent workflow test |
| `npm run test:integration` | 5 checks passed, including the parent integration test |
| `npm run build` | Production build passed |
| Service health | Proxy, blockchain, and IPFS reported healthy |
| Cryptographic roundtrips | 40 of 40 restored the exact input bytes |

The automated checks covered:

- Registration proof and signed-request authentication.
- Replay rejection, timestamp validation, and request-body integrity.
- Group creation, join requests, approval, rejection, and membership permissions.
- Encryption, ciphertext hashes, GCM authentication, HMAC verification, and uploader provenance.
- File-removal permissions and on-chain tombstones.
- Denial of all key versions to revoked members.
- Continued access to old ciphertext using a previously cached key, demonstrating the lazy-revocation limitation.
- Rejection of stale-key uploads.
- Voluntary leave, key rotation, and migration threshold triggering.
- Migration recovery after a simulated lost chain receipt.
- Stable record handles through supersession, key purge, and local garbage collection.
- Cross-group access isolation and contract enforcement of proxy-only writes.
- Filename, extension, and MIME-type preservation through migration, plus legacy `.bin` fallback behavior.

Earlier manual browser checks confirmed identity creation, group creation, encrypted upload, verified download, key-version inventory, and direct blockchain audit reads. The [saved browser screenshot](docs/browser-verification.png) shows the download verification checklist.

Passing these checks establishes the tested behavior; it does not constitute an independent security audit.

## 5. Evaluation limitations

- Revocation results use only three repetitions per configuration and small file counts.
- Trials share a growing chain and IPFS repository. Background load and garbage collection can influence timing.
- The IPFS node is offline and local; network latency, remote replication, and multi-node availability were not tested.
- Hardhat mines immediately, so the measurements do not represent public-chain confirmation delays or transaction fees.
- Lazy revocation cannot recall copied keys or ciphertext. Re-encryption and local garbage collection cannot erase copies held elsewhere.
- Live integration tests and the running proxy share a development chain signer. An initial benchmark attempt encountered a stale transaction nonce; restarting the proxy resolved it before the completed trial set. The startup guide documents stopping the proxy for live tests and restarting it afterward.
- End-to-end transfer scaling, cumulative multi-revocation costs, key-inventory curves, gas comparisons, concurrent throughput, and production resilience remain unevaluated.

## 6. Conclusion

Within the tested local environment, SecureFile preserved encrypted file contents and metadata, enforced membership-based key access, and supported verified migration to newer key versions.

The primary measured result is lower immediate revocation cost: for ten 64 KiB files, lazy revocation averaged **273.40 ms**, compared with **2,767.22 ms** for eager revocation. This benefit comes with deferred migration work and the documented exposure of old ciphertext to users who retained old keys.

## 7. Evidence and reproduction

- [Raw revocation measurements](docs/benchmark-results.json)
- [Raw cryptographic measurements](docs/crypto-results.json)
- [Detailed methodology and reproduction commands](docs/evaluation.md)
- [Startup instructions](docs/startup.md)
- [Implementation limits](docs/implementation-limits.md)

This summary uses existing recorded measurements; writing it did not rerun the experiments.
