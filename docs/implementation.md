# Implementation and verification

## Scope

Implemented W1–W13: self-signed registration; signed HTTP requests; group creation; join requests; owner approval/rejection; wrapped versioned keys; client-encrypted upload; verified download; removal; lazy/eager revocation; voluntary leave; threshold migration and purge; file listing; cross-group isolation.

UI: identity switcher, group cards, membership controls, upload/download stages, key inventory and threshold, direct-chain audit, inspector, and security lab (public ciphertext, current/old keys, cached-key decryption, replay, and tamper).

## Wire-format clarifications

- AAD is the UTF-8 bytes `SFS-BLOB-v1`, followed by the **16 raw group ID bytes**, then the version as four big-endian bytes. All clients and the proxy share this definition.
- On-chain group IDs are right-padded to bytes32; user IDs are full SHA-256 values.
- The signed upload includes client timestamp and nonce. The supplied contract schema does not store these two fields, so the proxy retains the original manifest in SQLite. A signed endpoint serves it; clients compare its fields and signature with the immutable original chain record before signature verification. A mirror rebuilt from chain alone cannot restore those missing manifest fields. Download intentionally fails provenance verification if the original manifest is unavailable.
- Sealed keys include group/version AAD to prevent swapping encrypted database values between groups or versions.

## Consistency

All authenticated operations run through a single process queue. Membership/version validation remains protected through asynchronous IPFS and chain writes, preventing a concurrent revocation from accepting a stale-key upload. This demo supports **one proxy process per database**, and buffers whole files. It is not designed for horizontal scaling or high throughput.

Membership changes and event outbox inserts share a SQLite transaction. A worker retries unsent events. This gives at-least-once audit delivery: a crash after chain inclusion but before outbox acknowledgement may duplicate a group event. A failed event write may return an error after local membership has committed; refresh group state before retrying.

Migration persists its encrypted output before IPFS add, then stores the CID and chain successor. Repeated adds after a crash produce the same CID. A lost chain receipt is recovered by inspecting the old record's successor. Unpin is idempotent; purge requires no active references and no unfinished jobs. A background worker retries unfinished migrations. No plaintext is persisted by the migration job.

The file mirror is reconciled from chain at startup. File uploads are only reported successful after chain confirmation. In a lost-receipt scenario, reconciliation prevents unpinning a blob referenced by a successful chain transaction. Crash-atomicity across SQLite, IPFS, and Ethereum is not absolute: an orphaned pin or missing original manifest may require operator repair. Removal can leave a pin if unpin fails after the tombstone commits. Production operation needs durable intent journals and reconciliation for every cross-system side effect.

## Trust boundaries

- The proxy is fully trusted and holds all live group keys. Client-side encryption prevents receiving upload plaintext, but does not make the proxy unable to decrypt it.
- Revocation blocks all future key retrieval. Cached keys and copied ciphertext cannot be recalled. Local garbage collection does not erase remote copies.
- The HMAC key remains constant, including across revocations. A former member can retain it to test guesses.
- Chain metadata is public: IDs, sizes, CIDs, timestamps, signatures, and membership events.
- Identity switching and unencrypted IndexedDB storage are demo conveniences. Non-extractable keys do not protect against malicious same-origin script or a compromised browser.
- Local HTTP is supported on loopback only. A deployment beyond localhost needs HTTPS, authenticated administration, rate limits, a hardened content security policy, backups, monitoring, and a non-demo chain signer. Hardhat's development account is public and must never be funded outside the local chain.
- Kubo runs offline for a deterministic local demo. This verifies genuine IPFS storage and pin/GC APIs, but not a multi-node network.

## Test coverage

`test/workflows.test.js` checks W1–W13 over HTTP with SQLite and real WebCrypto/Node crypto. It includes registration proof, key non-extractability, replay, body-byte tampering, expired timestamps, owner checks, pending/rejected denial, ciphertext/hash/signature tampering, AAD binding, random IVs, file permissions, revoked-key denial, cached-key access, stale upload refusal, leave, threshold triggering, migration crash recovery, stable record handles, purge, eager migration, and group isolation.

`test/integration.live.js` verifies the deployed Solidity contract rejects a non-proxy writer and exercises real Kubo upload, download, revocation, supersession, signature provenance, key purge, garbage collection, audit reads, and tombstones.

Browser checks cover real IndexedDB identity creation, group creation, upload, decryption, and tab navigation. The benchmark is a small E3 smoke comparison; it is not a statistically controlled performance study. E1/E2/E4/E5/E6 publication-ready experiments remain future work.

Original filenames and MIME types are stored in a versioned, length-prefixed JSON header inside the encrypted plaintext. Integrity checks cover the entire payload before the client extracts the original file bytes. Migration preserves this header. Legacy uploads without the header use a record-ID .bin filename. Optional chart dashboard, passphrase protection, and ownership transfer are not implemented.

