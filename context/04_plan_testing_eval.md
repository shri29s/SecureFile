# 04: Plan, Testing, Evaluation, Threat Model

## 1. Six-hour plan mapped to workflows

| Time | Goal | Workflows | Done when |
|---|---|---|---|
| 0:00 to 1:00 | Environment + contract | n/a | `ipfs add/cat` works; contract deployed on Hardhat; `addRecord`/`getRecord` callable from a script |
| 1:00 to 2:00 | Proxy core: DB, auth middleware, users, groups, join/approve, key endpoint | W1, W2, W3, W4, W12 | Alice registers, creates group, Bob joins, is approved, and fetches a wrapped key that he can unwrap |
| 2:00 to 3:00 | Upload with sender-side encryption | W5 | Alice uploads; chain record visible with `keyVersion=1`; stale-version and bad-signature requests rejected |
| 3:00 to 4:00 | Download, list, remove file | W6, W7, W11 | Bob downloads and hash verifies; outsider gets ciphertext but no key; tombstone works |
| 4:00 to 5:00 | Revocation with key versioning | W8, W9 | Revoked Bob gets `403` on all key versions; new uploads use v2; old files still open for Carol |
| 5:00 to 5:45 | Threshold re-encryption + purge | W10 | After 4 revocations (T=3), job migrates files, `supersededBy` chain works, old keys return `410` |
| 5:45 to 6:00 | Benchmarks + write-up | n/a | Results table filled; threat model written |

**Order of risk:** upload/download correctness first, revocation second, re-encryption last. If time runs out, the re-encryption job becomes a manual `admin reencrypt` script (already in the CLI spec). A scheduler is not needed.

## 2. Test scenarios (write each as a small script in `test/`)

Actors: `alice` (owner), `bob`, `carol` (members), `dave` (outsider), `bob` also in group 2.

| # | Scenario | Expected |
|---|---|---|
| T1 | Register all 4 users | `userId` = sha256(signPub); duplicate registration → `409` |
| T2 | Alice creates G1; Bob and Carol join; Alice approves | Both can fetch key v1 |
| T3 | Dave requests key without joining | `403 NOT_MEMBER` |
| T4 | Alice uploads 1 MB file | Chain record has `keyVersion=1`, `uploaderSig` non-empty; proxy logs show only ciphertext |
| T5 | Bob downloads | Plaintext equals original; HMAC equals on-chain `contentMac` |
| T6 | Dave fetches CID directly from IPFS | Gets bytes, cannot decrypt (no key) |
| T7 | Tamper test: flip one byte of the stored blob (test hook) | GCM tag failure on download |
| T8 | Replay a captured upload request | `401 REPLAY` |
| T9 | Request with timestamp 5 minutes old | `401 STALE_TIMESTAMP` |
| T10 | Bob in G1 and G2; Alice only G1 | Alice → `403` on G2 files; Bob reads both |
| T11 | Alice removes Bob from G1 | `currentVersion=2`; **no** change to existing files or IPFS pins |
| T12 | Bob requests key v1 and v2 after removal | Both `403` |
| T13 | Carol uploads file F2 | `keyVersion=2`; Bob cannot fetch the key |
| T14 | Carol downloads old file F1 | Works using v1 key |
| T15 | Upload prepared with v1 after rotation | `409 STALE_KEY_VERSION`; client retries and succeeds |
| T16 | File removal by uploader, owner, and a third member | Allowed, allowed, `403`; chain shows `Removed`; download fails |
| T17 | Perform 4 revocations (versions up to v5), with files under v1..v4 | `admin status` shows trigger fires (`5 - 1 > 3`) |
| T18 | Run re-encryption | All active records now `keyVersion=5`; old records `Superseded`; `contentMac` unchanged; downloading by **old** `recordId` still works |
| T19 | Kill the job midway (throw after `BLOB_ADDED`), rerun | Finishes; no duplicate records; no orphan pins |
| T20 | After purge, request key v1 | `410 KEY_PURGED`; `KeyPurged` event on chain |
| T21 | Download racing a purge | Client re-resolves and succeeds on retry |
| T22 | Owner tries to remove self | Rejected |

## 3. Evaluation (your headline result)

The paper has no evaluation, so any measurements are a contribution.

### 3.1 Metrics and setup

- Machine specs, Node/Kubo/Hardhat versions, all-local setup (state this: network effects are excluded).
- Repeat each measurement 5 times; report mean and standard deviation.

### 3.2 Experiments

| Exp | Variable | Measure | Notes |
|---|---|---|---|
| E1 Upload latency | file size: 1 KB, 100 KB, 1 MB, 10 MB, 50 MB | total, plus breakdown: client encrypt, transfer, IPFS add, chain write | Use `--time` |
| E2 Download latency | same sizes | total, plus breakdown: chain read, IPFS fetch, key fetch, decrypt, verify | |
| E3 Revocation cost | N files in group: 10, 50, 100 (each 1 MB), 1 revocation | wall-clock time and bytes read/written on IPFS | **Compare:** (a) *paper-style*: re-encrypt all N immediately (run the W10 job for all files straight after rotation), (b) *yours*: rotate only |
| E4 Amortized cost | R = 10 revocations, N = 50 files | cumulative cost over time | (a) paper-style: re-encrypt after each revoke; (b) yours with T = 3, so a batch every ~3-4 revokes; (c) yours with T = ∞ |
| E5 Key storage | versions alive at proxy over R revocations | count | Show the purge sawtooth with T = 3 |
| E6 Chain overhead | gas per `addRecord`, `supersede`, `markRemoved`, `logGroupEvent` | gas units | Read from receipts |

To implement E3(a) without writing a second system, add an env flag `REVOKE_MODE=eager` that makes W8 call the W10 job immediately for all records, then run both modes on the same data.

Expected shape: revocation cost for the paper-style design grows linearly with N × file size, yours is constant. E4 shows you converge back toward the paper's cost if T is small, so the plot of cost vs T is your trade-off curve (security freshness vs cost).

### 3.3 Result tables to fill

```
Table 1  Upload/download time vs file size (mean ± sd, ms)
Table 2  Revocation time vs N (paper-style vs proposed)
Table 3  Cumulative cost over R revocations for T ∈ {1, 3, ∞}
Table 4  Gas per contract call
```

## 4. Threat model (put this in the report)

**Assets:** file confidentiality, file integrity, attribution of uploads, group membership integrity.

**Trust assumptions:**
- Proxy: trusted and honest. It holds all live group keys, so a compromised proxy exposes every group. It is also a single point of failure and availability.
- IPFS: untrusted. Sees only ciphertext.
- Blockchain: integrity trusted, confidentiality none (all fields public).
- Clients: trusted while members; local key files are protected only by filesystem permissions.

**Attacks considered and mitigations**

| Attack | Mitigation |
|---|---|
| Outsider downloads ciphertext by CID | GCM ciphertext; no key without membership |
| Forged requests | Ed25519 signature on every request |
| Replay | Timestamp window + nonce table |
| Ciphertext tampering or swapping | GCM tag; AAD binds group + version; on-chain `ctHash`, `contentMac` |
| Uploader denies upload | `uploaderSig` stored on chain |
| Revoked user fetches new keys or reads new files | Membership check on all key versions; stale-version uploads rejected; new files use the new key |
| Proxy sees plaintext on upload | Not possible (sender-side encryption); **but** it sees plaintext transiently during re-encryption |
| Chain forgery | Only the proxy address can write; clients verify signatures and hashes |

**Out of scope / not mitigated (be honest):**
- **Lazy revocation.** A revoked user keeps any key they cached and can still fetch old ciphertext by CID. Files under old versions stay readable to them until re-encrypted and unpinned. Even then, copies on other IPFS nodes or on the user's disk cannot be recalled.
- **Window of exposure** between revocation and re-encryption is `T`-dependent. Smaller `T` means less exposure and more cost; this is the trade-off in E4.
- **Metadata leakage on chain:** group IDs, pseudonymous user IDs, sizes, timestamps, CIDs, membership events.
- **Proxy compromise or downtime:** no keys, no access. No threshold or multi-proxy design.
- **Hash key is not rotated:** a revoked member keeps `hashKey` (only useful for confirming guesses of file contents).
- **No forward secrecy for group keys** and no protection against a malicious owner.
- **Local identity files are not passphrase-protected** unless you add that.
- Rollback: SQLite could be restored to an older state by an admin; the chain is the truth for files, but membership state lives only in the proxy. Optionally the chain's `GroupEvent` log lets you audit this.

## 5. Cut list (if you fall behind, drop in this order)

1. Passphrase protection of client identities.
2. Filename metadata inside blob.
3. Owner approval of re-joining revoked users.
4. `group leave` (W9).
5. Uploader signature verification on download (W6 step 6).
6. Automatic trigger of re-encryption → manual `admin reencrypt`.
7. E4/E5 experiments → keep E1, E2, E3, E6.

**Never cut:** sender-side encryption, key versioning, revocation test T11 to T14, E3 comparison, the lazy-revocation caveat in the report.

## 6. Common pitfalls checklist

- [ ] Hash the **raw** request bytes for the signature, not re-serialized JSON.
- [ ] Persist job state **before** each side effect in W10.
- [ ] `keyVersion` check in upload uses the DB inside the same transaction that reads `current_version`.
- [ ] Never log keys, plaintext, or unsealed group keys.
- [ ] GCM: new random IV every encryption; never decrypt-then-use before the tag verifies.
- [ ] Use `Buffer`/`bytes32` conversions consistently (hex with/without `0x`) between Node and ethers.
- [ ] Kubo: `ipfs pin rm` only removes the pin; run `ipfs repo gc` to free the bytes.
- [ ] Hardhat restarts wipe the chain: redeploy and reset the proxy DB together, or keep a `reset.sh`.
- [ ] Set `express.raw({limit: ...})` big enough for the largest benchmark file.
