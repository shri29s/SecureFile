# SFS: Secure File Sharing on IPFS + Blockchain (Project Context)

Base paper: *A Secure File Sharing System Based on IPFS and Blockchain* (Huang, Chang, Wu, IECC 2020).
This document set specifies the implementation of the paper's design **plus three improvements**.

| File | Contents |
|---|---|
| `00_overview.md` | This file: goals, paper-vs-ours, architecture, trust model, stack, fixed decisions |
| `01_data_and_crypto.md` | Identifiers, crypto primitives, blob/manifest formats, request auth, DB schema, smart contract spec |
| `02_workflows.md` | Step-by-step workflows: register, create group, join, approve, upload, download, remove file, remove member, leave, re-encrypt, purge |
| `03_api_and_cli.md` | HTTP endpoints, error codes, CLI commands |
| `04_plan_testing_eval.md` | 6-hour plan, test cases, evaluation, threat model, caveats, cut list |
| `05_ui_spec.md` | **Demo UI** (React + WebCrypto), extra backend endpoints, attacker/inspector panels, demo script, **revised time plan (overrides `04` section 1)** |

---

## 1. Goal

A group-based file sharing system where:
- Large files live on **IPFS** (as ciphertext only).
- **Blockchain** keeps a tamper-proof record of every upload (who, which group, hash, CID, key version).
- A trusted **IPFS Proxy** handles registration, group membership, access control and group-key custody.
- Members can create groups, join several groups, and only read files of groups they belong to.

## 2. The three improvements over the paper (your ideas)

1. **Client-side (sender-side) encryption.** The sender encrypts before upload. The proxy never receives plaintext on upload.
2. **Versioned group keys; no re-encryption on revocation.** Each group has keys `v1, v2, ...`. Revoking a member creates `v(n+1)`. Old files stay under their old version. Only *new* files use the new key.
3. **Threshold re-encryption.** When too many key versions are in use (`currentVersion - oldestVersionInUse > T`), the proxy migrates old files to the latest key in a background/batch job, then **purges** unreferenced old keys.

### Paper vs this implementation

| Aspect | Paper | This implementation | Reason |
|---|---|---|---|
| Who encrypts | Proxy | **Sender client** | Proxy never sees plaintext on upload |
| Cipher | Symmetric, e.g. AES-CBC | **AES-256-GCM** | Built-in integrity/authenticity |
| Group key | One key, replaced on revoke | **Versioned keys v1..vn** | O(1) revocation |
| Revocation | Re-encrypt *all* files immediately | **New key only; old files untouched** | Cheap revocation |
| Re-encryption | Always, on every revoke | **Deferred, threshold-triggered batch** | Amortized cost |
| Key delivery | Extra "key wrapping key" | **RSA-OAEP wraps the group key directly** | One less layer |
| File hash on chain | Raw hash | **Keyed HMAC** | Raw hash lets anyone confirm a known file exists |
| Chain record | group_id, user_id, file_hash, IPFS_hash | **+ keyVersion, ctHash, size, uploaderSig, status, supersedes/supersededBy** | Versioning, supersession, non-repudiation |
| Request security | Signed requests | **Signed + timestamp + nonce** | Replay protection |
| File deletion | Not covered | **Tombstone on chain + unpin** | Completeness |
| Evaluation | None | **Benchmarks vs paper-style revocation** | Your headline result |

## 3. Architecture

```
                     signed HTTPS/HTTP requests
   +-----------+  ----------------------------->  +--------------------+
   |  Client   |   (ciphertext, wrapped keys)     |     IPFS PROXY     |
   |  (CLI)    |  <-----------------------------  |  (Node + Express)  |
   |           |                                  |  - registry (DB)   |
   | - keygen  |                                  |  - group key store |
   | - AES-GCM |                                  |  - access control  |
   | - sign    |                                  |  - chain writer    |
   +-----+-----+                                  |  - re-encrypt job  |
         |                                        +----+----------+----+
         | read-only (chain + optional direct IPFS)    |          |
         |                                             |          |
         v                                             v          v
   +-----------+                              +-------------+  +-------------+
   | Blockchain| <----- write (proxy only) ---| IPFS (Kubo) |  |  Hardhat    |
   | (records) |                              | ciphertext  |  |  local node |
   +-----------+                              +-------------+  +-------------+
```

- **Client** reads the chain directly (public) and may read ciphertext from IPFS directly or via the proxy.
- **Only the proxy writes** to the chain (as in the paper). The contract rejects writes from any other address.
- Client-to-proxy traffic is always signed. Group keys only ever leave the proxy wrapped under the requester's public key.

## 4. Entities and trust model

| Entity | Role | Trust |
|---|---|---|
| Owner | Creates group, approves/removes members, can remove any file in the group | Trusted after registration |
| Member | Uploads/downloads group files | Trusted after approval; **untrusted after revocation** |
| Proxy | Registry, access control, key custody, chain writer, re-encryption | **Fully trusted** (single point of failure; see caveats) |
| IPFS | Stores ciphertext | **Untrusted**; anyone with the CID can fetch |
| Blockchain | Append-only record of uploads and group events | Trusted for integrity/ordering, **public** (no confidentiality) |

## 5. Tech stack (fastest path)

- **Proxy:** Node.js 20+, Express, `better-sqlite3`
- **IPFS:** local Kubo daemon + `kubo-rpc-client` (ESM-only: set `"type": "module"`)
- **Chain:** Hardhat local node, one Solidity contract, `ethers` v6
- **Crypto:** Node built-in `crypto` only
- **Client:** CLI (`commander` or plain `process.argv`). **No UI.**

## 6. Repository layout

```
sfs/
  contracts/FileRegistry.sol
  scripts/deploy.js                  # writes deployment.json {address, abi path}
  proxy/
    src/server.js                    # express app bootstrap
    src/config.js                    # env: PORT, RPC_URL, PROXY_PK, PROXY_MASTER_KEY, IPFS_API, T
    src/db.js                        # sqlite init + queries
    src/auth.js                      # signature/timestamp/nonce middleware
    src/crypto.js                    # seal/unseal keys, RSA wrap, verify sig
    src/chain.js                     # contract wrapper (proxy signer)
    src/ipfs.js                      # add/cat/pin/unpin
    src/routes/users.js
    src/routes/groups.js             # create, join, approve, remove, leave
    src/routes/keys.js
    src/routes/files.js              # upload, download, remove, list
    src/jobs/reencrypt.js            # threshold job + purge
  client/
    src/cli.js
    src/keystore.js                  # local key files per identity
    src/crypto.js                    # AES-GCM, HMAC, sign, unwrap
    src/api.js                       # signed request helper
    src/chain.js                     # read-only contract access
  test/                              # scenario scripts (see 04)
  bench/                             # benchmark scripts
  docs/                              # report, threat model
```

## 7. Fixed decisions (do not reopen these during the 6 hours)

| # | Decision | Value |
|---|---|---|
| D1 | Who writes to chain | Proxy only (contract `onlyProxy`) |
| D2 | Signature scheme | Ed25519 |
| D3 | Key-wrap scheme | RSA-OAEP, 3072-bit, SHA-256 |
| D4 | File cipher | AES-256-GCM, random 12-byte IV per file, 16-byte tag |
| D5 | File is encrypted directly with the group key of version `v` | (no per-file key layer) |
| D6 | Content hash | HMAC-SHA256 with a per-group, **never-rotated** `hashKey` |
| D7 | New members can read all non-purged key versions | (see W4) |
| D8 | Revoked/left members are refused **all** versions, forever | |
| D9 | Upload must use exactly `currentVersion` | else `409 STALE_KEY_VERSION` |
| D10 | Re-encryption threshold `T` | 3 (configurable via env) |
| D11 | Re-encryption migrates **all** records below `currentVersion` once triggered | then purges unreferenced keys |
| D12 | Pseudonymous IDs on chain | `userId = sha256(signPub)`, `groupId = random 16 bytes` |
| D13 | Storage at proxy | SQLite; group keys sealed with `PROXY_MASTER_KEY` |
| D14 | Replay window | timestamp ±60 s, nonce unique per user for 120 s |

## 8. Glossary

- **Group key `K_v`**: 32-byte AES key, version `v`, per group.
- **hashKey**: 32-byte per-group HMAC key (constant across versions).
- **Record**: on-chain entry describing one stored ciphertext.
- **recordId**: the on-chain index of a record. The first record of a file is the file's permanent handle (`trans_id` in the paper).
- **Supersede**: a re-encrypted file gets a *new* record; the old record points forward via `supersededBy`. Following `supersededBy` always leads to the latest record.
- **Lazy revocation**: revoked users lose future access, but anything they already hold keeps working (see `04`).
