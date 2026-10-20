# 01: Data Model, Crypto, Formats, Contract

## 1. Identifiers

| ID | Definition | Notes |
|---|---|---|
| `userId` | `hex(sha256(signPubDER))` (32 bytes) | Pseudonymous; derived from the signing public key |
| `groupId` | 16 random bytes, hex; padded to `bytes32` on chain | Created by proxy |
| `keyVersion` | `uint32`, starts at 1 | Per group |
| `recordId` | `uint256`, auto-increment from 1 in contract | `0` means "none" |
| `cid` | IPFS CID string of the ciphertext blob | |

## 2. Client key material

Each identity (e.g. `alice`) has a folder `~/.sfs/<name>/`:

```
identity.json
  { name, userId, signPub, signPriv, encPub, encPriv }   // PEM/DER base64
keycache.json   (optional)
  { "<groupId>": { "<version>": { key, hashKey } } }     // unwrapped group keys
```

- **Signing pair:** Ed25519 (identity + request/manifest signatures).
- **Encryption pair:** RSA-OAEP 3072 (only used to receive wrapped group keys).
- Two separate pairs: do not reuse one key for signing and encryption.
- Optional: encrypt `identity.json` with a passphrase. Skip if short on time and note it in the report.

## 3. Crypto primitives

| Purpose | Primitive | Node API |
|---|---|---|
| Identity / request / manifest signature | Ed25519 | `crypto.generateKeyPairSync('ed25519')`, `crypto.sign(null, data, priv)`, `crypto.verify(null, data, pub, sig)` |
| Group key delivery | RSA-OAEP-SHA256, 3072-bit | `crypto.publicEncrypt({key, oaepHash:'sha256', padding: RSA_PKCS1_OAEP_PADDING}, buf)` / `privateDecrypt` |
| File encryption | AES-256-GCM | `createCipheriv('aes-256-gcm', key, iv)`, `setAAD`, `getAuthTag` |
| Content MAC | HMAC-SHA256 | `createHmac('sha256', hashKey)` |
| Ciphertext hash | SHA-256 | `createHash('sha256')` |
| Keys at rest on proxy | AES-256-GCM under `PROXY_MASTER_KEY` | same as file cipher |
| Randomness | `crypto.randomBytes` | keys, IVs, nonces, groupId |

Rules:
- **Never reuse an IV under the same key.** Random 12 bytes per encryption.
- RSA-OAEP payload for key delivery: `K_v (32 bytes) || hashKey (32 bytes)` = 64 bytes. This fits comfortably under the OAEP limit for 3072-bit keys.
- GCM random-IV limit: stay far below ~2^32 files per key version. Not a concern at this scale; mention in the report.

## 4. Encrypted blob format (what is stored on IPFS)

```
offset  size   field
0       1      format version = 0x01
1       12     IV
13      N      ciphertext (same length as plaintext)
13+N    16     GCM auth tag
```

- **AAD (additional authenticated data):** `"SFS-BLOB-v1" | groupId | keyVersion(4 bytes BE)`.
  This binds the ciphertext to its group and key version so blobs cannot be silently moved between groups.
- Re-encryption produces a new blob (new IV, new key version in AAD, therefore a new CID).
- Optional: put `{filename, mime}` as a length-prefixed JSON header *inside* the plaintext so filenames never reach IPFS or the chain. Cut this if short on time; the CLI can take `--out` instead.

## 5. Upload manifest (signed by the uploader)

Canonical string (UTF-8, `|`-separated, fixed order, hex for byte fields):

```
SFS-UPLOAD-v1|groupId|uploaderId|contentMac|ctHash|keyVersion|size|clientTs|nonce
```

- `contentMac = HMAC-SHA256(hashKey, plaintext)`
- `ctHash = SHA-256(blob)` (the full blob including version byte, IV and tag)
- `size = blob length in bytes`
- `uploaderSig = Ed25519(signPriv, canonical string)`

The proxy verifies `uploaderSig`, recomputes `ctHash` from the received blob, then stores `uploaderSig` **on chain** so the upload stays attributable even if the proxy is later compromised.

## 6. Request authentication (every call except registration)

Headers:

```
X-User-Id:   <userId>
X-Timestamp: <unix ms>
X-Nonce:     <16 random bytes hex>
X-Signature: <base64 Ed25519 signature>
```

Signed string:

```
SFS-REQ-v1\n<METHOD>\n<PATH+QUERY>\n<X-Timestamp>\n<X-Nonce>\n<hex sha256(raw body)>
```

Proxy middleware order:
1. Look up `userId` in `users`; get `signPub`. Unknown means `401`.
2. Reject if `|now - ts| > 60 s` (`401 STALE_TIMESTAMP`).
3. Reject if `(userId, nonce)` already in `nonces` (`401 REPLAY`); otherwise insert with expiry `now + 120 s`.
4. Verify signature over the string above (`401 BAD_SIGNATURE`).
5. Attach `req.user`. Group-level authorization happens in route handlers.

Body hashing: use `express.raw()` (or `verify` callback of `express.json`) so you hash the **exact bytes** received.
Registration is the exception: the body carries both public keys and a self-signature (proof of possession).

## 7. Proxy database (SQLite)

```sql
users(
  user_id TEXT PRIMARY KEY,
  name TEXT,
  sign_pub TEXT NOT NULL,        -- base64 DER
  enc_pub  TEXT NOT NULL,        -- base64 DER
  created_at INTEGER
);

groups(
  group_id TEXT PRIMARY KEY,
  name TEXT,
  owner_id TEXT NOT NULL REFERENCES users,
  current_version INTEGER NOT NULL,
  hash_key_sealed BLOB NOT NULL, -- sealed under master key
  created_at INTEGER
);

group_members(
  group_id TEXT, user_id TEXT,
  role TEXT CHECK(role IN ('owner','member')),
  status TEXT CHECK(status IN ('pending','active','rejected','revoked','left')),
  joined_at INTEGER,
  ended_at_version INTEGER,      -- version that was current when access ended
  PRIMARY KEY(group_id, user_id)
);

group_keys(
  group_id TEXT, version INTEGER,
  key_sealed BLOB NOT NULL,      -- sealed under master key; set to NULL when purged
  reason TEXT,                   -- 'create' | 'revoke' | 'leave'
  created_at INTEGER,
  purged_at INTEGER,             -- NULL while live
  PRIMARY KEY(group_id, version)
);

files(                           -- local mirror of chain for fast queries
  record_id INTEGER PRIMARY KEY,
  group_id TEXT, uploader_id TEXT,
  cid TEXT, key_version INTEGER,
  status TEXT CHECK(status IN ('active','superseded','removed')),
  size INTEGER, tx_hash TEXT, created_at INTEGER
);

nonces(user_id TEXT, nonce TEXT, expires_at INTEGER, PRIMARY KEY(user_id, nonce));

reencrypt_jobs(
  old_record_id INTEGER PRIMARY KEY,
  group_id TEXT,
  state TEXT CHECK(state IN ('PENDING','BLOB_ADDED','CHAIN_WRITTEN','OLD_UNPINNED','DONE')),
  new_cid TEXT, new_record_id INTEGER,
  attempts INTEGER DEFAULT 0, updated_at INTEGER
);
```

The chain is the source of truth; `files` is a cache you can rebuild from chain events (`FileRecorded`, `FileSuperseded`, `FileRemoved`).

### Key sealing at rest
`sealed = IV(12) || AES-256-GCM(PROXY_MASTER_KEY, K_v) || tag(16)`. The master key comes from an env var, never from the DB. This is about 15 minutes of work and is worth mentioning in the threat model.

## 8. Smart contract spec: `FileRegistry.sol`

```solidity
enum Status { Active, Superseded, Removed }

struct Record {
  bytes32 groupId;
  bytes32 uploaderId;
  bytes32 contentMac;     // HMAC of plaintext
  bytes32 ctHash;         // sha256 of stored blob
  string  cid;
  uint32  keyVersion;
  uint64  size;
  uint64  timestamp;      // block.timestamp
  uint256 supersedes;     // 0 if original
  uint256 supersededBy;   // 0 if latest
  Status  status;
  bytes   uploaderSig;    // empty for re-encrypted records (see below)
}
```

State:
- `address public proxy;` set in constructor; modifier `onlyProxy`.
- `mapping(uint256 => Record) records; uint256 public recordCount;`
- `mapping(bytes32 => uint256[]) groupRecords;`

Write functions (all `onlyProxy`):

| Function | Behavior |
|---|---|
| `addRecord(groupId, uploaderId, contentMac, ctHash, cid, keyVersion, size, uploaderSig) -> recordId` | Appends record with `Active`; pushes to `groupRecords`; emits `FileRecorded` |
| `supersede(oldId, newCid, newKeyVersion, newCtHash, newSize) -> newId` | Requires `old.status == Active` and `newKeyVersion > old.keyVersion`. Creates a new `Active` record copying `groupId, uploaderId, contentMac`, with `supersedes = oldId`, empty sig. Sets `old.status = Superseded`, `old.supersededBy = newId`. Emits `FileSuperseded`. **Atomic and reverts if the old record is no longer Active, which makes the job idempotent.** |
| `markRemoved(recordId, requesterId)` | Requires `status == Active`. Sets `Removed`. Emits `FileRemoved(recordId, requesterId)` |
| `logGroupEvent(groupId, kind, subjectId, keyVersion)` | Emits `GroupEvent`. Kinds: `0 GroupCreated, 1 MemberAdded, 2 MemberRemoved, 3 KeyRotated, 4 KeyPurged, 5 MemberLeft` |

Read functions: `getRecord(id)`, `getGroupRecords(groupId) -> uint256[]`, `recordCount()`.

Events:
```
FileRecorded(uint256 indexed recordId, bytes32 indexed groupId, string cid, uint32 keyVersion)
FileSuperseded(uint256 indexed oldId, uint256 indexed newId)
FileRemoved(uint256 indexed recordId, bytes32 requesterId)
GroupEvent(bytes32 indexed groupId, uint8 kind, bytes32 subjectId, uint32 keyVersion)
```

Notes:
- **Re-encrypted records have no `uploaderSig`**: the original signature covered the old `ctHash`/`keyVersion`. Provenance is the `supersedes` link back to the signed original, plus the fact that only the proxy could write it. State this in the report. `contentMac` is unchanged across re-encryption (stable `hashKey`), so plaintext integrity can still be checked end-to-end.
- Everything on chain is public: `groupId`, `uploaderId`, `cid`, sizes, timestamps, membership events. IDs are pseudonymous, but mention metadata leakage in the report.
- Deploy script: deploy with Hardhat account #0 as `proxy`; write `{address}` to `deployment.json`; copy ABI for proxy and client.

## 9. Proxy configuration (env)

```
PORT=3001            # not 8080: Kubo's gateway already uses 8080
DEMO_MODE=1          # enables eager-revoke mode and /public/* demo endpoints (see 05)
RPC_URL=http://127.0.0.1:8545
PROXY_PK=<hardhat account #0 private key>
CONTRACT_ADDRESS=<from deployment.json>
IPFS_API=http://127.0.0.1:5001
PROXY_MASTER_KEY=<64 hex chars>
REENCRYPT_T=3
MAX_UPLOAD_MB=100
```
