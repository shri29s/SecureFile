# 02: Workflows

Conventions:
- "signed request" = request authenticated as in `01` section 6.
- `P` = proxy, `C` = client, `IPFS` = Kubo node, `CH` = chain.
- Every workflow lists **preconditions, steps, postconditions, failures**.
- Paper step numbers are noted where a workflow maps to the paper (Steps 1 to 10).

---

## W1. User registration

**Actors:** any new user (future owner or member). Maps to paper Step 1 (registration), but registration is separated from group creation.

**Preconditions:** none.

**Steps**
1. C generates an Ed25519 signing pair and an RSA-OAEP 3072 encryption pair; computes `userId = hex(sha256(signPub))`; saves `identity.json`.
2. C sends `POST /users/register` with `{name, signPub, encPub, selfSig}`, where `selfSig = Ed25519(signPriv, "SFS-REG-v1|" + userId + "|" + encPub)` (proof of possession).
3. P recomputes `userId` from `signPub`, verifies `selfSig`, and checks `userId` is not already registered.
4. P inserts into `users` and returns `{userId}`.

**Postconditions:** public keys are in the proxy's directory (`GET /users/:id` returns them; used later to verify uploader signatures).

**Failures:** `409 USER_EXISTS`, `400 BAD_SELF_SIGNATURE`.

---

## W2. Owner creates a group

**Actors:** registered user becomes owner. Maps to paper Step 1 (group creation, `group_id` issued).

**Preconditions:** W1 done.

**Steps**
1. C sends signed `POST /groups {name}`.
2. P generates `groupId` (16 random bytes), `K_1 = randomBytes(32)`, `hashKey = randomBytes(32)`.
3. P inserts `groups(current_version=1)`, `group_members(owner, active)`, `group_keys(version 1, reason='create')` (sealed).
4. P calls `CH.logGroupEvent(groupId, GroupCreated, ownerId, 1)`.
5. P returns `{groupId, currentVersion: 1}`.

**Postconditions:** group exists with one active member (the owner) and one key version.

**Failures:** `401` auth errors only.

---

## W3. User requests to join a group

**Actors:** registered user, who must know the `groupId` (shared out of band by the owner). Maps to paper Step 6.

**Preconditions:** W1 done; user is not already `active` in the group.

**Steps**
1. C sends signed `POST /groups/:groupId/join-requests`.
2. P checks the group exists and the user's current status:
   - none, `rejected`, `left` → insert/update to `pending`
   - `revoked` → **`403 REVOKED`** (revoked users cannot rejoin through this path; the owner would have to explicitly re-approve, see W4 note)
   - `active` → `409 ALREADY_MEMBER`
3. P returns `{status: 'pending'}`.

**Postconditions:** a pending row exists; the user still has **no** key access.

---

## W4. Owner approves (or rejects) a member

**Actors:** owner. Maps to paper Step 6 ("A new user needs to receive permission by the group owner").

**Preconditions:** requester is the group owner; target is `pending`.

**Steps**
1. Owner lists requests with signed `GET /groups/:groupId/join-requests` (returns `userId, name, createdAt`).
2. Owner sends signed `POST /groups/:groupId/members {userId, decision: 'approve'|'reject'}`.
3. P verifies the caller is the owner (`groups.owner_id`).
4. **Approve:** set status `active`, `joined_at = now`. **No key rotation is needed.** P calls `CH.logGroupEvent(groupId, MemberAdded, userId, currentVersion)`.
   **Reject:** set status `rejected`.
5. P returns the new status.

**Postconditions:** an approved member can fetch **any non-purged key version** (decision D7), therefore can read all existing files. The member's wrapped keys are generated on demand (W12), not stored.

**Note (re-adding a revoked user):** allowed only if the owner explicitly approves again; implement as "owner can approve a `revoked`/`left` user if that user has a pending request". Keep this as a stretch goal. Skipping it is fine.

**Failures:** `403 NOT_OWNER`, `404 NO_PENDING_REQUEST`.

---

## W5. File upload (sender-side encryption)

**Actors:** active member. Maps to paper Steps 2 to 5, with encryption moved to the client.

**Preconditions:** uploader is an `active` member.

**Steps**
1. **Fetch key.** C performs W12 for `current` and gets `{version v, K_v, hashKey}`.
2. **Hash.** C computes `contentMac = HMAC-SHA256(hashKey, plaintext)`.
3. **Encrypt.** C builds the blob: `0x01 || IV || AES-256-GCM(K_v, IV, plaintext, AAD) || tag`, with `AAD = "SFS-BLOB-v1" | groupId | v`.
4. **Manifest.** C computes `ctHash = sha256(blob)`, builds the canonical manifest string (`01` section 5) and signs it: `uploaderSig`.
5. **Send.** C sends signed `POST /groups/:groupId/files` with `{manifest fields, uploaderSig, blob}` (JSON+base64 is fine; raw body + manifest header is better for large files).
6. **Authorize.** P checks: caller is `active` member; `manifest.uploaderId == caller`; `keyVersion == groups.current_version` (else **`409 STALE_KEY_VERSION`**, client repeats from step 1); manifest `size` equals blob length; `sha256(blob) == ctHash`; `uploaderSig` is valid against the caller's `signPub`; manifest nonce/timestamp is fresh.
7. **Store.** P adds the blob to IPFS (`pin: true`) → `cid`. (Paper Step 3.)
8. **Record.** P calls `CH.addRecord(groupId, uploaderId, contentMac, ctHash, cid, v, size, uploaderSig)` → `recordId`, tx hash. (Paper Step 4.)
9. P inserts the `files` mirror row and returns `{recordId, cid, txHash}`. (Paper Step 5; `recordId` is the `trans_id`.)

**Postconditions:** blob pinned on IPFS; immutable record on chain; the proxy never saw plaintext.

**Failure/ordering:** if step 8 fails after step 7, **unpin** the CID (best-effort) and return `502`. Never return success without the chain record.

---

## W6. File download

**Actors:** active member. Maps to paper Steps 7 to 10.

**Preconditions:** the user knows a `recordId` (from the uploader, or from W11 listing).

**Steps**
1. **Resolve.** C reads `CH.getRecord(recordId)` and, while `supersededBy != 0`, follows to the latest record. If final `status == Removed` → "file removed".
2. **Fetch ciphertext.** From P (`GET /ipfs/:cid`, signed) or **directly from IPFS** by CID. The blob is public either way.
3. **Fetch key.** C performs W12 for `record.keyVersion`. If `410 KEY_PURGED`: the file was re-encrypted meanwhile, so go back to step 1 once.
4. **Decrypt.** Parse blob; verify `sha256(blob) == record.ctHash`; AES-GCM decrypt with `K_v` and the same AAD. A tag failure means abort.
5. **Verify integrity.** Recompute `HMAC(hashKey, plaintext)` and compare with `record.contentMac`. (Paper step 10 "compare hash".)
6. **Verify origin (optional but cheap).** If the record is an original (`supersedes == 0`), fetch the uploader's `signPub` (`GET /users/:id`), rebuild the manifest string, and verify `uploaderSig`.
7. Write plaintext to `--out`.

**Postconditions:** plaintext on the client, integrity checked against the chain.

**Outsider test:** a non-member can run steps 1 and 2 (ciphertext obtained) but step 3 returns `403`, so decryption is impossible.

---

## W7. File removal

**Actors:** the original uploader, or the group owner.

**Preconditions:** record is the *latest* and `Active`.

**Steps**
1. C resolves the latest record (follow `supersededBy`) and sends signed `DELETE /groups/:groupId/files/:recordId`.
2. P verifies: caller is `active` member **and** (`caller == uploaderId` **or** caller is owner).
3. P calls `CH.markRemoved(recordId, callerId)`. The chain keeps the record as a **tombstone**; history is never erased.
4. P unpins the CID on its IPFS node (`pin/rm`); optionally runs `repo/gc` to reclaim space. Updates `files.status = 'removed'`.
5. P returns `{removed: true}`.

**Postconditions:** the file is no longer downloadable through the system.

**Caveat (document):** other IPFS nodes that cached the ciphertext may still hold it. It is encrypted, but a holder of the matching group key could still decrypt it. Deletion on IPFS is best effort.

---

## W8. Member removal (revocation with key versioning): *your improvement #2*

**Actors:** owner.

**Preconditions:** target is `active`; target is not the owner.

**Steps**
1. Owner sends signed `DELETE /groups/:groupId/members/:userId` (or `POST .../revoke`).
2. P verifies caller is owner.
3. P **atomically** (single DB transaction):
   a. sets target `status = 'revoked'`, `ended_at_version = current_version`;
   b. generates `K_{n+1} = randomBytes(32)`, inserts `group_keys(version n+1, reason 'revoke')`;
   c. sets `groups.current_version = n+1`.
4. P calls `CH.logGroupEvent(MemberRemoved, userId, n)` and `CH.logGroupEvent(KeyRotated, ownerId, n+1)`.
5. P **does not touch any existing file or key**. No re-encryption.
6. P evaluates the threshold (W10 trigger). If exceeded, it enqueues the job.
7. P returns `{currentVersion: n+1}`.

**Effects (these are your acceptance criteria):**
- The revoked user's requests to `GET .../keys/*` → `403` for **every** version, including old ones (decision D8).
- Remaining members: new uploads use `v(n+1)`; old files still decrypt using `K_n` etc. fetched on demand.
- Any in-flight upload from a member using `v(n)` is rejected with `409 STALE_KEY_VERSION` and retried with `v(n+1)`. This prevents new content from being written under a key the revoked user holds.
- **Cost: O(1)** (one key, two chain events), independent of the number of files.

**Lazy-revocation caveat:** the revoked user still holds `K_1..K_n` if they cached them, and old ciphertext on IPFS remains fetchable by CID. They can read every file stored under those versions until it is re-encrypted and unpinned (W10).

---

## W9. Member leaves voluntarily

Same as W8 with these differences: the caller is the member themself, status becomes `left`, and chain event is `MemberLeft`. A key rotation still happens (the leaving user holds old keys). Owners cannot leave while the group exists (out of scope: group deletion/ownership transfer).

---

## W10. Threshold re-encryption and key purge: *your improvement #3*

**Actors:** proxy (automatic or manual trigger).

**Trigger** (evaluated after every revocation/leave, and available as `admin reencrypt`):

```
oldestInUse = MIN(key_version) over files WHERE group_id=? AND status='active'
trigger if (current_version - oldestInUse) > T          -- T=3 by default
```

**Job (per group)** processes every active record with `key_version < current_version` (decision D11). Each record has one row in `reencrypt_jobs`, advancing through states that are **persisted before each side effect**:

| State | Action | Resume rule |
|---|---|---|
| `PENDING` | fetch blob from IPFS; decrypt with `K_old`; verify GCM tag and `HMAC(hashKey, plaintext) == record.contentMac` (abort the job for this record if mismatch) | restart from here |
| (decrypt→encrypt) | encrypt with `K_current` (fresh IV, new AAD) → `newBlob` | |
| `BLOB_ADDED` | `IPFS.add(newBlob)` → `newCid`; **store `newCid` in the job row** | on resume, reuse `newCid`; do not add again |
| `CHAIN_WRITTEN` | `CH.supersede(oldId, newCid, currentVersion, newCtHash, newSize)` → `newId`; store `newId` | contract **reverts if old is no longer Active**; on revert, treat as already done and read `supersededBy` |
| `OLD_UNPINNED` | unpin old CID | idempotent |
| `DONE` | update `files` mirror (old `superseded`, new row `active`) | |

Properties:
- **Idempotent and crash-safe**: re-running the job picks up unfinished rows. Chain `supersede` is atomic and single-shot.
- **Plaintext exposure:** the proxy holds plaintext **in memory only** during this step. Say so in the threat model.
- `recordId`s held by users stay valid: step 1 of W6 follows `supersededBy`.

**Purge** (after the job): for each version `v < current_version` with **zero** `Active` records referencing it **and** no unfinished job rows:
1. set `group_keys.key_sealed = NULL`, `purged_at = now`;
2. `CH.logGroupEvent(KeyPurged, ownerId, v)`.

After purge, `GET .../keys/v` returns `410 KEY_PURGED`.

**What this buys you (state precisely in the report):**
- Old key versions no longer exist at the proxy, so the proxy's attack surface and key inventory shrink.
- Old ciphertext is unpinned from the proxy node, which reduces availability for a revoked user. It does **not** guarantee deletion from other IPFS nodes.
- It does **not** retroactively revoke anything a revoked user already copied.

---

## W11. Listing files / auditing

**Steps**
1. C calls `CH.getGroupRecords(groupId)` and loads each record (or uses signed `GET /groups/:groupId/files`, which reads the `files` mirror).
2. Show `recordId, uploaderId, keyVersion, size, timestamp, status`, hiding `Superseded` records by default.
3. Audit view: fetch `GroupEvent` logs (`GroupCreated`, `MemberAdded`, `MemberRemoved`, `KeyRotated`, `KeyPurged`) to show the group's history. This is a nice demo for the report.

---

## W12. Group key retrieval (sub-workflow used by W5/W6/W10)

**Steps**
1. C sends signed `GET /groups/:groupId/keys/:version` (`version` may be `current`).
2. P checks the caller is an `active` member of the group. Any other status → `403` (this is where revocation is enforced for **all** versions).
3. P resolves the version (`current` → `groups.current_version`); if the row has `purged_at` → `410 KEY_PURGED`; if missing → `404`.
4. P unseals `K_v`, builds `payload = K_v || hashKey`, wraps with RSA-OAEP using the caller's `encPub` from `users`.
5. P returns `{version, wrapped: base64}`; C unwraps with `encPriv`, optionally caches in `keycache.json`.

---

## W13. One user in multiple groups (paper section 3.6)

Nothing special in the protocol. Membership, keys and mapping are all keyed by `(groupId, userId)`. The same RSA key wraps keys for every group. Test: Bob in group 1 and group 2 can open files of both; Alice (group 1 only) gets `403` for group 2; Charlie (group 2 only) gets `403` for group 1.

---

## State summary of a member

```
(none) --join--> pending --approve--> active --revoke--> revoked
                    |                    |
                    +--reject--> rejected +--leave--> left
```
