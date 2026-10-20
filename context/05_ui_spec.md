# 05: Demo UI Specification

This file **extends** files 00 to 04. Where it conflicts with them (port number, client choice, time plan), **this file wins**.

## 1. What changes and why

| Topic | Before | Now | Reason |
|---|---|---|---|
| Primary client | CLI | **Browser UI** (CLI shrinks to test scripts) | Demo needs a UI; saves time overall |
| Client crypto | Node `crypto` | **One shared `client-core` module on WebCrypto** (`crypto.subtle`), used by both the browser and Node 20+ test scripts | Write crypto once, same bytes everywhere |
| Proxy port | 8080 | **3001** | Kubo's gateway already uses 8080 (this was a bug in file 01) |
| UI hosting | n/a | Proxy serves the built UI as static files at `/` | Same origin: no CORS work |
| Identities | Folders on disk | **IndexedDB**, one entry per demo identity, with an identity switcher | One browser plays Alice/Bob/Carol/Dave |

The wire formats are unchanged: SPKI DER public keys, PKCS8 private keys, Ed25519 64-byte signatures, RSA-OAEP-SHA256, AES-256-GCM, blob layout `0x01 || IV || ciphertext || tag`.
WebCrypto's AES-GCM output is already `ciphertext || tag`, so it is byte-compatible with the proxy's Node `createCipheriv` output in the re-encryption job.

## 2. Stack for the UI

| Layer | Choice |
|---|---|
| Build | Vite |
| UI | React (plain JS is fine) + Tailwind CSS |
| Crypto | WebCrypto via `client-core` (Ed25519, RSA-OAEP, AES-GCM, HMAC, SHA-256) |
| Chain reads | `ethers` v6 `JsonRpcProvider` pointing at Hardhat (`http://127.0.0.1:8545`), used by the Inspector and audit view |
| Storage | IndexedDB (via `idb-keyval` or raw) for identities and key cache |
| Charts | `recharts` (benchmark and version bars) |

Browser requirement: a current Chrome, Edge, Firefox or Safari (Ed25519 in WebCrypto). If the demo machine's browser lacks it, swap the sign/verify calls for `@noble/ed25519`; nothing else changes.

### Repo additions
```
client-core/            # shared, no DOM or Node-specific APIs
  src/crypto.js         # keygen, wrap/unwrap, encryptBlob, decryptBlob, hmac, sign, userId
  src/api.js            # signed fetch(): builds headers per file 01 section 6
  src/manifest.js       # canonical manifest string builder/verifier
  src/chainRead.js      # ethers read-only helpers
ui/
  index.html, vite.config.js
  src/main.jsx, App.jsx
  src/state/identity.js # IndexedDB + current identity context
  src/pages/{Groups,Group}.jsx
  src/components/{IdentityBar,FilesTab,MembersTab,KeysTab,AuditTab,InspectorTab,AttackerPanel,BenchPanel,Toasts}.jsx
test/                   # Node scripts using client-core (replaces the CLI for T1 to T22)
```

## 3. `client-core` rules

- **Private keys are non-extractable `CryptoKey` objects**, stored directly in IndexedDB (structured clone). Public keys are exported as SPKI DER to compute `userId = hex(sha256(signPubDER))`.
- **Group key cache** (per identity): `{groupId: {version: {aesKey: CryptoKey, hmacKey: CryptoKey}}}`, both non-extractable and stored in IndexedDB. Toggle in settings: **"Cache group keys on this device"** (default ON). This exists so the attacker demo (section 6) can show lazy revocation honestly.
- All large buffers are `Uint8Array`; base64 only at the JSON boundary.
- Every network call goes through `signedFetch(identity, method, path, body)`; the UI never builds auth headers by hand.
- `encryptBlob(aesKey, plaintext, groupId, version)` returns the blob; `decryptBlob(...)` throws a typed `TagError` on GCM failure so the UI can show "tampered".
- Max practical file size in-browser for the demo: ~50 MB (whole-buffer WebCrypto). Enforce in the UI.

## 4. Backend additions (the UI needs these; add to file 03)

| Method + Path | Who | Purpose |
|---|---|---|
| `GET /me/groups` | any registered user | `[{groupId, name, role, status, currentVersion}]` for the identity switcher's home page |
| `GET /groups/:g` (extend) | active member | add `members:[{userId, name, role, status}]` (all statuses visible to the owner; only `active` to others) |
| `GET /groups/:g/files` (extend) | active member | add `uploaderName`; hide `superseded` unless `?all=1` |
| `GET /admin/groups/:g/status` | **owner-authenticated** (not "local only" anymore) | `{currentVersion, T, versions:[{version, createdAt, reason, purgedAt, activeFiles}], oldestInUse, triggerFires, jobs:{pending,done}}`. Must never return key material |
| `POST /admin/groups/:g/reencrypt` | owner | run W10 now; return `{migrated, purgedVersions, elapsedMs}` |
| `DELETE /groups/:g/members/:userId?mode=lazy\|eager` | owner | `lazy` = your design (default). `eager` = paper-style: rotate **and** immediately run W10 on every record. Returns `{currentVersion, elapsedMs, filesReencrypted, bytesProcessed}`. Only honored when `DEMO_MODE=1` |
| `GET /public/ipfs/:cid` | **unauthenticated, `DEMO_MODE=1` only** | Raw ciphertext. Stands in for "anyone on the internet who knows the CID" (the outsider/attacker demo). You may instead use Kubo's gateway at `http://127.0.0.1:8080/ipfs/<cid>` |
| `GET /public/config` | unauthenticated | `{rpcUrl, contractAddress, abi, demoMode, T}` so the UI configures itself |
| static `/` | n/a | `express.static('ui/dist')` |

Additional job behavior for the demo: after W10 unpins old CIDs, call `ipfs.repo.gc()` so the old blobs are actually gone from the node (otherwise the "availability loss" demo step does not show).

Env additions: `DEMO_MODE=1`, `PORT=3001`.

## 5. Screens

### 5.1 Global: Identity bar (top of every page)
- Dropdown of local identities (name + short `userId`), **"New identity"** button (W1: generates keys, registers).
- Shows role/status badge for the open group.
- Shows connection health: proxy, IPFS, chain (green/red dots from `/public/config` and a ping).
- Toasts map error `code`s from file 03 to friendly messages.

### 5.2 Groups page (`/`)
- **My groups** from `GET /me/groups`, each card showing role, status (`active`, `pending`, `revoked`...), `currentVersion`.
- **Create group** (name) → W2.
- **Join group** (paste `groupId`) → W3, card appears as `pending`.
- Copy-to-clipboard on `groupId` (needed to invite people in the demo).

### 5.3 Group page (`/g/:groupId`), tabbed

**Files tab** (W5, W6, W7, W11)
- Drag-and-drop upload with a progress strip showing stages: `Fetching key → Encrypting → Signing → Uploading → Recorded on chain`. Show `recordId`, CID, `keyVersion` and tx hash on success.
- Table: name/recordId, uploader, size, **key version badge** (colour per version), timestamp, status. Actions: Download, Remove (if uploader/owner).
- Download shows the verification checklist as it runs: `Chain record ✓ · Ciphertext hash ✓ · Decrypted (GCM tag) ✓ · Content MAC matches chain ✓ · Uploader signature ✓`.
- Failure states shown clearly: **Access denied (not a member / revoked)**, **Tampered (tag failure)**, **Key purged, retrying**.
- Handle `409 STALE_KEY_VERSION` and `410 KEY_PURGED` with the single automatic retry from file 03, and show a small "retried with v3" note (nice to see in demo).

**Members tab** (W3, W4, W8, W9)
- Member table with status chips. Owner sees:
  - **Pending requests** with Approve / Reject.
  - **Remove** per member with a mode selector (visible when `demoMode`): **Lazy (this project)** vs **Eager (paper-style)**.
  - After removal, a result panel: `new version vN · elapsed X ms · files re-encrypted K · bytes processed B`. This is the live version of experiment E3.
- Non-owner members see **Leave group** (W9).

**Keys & Versions tab** (W8, W10, W12), the most important tab for your contribution
- Horizontal **version timeline** `v1 → v2 → v3 ...`, each block showing: created reason (create / revoke / leave), **number of active files** under it, and `purged` state (greyed with a lock icon).
- A **threshold gauge**: `currentVersion − oldestInUse = D` against `T`, with a "trigger will fire" indicator.
- **Run re-encryption now** button (W10) with progress from `status.jobs`, plus a result summary (migrated, purged versions, ms).
- No key bytes are ever displayed. Only metadata.

**Audit tab** (W11)
- Timeline built from chain `GroupEvent` logs (read **directly from the chain** with ethers, not from the proxy): created, member added, member removed, key rotated, key purged, plus `FileRecorded/Superseded/Removed`.
- Each entry shows block number and tx hash. Emphasize in the demo that this view does not depend on trusting the proxy.

**Inspector tab** (the "what does each party see?" panel)
Three side-by-side panes for a selected file:
1. **Chain**: the raw record fields (`groupId, uploaderId, contentMac, ctHash, cid, keyVersion, size, supersedes/supersededBy, status, uploaderSig`).
2. **IPFS**: the first 256 bytes of the stored blob as hex, with the layout annotated (`version | IV | ciphertext…`) and the line "Unreadable without the group key".
3. **Proxy**: the key metadata from `status` (versions, created, purged), and a statement that plaintext was never received on upload.
A **"Decrypt here"** button shows the plaintext only for the current identity if it is an active member.

### 5.4 Attacker panel (inside Inspector, or a separate `/attack` route)
Action buttons that run as the **currently selected identity**, so the presenter switches to Dave or a revoked Bob first:

| Button | Calls | Expected |
|---|---|---|
| "Fetch ciphertext by CID" | `GET /public/ipfs/:cid` | Succeeds → bytes shown as hex (**proves ciphertext is public**) |
| "Request group key v_current" | W12 | `403` for outsider/revoked |
| "Request old key v1" | W12 | `403` for revoked (**proves D8**) |
| "Decrypt with cached key" | local key cache | For a revoked user with cache ON: **succeeds on old files** (**lazy revocation, shown honestly**); fails for files under the new version |
| "Replay last request" | resend captured signed request | `401 REPLAY` |
| "Tamper & download" | test hook flips a byte before decrypt | GCM tag failure |

### 5.5 Benchmark panel (optional, `/bench`)
- Controls: N files, file size, number of revocations R, T.
- Runs the lazy vs eager revocation sequence on a scratch group using the same `?mode=` parameter.
- Output: bar chart of elapsed ms per revocation (eager vs lazy), and a cumulative-cost line chart. This replaces most of the manual work for experiments E3/E4.
- If time is short, make it a Node script and paste the numbers into the report instead.

## 6. Demo script (about 8 minutes)

Prepare with a `reset.sh` that restarts Hardhat, redeploys, wipes the proxy DB and clears IPFS data, then pre-creates Alice, Bob, Carol and Dave identities.

1. **Setup (30 s)**: Alice creates group "Project-X". Bob and Carol request to join; Alice approves.
2. **Upload (1 min)**: Alice uploads `report.pdf`. Show the stage strip. Open Inspector: the chain record has `keyVersion 1`; IPFS pane shows only ciphertext; proxy pane says "never saw plaintext".
3. **Download (30 s)**: Bob downloads; the verification checklist goes green.
4. **Outsider (1 min)**: Switch to Dave. Attacker panel: fetch by CID works (ciphertext), key request is `403`.
5. **Revocation (2 min)**: Alice uploads 5 more files first. Alice removes Bob using **Eager** mode and the result panel shows the cost (all files re-encrypted). Then removes another test member using **Lazy** and the cost is a few ms. This is the headline comparison.
6. **Versions (1 min)**: Keys tab: v1 → v2 timeline; new upload by Carol lands on v2; Carol still opens the old file. Bob (revoked) gets `403` on v1 and v2.
7. **Honest limitation (1 min)**: As Bob (cache ON), "Decrypt with cached key" works on the old file. Say it out loud: this is lazy revocation.
8. **Threshold fix (1 min)**: After enough revocations the gauge trips; run re-encryption; old versions show purged; old `recordId` still downloads for Carol via `supersededBy`; as Bob, "Fetch ciphertext by old CID" now fails (unpinned and GC'd on this node).
9. **Audit (30 s)**: Audit tab: every membership and key event, read straight from the chain.

## 7. Revised 6-hour plan (UI included)

The CLI is dropped as a client. Verify backend stages with small Node scripts using `client-core`, and build each UI screen **right after** its backend stage so you always have something demoable.

| Time | Work | UI delivered |
|---|---|---|
| 0:00 to 0:45 | Environment, contract, deploy script, Vite scaffold | n/a |
| 0:45 to 1:45 | Proxy core: DB, auth middleware, W1 to W4, W12, `/me/groups`, static hosting | Identity bar, Groups page, Members tab (join/approve) |
| 1:45 to 2:45 | `client-core` (crypto + signedFetch) and W5/W6 | Files tab (upload/download with checklist) |
| 2:45 to 3:30 | W7 removal, W8 revocation with `mode=lazy\|eager`, W9 | Remove/leave, revoke result panel |
| 3:30 to 4:15 | W10 re-encrypt + purge + status endpoint, `repo.gc()` | Keys & Versions tab |
| 4:15 to 5:00 | Audit + Inspector + Attacker panel | Audit, Inspector, Attacker |
| 5:00 to 5:30 | Rehearse the demo script; fix whatever breaks; run `test/` scripts | Polish only |
| 5:30 to 6:00 | Benchmarks (script is fine) + report | Optional Bench panel |

### Scope tiers
- **Must:** Identity bar, Groups, Members tab, Files tab, Keys tab, revoke lazy-vs-eager result panel, Attacker panel buttons for "fetch ciphertext" and "request key".
- **Should:** Audit tab, Inspector, "Decrypt with cached key".
- **Could:** Benchmark panel, charts, replay/tamper buttons, dark mode.

If you fall behind, cut from the bottom of that list first. Never cut the lazy-vs-eager comparison; it is your headline.

## 8. UI pitfalls checklist

- [ ] The signature must cover the exact bytes sent. Build the body as a string/`Uint8Array` once, hash it, and send that same buffer.
- [ ] `Date.now()` skew between browser and proxy is fine on one machine; show a clear error for `STALE_TIMESTAMP` anyway.
- [ ] `CryptoKey` objects cannot be `JSON.stringify`'d; only store them in IndexedDB.
- [ ] Hex vs base64 vs `0x`-prefixed bytes32: pick one helper (`toHex`, `fromHex`) and use it everywhere, including `ethers` calls.
- [ ] Do not log or render `K_v`, `hashKey` or plaintext anywhere except the explicit "Decrypt here" action.
- [ ] Polling: refresh the Group page every ~3 s (files, members, status) so approvals and revocations from another identity appear without a manual reload.
- [ ] After Hardhat restarts, clear IndexedDB identities too, or `userId`s will point at a wiped proxy DB.
- [ ] Make sure `ipfs.repo.gc()` is actually called after the unpin step, otherwise the availability-loss step in the demo does nothing.
