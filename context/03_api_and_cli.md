# 03: HTTP API and CLI

All endpoints except `POST /users/register` require the auth headers from `01` section 6.
Bodies are JSON unless noted. Binary fields are base64.

## 1. Endpoints

### Users
| Method + Path | Auth | Body | Response | Workflow |
|---|---|---|---|---|
| `POST /users/register` | self-signature | `{name, signPub, encPub, selfSig}` | `{userId}` | W1 |
| `GET /users/:userId` | any registered user | n/a | `{userId, name, signPub, encPub}` | W6 step 6 |

### Groups and membership
| Method + Path | Who | Body | Response | Workflow |
|---|---|---|---|---|
| `POST /groups` | any user | `{name}` | `{groupId, currentVersion:1}` | W2 |
| `GET /groups/:g` | active member | n/a | `{groupId, name, ownerId, currentVersion, members:[{userId,role}]}` | n/a |
| `POST /groups/:g/join-requests` | any user | n/a | `{status:'pending'}` | W3 |
| `GET /groups/:g/join-requests` | owner | n/a | `[{userId,name,createdAt}]` | W4 |
| `POST /groups/:g/members` | owner | `{userId, decision}` | `{status}` | W4 |
| `DELETE /groups/:g/members/:userId` | owner | n/a | `{currentVersion}` | W8 |
| `POST /groups/:g/leave` | member | n/a | `{currentVersion}` | W9 |

### Keys
| Method + Path | Who | Response | Workflow |
|---|---|---|---|
| `GET /groups/:g/keys/:version` (`version` = integer or `current`) | active member | `{version, wrapped}` where `wrapped = RSA-OAEP(encPub, K_v‖hashKey)` | W12 |

### Files
| Method + Path | Who | Body / Response | Workflow |
|---|---|---|---|
| `POST /groups/:g/files` | active member | `{contentMac, ctHash, keyVersion, size, clientTs, nonce, uploaderSig, blob}` → `{recordId, cid, txHash}` | W5 |
| `GET /groups/:g/files` | active member | `[{recordId, uploaderId, keyVersion, size, timestamp, status, cid}]` | W11 |
| `GET /ipfs/:cid` | active member of the owning group (lookup via `files`) | raw ciphertext bytes | W6 |
| `DELETE /groups/:g/files/:recordId` | uploader or owner | `{removed:true}` | W7 |

> **UI update:** the browser UI is now the primary client and needs extra endpoints (`GET /me/groups`, `?mode=lazy|eager` on member removal, `/public/*` demo endpoints, extended group/status responses). See `05_ui_spec.md` section 4. The CLI section below is now only a reference for the Node test scripts.

### Admin (owner-authenticated; the UI uses these)
| Method + Path | Purpose |
|---|---|
| `POST /admin/groups/:g/reencrypt` | Run the W10 job now (manual trigger) |
| `GET /admin/groups/:g/status` | `{currentVersion, versionsInUse:{v:count}, liveKeys:[...], pendingJobs}` |

## 2. Error codes

| HTTP | `code` | Meaning |
|---|---|---|
| 400 | `BAD_REQUEST`, `BAD_SELF_SIGNATURE`, `BAD_MANIFEST`, `HASH_MISMATCH` | Malformed input or integrity mismatch |
| 401 | `UNKNOWN_USER`, `STALE_TIMESTAMP`, `REPLAY`, `BAD_SIGNATURE` | Authentication failure |
| 403 | `NOT_MEMBER`, `NOT_OWNER`, `REVOKED`, `NOT_ALLOWED` | Authorization failure |
| 404 | `NO_GROUP`, `NO_RECORD`, `NO_PENDING_REQUEST`, `NO_KEY_VERSION` | Not found |
| 409 | `USER_EXISTS`, `ALREADY_MEMBER`, `STALE_KEY_VERSION` | Conflict; the client can retry after refetching the key |
| 410 | `KEY_PURGED` | Version was re-encrypted away; client should re-resolve the record |
| 413 | `TOO_LARGE` | Over `MAX_UPLOAD_MB` |
| 502 | `CHAIN_ERROR`, `IPFS_ERROR` | Dependency failure |

Error body: `{ "code": "...", "message": "..." }`.

## 3. CLI (`sfs`)

Use `--id <name>` to select an identity folder (`~/.sfs/<name>`), so one machine can play Alice, Bob, Carol and an outsider.

```
sfs --id alice register
sfs --id alice group create --name team1                 # prints groupId
sfs --id bob   group join --group <gid>
sfs --id alice group requests --group <gid>
sfs --id alice group approve --group <gid> --user <uid>
sfs --id alice group reject  --group <gid> --user <uid>
sfs --id alice group remove  --group <gid> --user <uid>   # revocation (W8)
sfs --id bob   group leave   --group <gid>                # W9
sfs --id alice group info    --group <gid>

sfs --id alice file upload   --group <gid> --path ./a.pdf # prints recordId
sfs --id bob   file list     --group <gid>
sfs --id bob   file download --group <gid> --record <rid> --out ./a.pdf
sfs --id alice file remove   --group <gid> --record <rid>

sfs --id alice admin status    --group <gid>              # versions in use, live keys
sfs --id alice admin reencrypt --group <gid>              # manual W10
sfs --id alice audit           --group <gid>              # GroupEvent history from chain
```

Client behavior to implement:
- On `409 STALE_KEY_VERSION` during upload: refetch current key and retry **once**.
- On `410 KEY_PURGED` during download: re-resolve the record via `supersededBy` and retry **once**.
- Print timings with `--time` (used by the benchmark scripts).
