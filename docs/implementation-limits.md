# Implementation limits

This is a local research demonstrator, not a production storage service. The following boundaries are part of its interpretation.

## Confidentiality and revocation

- The proxy holds live group keys and can decrypt files. Sender-side encryption avoids upload plaintext passing through the proxy, but does not remove trust in it.
- Re-encryption exposes plaintext transiently in proxy memory.
- Removing a member denies all future proxy key requests, including old versions. It cannot invalidate keys or ciphertext already copied.
- Unpinning and garbage collection affect this Kubo node only. Other nodes or downloaded copies may retain ciphertext.
- The per-group HMAC key does not rotate. Former members retaining it can test guesses of file contents.
- Chain metadata is public, including pseudonymous identities, group membership events, file sizes and CIDs. Filenames/MIME types are encrypted inside new uploads.

## Durability and consistency

- Hardhat is ephemeral. Restarting it requires a fresh matching deployment/database. It is not a persistent blockchain deployment.
- The original signed upload manifest has timestamp/nonce fields stored only in SQLite. A chain-only rebuild cannot restore them, and downloads fail original-signature verification if that manifest is missing.
- SQLite, IPFS and the chain do not share a transaction. A crash can leave orphaned pins, a missing manifest, or a tombstoned file whose unpin needs repair.
- Membership audit events use an at-least-once outbox and can duplicate after a crash between chain inclusion and acknowledgement.
- Migration resumes through stored job states and successor links. The tested lost-receipt path is not proof that every possible failure window is covered.
- Backups must preserve the master key and matching database. No automated backup/restore tool is supplied.

## Operational limits

- Exactly one proxy process per database. Operations are serialized, including asynchronous dependency calls, which limits throughput.
- Files are held in memory. The browser limit is 50 MiB; larger or concurrent transfers need streaming and bounded resource management.
- Kubo is offline during the demo. Multi-node distribution and network failures have not been evaluated.
- The proxy and live tests currently share a local chain signing account. Stop the proxy for integration tests and restart it afterward to avoid cached transaction nonce errors.
- Browser identity switching is a demonstration convenience. Keys are non-extractable but same-origin scripts can still use them. There is no passphrase unlock, device recovery or production login flow.
- Turning off caching affects future key writes; it does not erase cached keys.
- Pre-metadata uploads retain `.bin` fallback filenames. Their original names cannot be recovered from stored records.

## Features not implemented

Ownership transfer, group deletion, production administrator tooling, a graphical benchmark dashboard, encrypted identity export, streaming uploads/downloads, and public-chain deployment are not implemented. Membership state is authoritative in SQLite rather than enforced by the smart contract.

## Before a production deployment

Use a durable chain and private signer management, HTTPS, hardened frontend security policies, request/resource limits, observability, coordinated backups, recovery drills, and a design for multi-process transaction ordering. Expand failure-injection and concurrency testing, arrange independent security review, and define the intended threat model explicitly.

See [implementation details](implementation.md) for wire formats and [evaluation](evaluation.md) for exactly what was measured.
