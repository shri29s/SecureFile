# SecureFile

Local research demo implementing the `context/` specifications: browser-side AES-256-GCM encryption, IPFS ciphertext storage, a Solidity registry, signed HTTP requests, versioned group keys, and deferred re-encryption.

## Documentation

- [Complete setup, startup and troubleshooting](docs/startup.md)
- [Implementation details and formats](docs/implementation.md)
- [Implementation limits and security boundaries](docs/implementation-limits.md)
- [Measured evaluation and results](docs/evaluation.md)
- [Original design specifications](context/00_overview.md)

## Installed environment

- Node 24 / npm; locked dependencies in `package-lock.json`.
- Hardhat local chain at `127.0.0.1:8545`, chain ID 31337.
- Kubo binary in `.runtime/kubo/ipfs.exe`, with an isolated offline repository in `.runtime/ipfs`.
- Kubo API port 5001, gateway port **8081** (8080 was unavailable).
- Express serves the built React application at **http://127.0.0.1:3001**.
- SQLite database in `data/sfs.sqlite`. `.env` contains the randomly generated master key; preserve it alongside database backups.

## Start

From the project root, in separate terminals:

```powershell
# Terminal 1
npm run chain

# Terminal 2
powershell -ExecutionPolicy Bypass -File scripts/ipfs.ps1

# Terminal 3: first run, or after a chain reset
npm run deploy
npm run build
npm start
```

The chain is ephemeral. Restarting Hardhat wipes its state. For a fresh demo, stop the proxy, deploy again, and choose a **new DB_PATH** in `.env` (for example `data/demo-2.sqlite`). Clear this site's IndexedDB or create new browser identities. Existing data is deliberately not deleted by setup scripts.

For a fresh checkout: `npm ci`, `npm run setup`, `npm run compile`, then install the official Windows AMD64 Kubo release into `.runtime/kubo/`. The release used during setup and its digest are recorded in `.runtime/kubo-release.json`. Download releases from the official `ipfs/kubo` GitHub repository and verify the release asset SHA-256 digest before extraction.

`npm run dev` starts Vite with an API proxy to port 3001. The normal demo uses `npm run build` and `npm start`.

## Verification

```powershell
npm test                 # HTTP workflows W1–W13; real crypto + SQLite, in-memory chain/IPFS
npm run test:integration # Real local chain/IPFS; starts an isolated HTTP server
npm run health           # Running proxy, chain and IPFS health
npm run build            # Production UI compilation
npm run bench            # E3 lazy/eager comparison; creates scratch groups
```

Live tests use a separate contract and an in-memory proxy database; they do not reset the user's application. Stop the proxy before running live tests and restart it afterward: the test shares its local chain signer and changes the account nonce. Tests write ciphertext to the local IPFS node and exercise garbage collection. The benchmark creates scratch identities/groups and writes `docs/benchmark-results.json`. Defaults: 1, 5, and 10 files of 64 KiB, three trials each; configure `BENCH_COUNTS`, `BENCH_FILE_BYTES`, and `BENCH_REPEATS`.

`npm run bench:crypto` measures the shared client cryptography. After both benchmarks, `npm run evaluation:report` regenerates the report from raw samples.

## Browser walkthrough

1. Create Alice, then create a group and copy its ID.
2. Create Bob, request to join using that ID. Switch to Alice and approve Bob in Members.
3. Alice uploads a file. Bob downloads it; the client checks the chain, ciphertext hash, GCM tag, HMAC, and original uploader signature.
4. In Inspector, note the record ID, group ID, and CID. The Security lab accepts these values even for an outsider.
5. As Alice, remove Bob with Lazy mode. No files migrate. Bob is refused all key versions, but a previously cached key can still decrypt available old ciphertext.
6. New files use the new key. Run re-encryption in Keys & Versions: old records point to new records, obsolete keys are purged, and old blobs are unpinned and garbage-collected locally.
7. Compare Eager revocation with Lazy using another active member. Inspect Audit for independently read blockchain events.

Private identity keys and cached group keys are non-extractable WebCrypto keys stored in IndexedDB. Disabling caching stops future writes; it does not erase previously cached keys. New browser uploads preserve the filename, extension, and MIME type inside the encrypted content. Downloads restore the original filename and exact file bytes. Earlier uploads without metadata retain the record-ID `.bin` fallback; re-upload them to preserve their names.

See [implementation notes](docs/implementation.md) for security boundaries, consistency limits, test coverage, and remaining work.

