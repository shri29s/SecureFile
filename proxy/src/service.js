import { randomBytes } from 'node:crypto';
import { canonicalManifest } from '../../client-core/src/manifest.js';
import { decrypt, encrypt, mac, pub, seal, sha, signatureOK, unseal, wrap } from './crypto.js';

export class HttpError extends Error {
  constructor(status, code, message = code) { super(message); this.status = status; this.code = code; }
}
const fail = (status, code) => { throw new HttpError(status, code); };
const hex = (s, length) => typeof s === 'string' && new RegExp(`^[a-f0-9]{${length}}$`).test(s);
const nameOK = s => typeof s === 'string' && s.trim().length > 0 && s.length <= 100;

export class Service {
  constructor(db, chain, ipfs, config) {
    Object.assign(this, { db, chain, ipfs, config });
    this.tail = Promise.resolve();
    const fingerprint = sha(config.masterKey);
    const previous = db.prepare("SELECT value FROM meta WHERE key='masterKeyFingerprint'").get();
    if (previous && previous.value !== fingerprint) throw new Error('Master key does not match this database');
    db.prepare("INSERT OR IGNORE INTO meta VALUES ('masterKeyFingerprint',?)").run(fingerprint);
  }
  // One queue protects authorization/version checks across asynchronous chain/IPFS writes.
  // This demo supports exactly one proxy process per database.
  exclusive(fn) {
    const next = this.tail.then(fn);
    this.tail = next.catch(() => {});
    return next;
  }
  user(id) { return this.db.prepare('SELECT * FROM users WHERE user_id=?').get(id); }
  group(g) { return this.db.prepare('SELECT * FROM groups WHERE group_id=?').get(g) || fail(404, 'NO_GROUP'); }
  member(g, u) { return this.db.prepare('SELECT * FROM group_members WHERE group_id=? AND user_id=?').get(g, u); }
  active(g, u) { const group = this.group(g); if (this.member(g, u)?.status !== 'active') fail(403, 'NOT_MEMBER'); return group; }
  owner(g, u) { const group = this.active(g, u); if (group.owner_id !== u) fail(403, 'NOT_OWNER'); return group; }
  auth(req) {
    const id = req.get('X-User-Id'), ts = req.get('X-Timestamp'), nonce = req.get('X-Nonce');
    const user = id && this.user(id); if (!user) fail(401, 'UNKNOWN_USER');
    if (!/^\d+$/.test(ts || '') || Math.abs(Date.now() - Number(ts)) > 60000) fail(401, 'STALE_TIMESTAMP');
    if (!hex(nonce, 32)) fail(401, 'BAD_SIGNATURE');
    this.db.prepare('DELETE FROM nonces WHERE expires_at < ?').run(Date.now());
    if (this.db.prepare('SELECT 1 FROM nonces WHERE user_id=? AND nonce=?').get(id, nonce)) fail(401, 'REPLAY');
    const message = `SFS-REQ-v1\n${req.method}\n${req.originalUrl}\n${ts}\n${nonce}\n${sha(req.rawBody || Buffer.alloc(0))}`;
    if (!signatureOK(user.sign_pub, message, req.get('X-Signature') || '')) fail(401, 'BAD_SIGNATURE');
    this.db.prepare('INSERT INTO nonces VALUES (?,?,?)').run(id, nonce, Date.now() + 120000);
    return user;
  }
  register(body) {
    const { name, signPub, encPub, selfSig } = body;
    if (!nameOK(name) || typeof signPub !== 'string' || typeof encPub !== 'string') fail(400, 'BAD_REQUEST');
    try { pub(signPub, 'ed25519'); pub(encPub, 'rsa'); } catch { fail(400, 'BAD_REQUEST'); }
    const userId = sha(Buffer.from(signPub, 'base64'));
    if (!signatureOK(signPub, `SFS-REG-v1|${userId}|${encPub}`, selfSig)) fail(400, 'BAD_SELF_SIGNATURE');
    if (this.user(userId)) fail(409, 'USER_EXISTS');
    this.db.prepare('INSERT INTO users VALUES (?,?,?,?,?)').run(userId, name.trim(), signPub, encPub, Date.now());
    return { userId };
  }
  outbox(g, kind, subject, version) { this.db.prepare('INSERT INTO event_outbox(group_id,kind,subject_id,version) VALUES (?,?,?,?)').run(g, kind, subject, version); }
  async flushEvents() {
    for (const e of this.db.prepare('SELECT * FROM event_outbox ORDER BY id').all()) {
      await this.chain.event(e.group_id, e.kind, e.subject_id, e.version);
      this.db.prepare('DELETE FROM event_outbox WHERE id=?').run(e.id);
    }
  }
  async createGroup(user, name) {
    if (!nameOK(name)) fail(400, 'BAD_REQUEST');
    const g = randomBytes(16).toString('hex'), now = Date.now();
    this.db.transaction(() => {
      this.db.prepare('INSERT INTO groups VALUES (?,?,?,?,?,?)').run(g, name.trim(), user, 1, seal(this.config.masterKey, randomBytes(32), `${g}:hash`), now);
      this.db.prepare('INSERT INTO group_members VALUES (?,?,?,?,?,NULL)').run(g, user, 'owner', 'active', now);
      this.db.prepare('INSERT INTO group_keys VALUES (?,?,?,?,?,NULL)').run(g, 1, seal(this.config.masterKey, randomBytes(32), `${g}:1`), 'create', now);
      this.outbox(g, 0, user, 1);
    })();
    await this.flushEvents();
    return { groupId: g, currentVersion: 1 };
  }
  myGroups(u) {
    return this.db.prepare('SELECT g.group_id groupId,g.name,g.current_version currentVersion,m.role,m.status FROM groups g JOIN group_members m USING(group_id) WHERE m.user_id=?').all(u);
  }
  info(g, u) {
    const group = this.active(g, u);
    let members = this.db.prepare('SELECT m.user_id userId,u.name,m.role,m.status,m.joined_at createdAt FROM group_members m JOIN users u USING(user_id) WHERE group_id=?').all(g);
    if (group.owner_id !== u) members = members.filter(m => m.status === 'active');
    return { groupId: g, name: group.name, ownerId: group.owner_id, currentVersion: group.current_version, members };
  }
  join(g, u) {
    this.group(g);
    const m = this.member(g, u);
    if (m?.status === 'revoked') fail(403, 'REVOKED');
    if (m?.status === 'active') fail(409, 'ALREADY_MEMBER');
    this.db.prepare("INSERT INTO group_members VALUES (?,?,'member','pending',?,NULL) ON CONFLICT(group_id,user_id) DO UPDATE SET status='pending',joined_at=excluded.joined_at").run(g, u, Date.now());
    return { status: 'pending' };
  }
  async decide(g, u, target, decision) {
    const group = this.owner(g, u);
    if (!['approve', 'reject'].includes(decision)) fail(400, 'BAD_REQUEST');
    if (this.member(g, target)?.status !== 'pending') fail(404, 'NO_PENDING_REQUEST');
    const status = decision === 'approve' ? 'active' : 'rejected';
    this.db.transaction(() => {
      this.db.prepare('UPDATE group_members SET status=?,joined_at=? WHERE group_id=? AND user_id=?').run(status, Date.now(), g, target);
      if (status === 'active') this.outbox(g, 1, target, group.current_version);
    })();
    await this.flushEvents(); return { status };
  }
  rawKey(g, v) {
    const row = this.db.prepare('SELECT * FROM group_keys WHERE group_id=? AND version=?').get(g, v);
    if (!row) fail(404, 'NO_KEY_VERSION');
    if (row.purged_at) fail(410, 'KEY_PURGED');
    return unseal(this.config.masterKey, row.key_sealed, `${g}:${v}`);
  }
  hashKey(g) { return unseal(this.config.masterKey, this.group(g).hash_key_sealed, `${g}:hash`); }
  keys(g, u, requested) {
    const group = this.active(g, u);
    const v = requested === 'current' ? group.current_version : Number(requested);
    if (!Number.isSafeInteger(v) || v < 1) fail(400, 'BAD_REQUEST');
    return { version: v, wrapped: wrap(this.user(u).enc_pub, Buffer.concat([this.rawKey(g, v), this.hashKey(g)])) };
  }
  mirror(record, txHash = '', manifest = null) {
    this.db.prepare(`INSERT INTO files VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(record_id) DO UPDATE SET status=excluded.status`)
      .run(record.recordId, record.groupId, record.uploaderId, record.cid, record.keyVersion, record.status, record.size, txHash, record.timestamp * 1000, manifest ? JSON.stringify(manifest) : null);
  }
  async reconcile() {
    const count = await this.chain.count();
    const max = this.db.prepare('SELECT MAX(record_id) id FROM files').get().id || 0;
    if (max > count) throw new Error('Blockchain was reset; use a fresh database and deployment together.');
    for (let id = 1; id <= count; id++) {
      const record = await this.chain.get(id);
      const existing = this.db.prepare('SELECT cid FROM files WHERE record_id=?').get(id);
      if (existing && existing.cid !== record.cid) throw new Error('Chain/database mismatch');
      this.mirror(record);
    }
  }
  async upload(g, u, m) {
    const group = this.active(g, u);
    if (m.groupId !== g || m.uploaderId !== u || !hex(m.contentMac, 64) || !hex(m.ctHash, 64) || !hex(m.nonce, 32) ||
      !Number.isSafeInteger(m.clientTs) || Math.abs(Date.now() - m.clientTs) > 60000 || !Number.isSafeInteger(m.size) ||
      typeof m.blob !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(m.blob)) fail(400, 'BAD_MANIFEST');
    if (m.keyVersion !== group.current_version) fail(409, 'STALE_KEY_VERSION');
    const blob = Buffer.from(m.blob, 'base64');
    if (blob.length > this.config.maxBytes) fail(413, 'TOO_LARGE');
    if (blob.length !== m.size || blob.length < 29 || blob[0] !== 1) fail(400, 'BAD_MANIFEST');
    if (sha(blob) !== m.ctHash) fail(400, 'HASH_MISMATCH');
    if (!signatureOK(this.user(u).sign_pub, canonicalManifest(m), m.uploaderSig)) fail(400, 'BAD_MANIFEST');
    const manifestNonce = `manifest:${m.nonce}`;
    if (this.db.prepare('SELECT 1 FROM nonces WHERE user_id=? AND nonce=?').get(u, manifestNonce)) fail(401, 'REPLAY');
    this.db.prepare('INSERT INTO nonces VALUES (?,?,?)').run(u, manifestNonce, Date.now() + 120000);
    let cid;
    try { cid = await this.ipfs.add(blob); } catch { fail(502, 'IPFS_ERROR'); }
    let result;
    try { result = await this.chain.add(m, cid); }
    catch {
      // A lost receipt can hide a successful transaction. Reconcile before unpinning.
      try { await this.reconcile(); } catch { fail(502, 'CHAIN_ERROR'); }
      if (!this.db.prepare("SELECT 1 FROM files WHERE cid=? AND status='active'").get(cid)) await this.ipfs.unpin(cid).catch(() => {});
      fail(502, 'CHAIN_ERROR');
    }
    const { blob: _, ...manifest } = m;
    this.mirror(await this.chain.get(result.recordId), result.txHash, manifest);
    return { ...result, cid, keyVersion: m.keyVersion };
  }
  listFiles(g, u, all) {
    this.active(g, u);
    return this.db.prepare(`SELECT f.record_id recordId,f.uploader_id uploaderId,u.name uploaderName,f.key_version keyVersion,f.size,f.created_at timestamp,f.status,f.cid,f.tx_hash txHash FROM files f JOIN users u ON u.user_id=f.uploader_id WHERE group_id=? ${all ? '' : "AND status != 'superseded'"} ORDER BY record_id DESC`).all(g);
  }
  async blob(cid, u) {
    const rows = this.db.prepare("SELECT group_id FROM files WHERE cid=? AND status='active'").all(cid);
    if (!rows.some(r => this.member(r.group_id, u)?.status === 'active')) fail(403, 'NOT_MEMBER');
    try { return await this.ipfs.cat(cid); } catch { fail(502, 'IPFS_ERROR'); }
  }
  async safeUnpin(cid) {
    if (!this.db.prepare("SELECT 1 FROM files WHERE cid=? AND status='active'").get(cid)) await this.ipfs.unpin(cid);
  }
  async remove(g, u, id) {
    const group = this.active(g, u), r = await this.chain.get(id).catch(() => fail(404, 'NO_RECORD'));
    if (r.groupId !== g || r.status !== 'active') fail(404, 'NO_RECORD');
    if (r.uploaderId !== u && group.owner_id !== u) fail(403, 'NOT_ALLOWED');
    await this.chain.remove(id, u);
    this.db.prepare("UPDATE files SET status='removed' WHERE record_id=?").run(id);
    await this.safeUnpin(r.cid);
    return { removed: true };
  }
  async revoke(g, u, target, leaving, mode) {
    const start = performance.now();
    const group = leaving ? this.active(g, u) : this.owner(g, u);
    if (group.owner_id === target || this.member(g, target)?.status !== 'active') fail(403, 'NOT_ALLOWED');
    if (!['lazy', 'eager'].includes(mode)) fail(400, 'BAD_REQUEST');
    if (mode === 'eager' && !this.config.demo) fail(403, 'NOT_ALLOWED');
    const v = group.current_version + 1;
    this.db.transaction(() => {
      this.db.prepare('UPDATE group_members SET status=?,ended_at_version=? WHERE group_id=? AND user_id=?').run(leaving ? 'left' : 'revoked', v - 1, g, target);
      this.db.prepare('UPDATE groups SET current_version=? WHERE group_id=?').run(v, g);
      this.db.prepare('INSERT INTO group_keys VALUES (?,?,?,?,?,NULL)').run(g, v, seal(this.config.masterKey, randomBytes(32), `${g}:${v}`), leaving ? 'leave' : 'revoke', Date.now());
      this.outbox(g, leaving ? 5 : 2, target, v - 1); this.outbox(g, 3, group.owner_id, v);
    })();
    await this.flushEvents();
    let result = { migrated: 0, bytesProcessed: 0 };
    if (mode === 'eager') result = await this.reencrypt(g);
    else if (this.status(g).triggerFires) this.enqueue(g);
    return { currentVersion: v, elapsedMs: performance.now() - start, filesReencrypted: result.migrated, bytesProcessed: result.bytesProcessed };
  }
  status(g) {
    const group = this.group(g);
    const versions = this.db.prepare("SELECT k.version,k.created_at createdAt,k.reason,k.purged_at purgedAt,(SELECT COUNT(*) FROM files f WHERE f.group_id=k.group_id AND f.key_version=k.version AND f.status='active') activeFiles FROM group_keys k WHERE k.group_id=? ORDER BY version").all(g);
    const oldestInUse = versions.find(v => v.activeFiles)?.version ?? group.current_version;
    const jobs = this.db.prepare("SELECT SUM(state!='DONE') pending,SUM(state='DONE') done FROM reencrypt_jobs WHERE group_id=?").get(g);
    return { currentVersion: group.current_version, T: this.config.threshold, versions, oldestInUse, triggerFires: group.current_version - oldestInUse > this.config.threshold, jobs: { pending: jobs.pending || 0, done: jobs.done || 0 } };
  }
  enqueue(g) {
    this.db.prepare(`INSERT OR IGNORE INTO reencrypt_jobs(old_record_id,group_id,state,updated_at)
      SELECT record_id,group_id,'PENDING',? FROM files WHERE group_id=? AND status='active' AND key_version < ?`).run(Date.now(), g, this.group(g).current_version);
  }
  async reencrypt(g) {
    const start = performance.now(); let migrated = 0, bytesProcessed = 0;
    this.enqueue(g);
    for (const job of this.db.prepare("SELECT * FROM reencrypt_jobs WHERE group_id=? AND state!='DONE' ORDER BY old_record_id").all(g)) {
      this.db.prepare('UPDATE reencrypt_jobs SET attempts=attempts+1,updated_at=? WHERE old_record_id=?').run(Date.now(), job.old_record_id);
      const old = await this.chain.get(job.old_record_id);
      if (old.status === 'removed') {
        this.db.prepare("UPDATE reencrypt_jobs SET state='DONE',new_blob=NULL WHERE old_record_id=?").run(job.old_record_id); continue;
      }
      let newId = old.supersededBy;
      if (!newId) {
        if (!job.new_blob) {
          const blob = await this.ipfs.cat(old.cid);
          if (sha(blob) !== old.ctHash) throw new Error('Ciphertext hash mismatch during migration');
          const plain = decrypt(this.rawKey(g, old.keyVersion), blob, g, old.keyVersion);
          if (mac(this.hashKey(g), plain) !== old.contentMac) throw new Error('Content MAC mismatch during migration');
          job.target_version = this.group(g).current_version;
          job.new_blob = encrypt(this.rawKey(g, job.target_version), plain, g, job.target_version);
          plain.fill(0);
          // Persist ciphertext before add: a crash repeats identical bytes and therefore the same CID.
          this.db.prepare("UPDATE reencrypt_jobs SET new_blob=?,target_version=?,state='PENDING' WHERE old_record_id=?").run(job.new_blob, job.target_version, job.old_record_id);
        }
        if (!job.new_cid) {
          job.new_cid = await this.ipfs.add(job.new_blob);
          this.db.prepare("UPDATE reencrypt_jobs SET new_cid=?,state='BLOB_ADDED' WHERE old_record_id=?").run(job.new_cid, job.old_record_id);
        }
        const result = await this.chain.supersede(job.old_record_id, job.new_cid, job.target_version, sha(job.new_blob), job.new_blob.length);
        newId = result.recordId;
      }
      this.db.prepare("UPDATE reencrypt_jobs SET new_record_id=?,state='CHAIN_WRITTEN' WHERE old_record_id=?").run(newId, job.old_record_id);
      this.mirror(await this.chain.get(job.old_record_id));
      this.mirror(await this.chain.get(newId));
      await this.safeUnpin(old.cid);
      this.db.prepare("UPDATE reencrypt_jobs SET state='OLD_UNPINNED' WHERE old_record_id=?").run(job.old_record_id);
      this.db.prepare("UPDATE reencrypt_jobs SET state='DONE',new_blob=NULL WHERE old_record_id=?").run(job.old_record_id);
      migrated++; bytesProcessed += old.size;
    }
    // A recovered job may target a version older than the current one after a
    // subsequent rotation. Queue its successor for the next worker pass.
    this.enqueue(g);
    const purgedVersions = [];
    if (!this.status(g).jobs.pending) {
      for (const v of this.status(g).versions) if (!v.purgedAt && !v.activeFiles && v.version < this.group(g).current_version) {
        this.db.transaction(() => {
          this.db.prepare('UPDATE group_keys SET key_sealed=NULL,purged_at=? WHERE group_id=? AND version=?').run(Date.now(), g, v.version);
          this.outbox(g, 4, this.group(g).owner_id, v.version);
        })(); purgedVersions.push(v.version);
      }
    }
    await this.flushEvents();
    if (this.config.demo) await this.ipfs.gc();
    return { migrated, purgedVersions, bytesProcessed, elapsedMs: performance.now() - start };
  }
}
