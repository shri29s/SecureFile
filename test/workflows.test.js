import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { openDb } from '../proxy/src/db.js';
import { Service } from '../proxy/src/service.js';
import { createApp } from '../proxy/src/app.js';
import { memoryAdapters } from './fixtures.js';
import { identity, registration, decryptBlob, encryptBlob, hash, hmac, utf8, TagError } from '../client-core/src/crypto.js';
import { fetchKey, prepareUpload, signedFetch, signedRequest, upload } from '../client-core/src/api.js';

test('W1–W13 HTTP workflows and security boundaries', async t => {
  const adapters = memoryAdapters(), db = openDb(':memory:');
  const s = new Service(db, adapters.chain, adapters.ipfs, { masterKey: randomBytes(32), threshold: 1, maxBytes: 1024 * 1024, demo: true });
  const server = createApp(s).listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  t.after(() => { server.close(); db.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const [alice, bob, carol, dave] = await Promise.all(['Alice', 'Bob', 'Carol', 'Dave'].map(identity));
  const call = (id, method, path, body) => signedFetch(id, method, path, body, base);
  const denied = (promise, code) => assert.rejects(promise, e => e.code === code);
  let g, keys, original, stale;
  const plain = utf8('Private research: \u0000 binary 🗝');
  await t.test('W1 registration validates proof and non-extractable keys', async () => {
    assert.equal(alice.signPriv.extractable, false); assert.equal(alice.encPriv.extractable, false);
    const bad = await registration(alice); bad.selfSig = 'AAAA';
    assert.equal((await fetch(base + '/users/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(bad) })).status, 400);
    for (const id of [alice, bob, carol, dave]) {
      const r = await fetch(base + '/users/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(await registration(id)) });
      assert.equal(r.status, 200); assert.equal((await r.json()).userId, id.userId);
    }
    const duplicate = await fetch(base + '/users/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(await registration(alice)) });
    assert.equal(duplicate.status, 409);
  });
  await t.test('Authentication: replay, exact bytes, timestamp, bad signature', async () => {
    const req = await signedRequest(alice, 'GET', '/me/groups');
    assert.equal((await fetch(base + '/me/groups', req)).status, 200);
    assert.equal((await (await fetch(base + '/me/groups', req)).json()).code, 'REPLAY');
    const altered = await signedRequest(alice, 'POST', '/groups', { name: 'test' });
    altered.body += ' ';
    assert.equal((await (await fetch(base + '/groups', altered)).json()).code, 'BAD_SIGNATURE');
    const expired = await signedRequest(alice, 'GET', '/me/groups');
    expired.headers['X-Timestamp'] = '1';
    assert.equal((await (await fetch(base + '/me/groups', expired)).json()).code, 'STALE_TIMESTAMP');
  });
  await t.test('W2 create, W3 join, W4 owner approval/rejection, W12 wrapped keys', async () => {
    g = (await call(alice, 'POST', '/groups', { name: 'Project X' })).groupId;
    assert.equal((await call(alice, 'GET', '/me/groups'))[0].role, 'owner');
    await denied(fetchKey(dave, g, 'current', base), 'NOT_MEMBER');
    for (const id of [bob, carol]) {
      await call(id, 'POST', `/groups/${g}/join-requests`);
      await denied(fetchKey(id, g, 'current', base), 'NOT_MEMBER');
      await denied(call(dave, 'POST', `/groups/${g}/members`, { userId: id.userId, decision: 'approve' }), 'NOT_MEMBER');
      await call(alice, 'POST', `/groups/${g}/members`, { userId: id.userId, decision: 'approve' });
    }
    await call(dave, 'POST', `/groups/${g}/join-requests`);
    await call(alice, 'POST', `/groups/${g}/members`, { userId: dave.userId, decision: 'reject' });
    await denied(fetchKey(dave, g, 1, base), 'NOT_MEMBER');
    keys = await fetchKey(bob, g, 'current', base);
    assert.equal(keys.aesKey.extractable, false);
    const stored = db.prepare('SELECT key_sealed FROM group_keys WHERE group_id=?').get(g);
    assert.equal(stored.key_sealed.length, 60);
  });
  await t.test('W5 upload rejects tampering; W6 download verifies hash, GCM, HMAC', async () => {
    const bad = await prepareUpload(alice, g, keys, plain); bad.ctHash = 'f'.repeat(64);
    await denied(call(alice, 'POST', `/groups/${g}/files`, bad), 'HASH_MISMATCH');
    const badSig = await prepareUpload(alice, g, keys, plain); badSig.uploaderSig = 'AAAA';
    await denied(call(alice, 'POST', `/groups/${g}/files`, badSig), 'BAD_MANIFEST');
    original = await upload(alice, g, plain, base);
    const blob = await call(bob, 'GET', `/ipfs/${original.cid}`);
    const record = await adapters.chain.get(original.recordId);
    assert.equal(await hash(blob), record.ctHash);
    assert.deepEqual(await decryptBlob(keys.aesKey, blob, g, 1), plain);
    assert.equal(await hmac(keys.hmacKey, plain), record.contentMac);
    const changed = blob.slice(); changed[14] ^= 1;
    await assert.rejects(decryptBlob(keys.aesKey, changed, g, 1), TagError);
    await assert.rejects(decryptBlob(keys.aesKey, blob, 'ff'.repeat(16), 1), TagError);
    await denied(call(dave, 'GET', `/ipfs/${original.cid}`), 'NOT_MEMBER');
    assert.equal((await fetch(base + `/public/ipfs/${original.cid}`)).status, 200);
    const another = await encryptBlob(keys.aesKey, plain, g, 1);
    assert.notEqual(await hash(another), record.ctHash);
    stale = await prepareUpload(carol, g, keys, plain);
  });
  await t.test('W7 denies other members; uploader removal leaves tombstone', async () => {
    await denied(call(bob, 'DELETE', `/groups/${g}/files/${original.recordId}`), 'NOT_ALLOWED');
    const file = await upload(bob, g, plain, base);
    await call(bob, 'DELETE', `/groups/${g}/files/${file.recordId}`);
    assert.equal((await adapters.chain.get(file.recordId)).status, 'removed');
  });
  await t.test('W8 lazy revoke denies ALL versions, preserves old ciphertext, rejects stale uploads', async () => {
    const r = await call(alice, 'DELETE', `/groups/${g}/members/${bob.userId}?mode=lazy`);
    assert.equal(r.currentVersion, 2); assert.equal(r.filesReencrypted, 0);
    for (const version of [1, 2, 'current']) await denied(fetchKey(bob, g, version, base), 'NOT_MEMBER');
    await denied(call(bob, 'POST', `/groups/${g}/join-requests`), 'REVOKED');
    await denied(call(carol, 'POST', `/groups/${g}/files`, stale), 'STALE_KEY_VERSION');
    const oldBlob = new Uint8Array(await (await fetch(base + `/public/ipfs/${original.cid}`)).arrayBuffer());
    assert.deepEqual(await decryptBlob(keys.aesKey, oldBlob, g, 1), plain);
    assert.equal((await adapters.chain.get(original.recordId)).keyVersion, 1);
    const newFile = await upload(carol, g, plain, base);
    const newBlob = await call(carol, 'GET', `/ipfs/${newFile.cid}`);
    await assert.rejects(decryptBlob(keys.aesKey, newBlob, g, 2), TagError);
  });
  await t.test('W9 leaving rotates; owner cannot leave; threshold enqueues', async () => {
    await denied(call(alice, 'POST', `/groups/${g}/leave`), 'NOT_ALLOWED');
    assert.equal((await call(carol, 'POST', `/groups/${g}/leave`)).currentVersion, 3);
    await denied(fetchKey(carol, g, 1, base), 'NOT_MEMBER');
    const status = await call(alice, 'GET', `/admin/groups/${g}/status`);
    assert.equal(status.triggerFires, true); assert.ok(status.jobs.pending > 0);
    await denied(call(dave, 'GET', `/admin/groups/${g}/status`), 'NOT_MEMBER');
  });
  await t.test('W10 resumable migration after lost chain receipt, purge, and GC', async () => {
    const supersede = adapters.chain.supersede;
    let crash = true;
    adapters.chain.supersede = async (...args) => { const result = await supersede(...args); if (crash) { crash = false; throw Error('simulated lost receipt'); } return result; };
    await assert.rejects(s.exclusive(() => s.reencrypt(g)), /lost receipt/);
    const result = await call(alice, 'POST', `/admin/groups/${g}/reencrypt`);
    assert.equal(result.migrated, 2); assert.deepEqual(result.purgedVersions, [1, 2]);
    assert.equal((await call(alice, 'POST', `/admin/groups/${g}/reencrypt`)).migrated, 0);
    await denied(fetchKey(alice, g, 1, base), 'KEY_PURGED');
    assert.equal((await fetch(base + `/public/ipfs/${original.cid}`)).status, 404);
    const old = await adapters.chain.get(original.recordId), latest = await adapters.chain.get(old.supersededBy);
    const current = await fetchKey(alice, g, latest.keyVersion, base);
    const blob = await call(alice, 'GET', `/ipfs/${latest.cid}`);
    assert.deepEqual(await decryptBlob(current.aesKey, blob, g, latest.keyVersion), plain);
    assert.equal(await hmac(current.hmacKey, plain), latest.contentMac);
    assert.equal(latest.contentMac, old.contentMac);
  });
  await t.test('W11 listing and W13 cross-group isolation; eager revocation migrates immediately', async () => {
    const group2 = (await call(bob, 'POST', '/groups', { name: 'Second group' })).groupId;
    await denied(fetchKey(alice, group2, 1, base), 'NOT_MEMBER');
    await call(carol, 'POST', `/groups/${g}/join-requests`);
    await call(alice, 'POST', `/groups/${g}/members`, { userId: carol.userId, decision: 'approve' });
    assert.equal((await call(carol, 'GET', `/groups/${g}/files`)).filter(r => r.status === 'active').length, 2);
    const eager = await call(alice, 'DELETE', `/groups/${g}/members/${carol.userId}?mode=eager`);
    assert.equal(eager.filesReencrypted, 2); assert.ok(eager.bytesProcessed > 0);
    assert.equal(s.status(g).versions.find(v => v.version === 3).purgedAt > 0, true);
  });
});
