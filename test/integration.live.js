import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Contract, ContractFactory, JsonRpcProvider, Wallet } from 'ethers';
import { configuration } from '../proxy/src/config.js';
import { openDb } from '../proxy/src/db.js';
import { chainAdapter } from '../proxy/src/chain.js';
import { ipfsAdapter } from '../proxy/src/ipfs.js';
import { Service } from '../proxy/src/service.js';
import { createApp } from '../proxy/src/app.js';
import { identity, registration, decryptBlob, utf8 } from '../client-core/src/crypto.js';
import { fetchKey, signedFetch, upload } from '../client-core/src/api.js';
import { reader, download } from '../client-core/src/chainRead.js';

test('Live Hardhat + Kubo: contract permissions, IPFS roundtrip, full client verification and migration', async t => {
  const config = configuration(), artifact = JSON.parse(readFileSync('artifacts/FileRegistry.json'));
  const deployProvider = new JsonRpcProvider(config.rpcUrl);
  const deployer = new Wallet(config.privateKey, deployProvider);
  const isolatedContract = await new ContractFactory(artifact.abi, artifact.evm.bytecode.object, deployer).deploy(deployer.address);
  await isolatedContract.waitForDeployment();
  const deployment = { address: await isolatedContract.getAddress(), abi: artifact.abi };
  deployProvider.destroy();
  const chain = chainAdapter(config, deployment), ipfs = ipfsAdapter(config.ipfsApi), db = openDb(':memory:');
  await Promise.all([chain.health(), ipfs.health()]);
  const service = new Service(db, chain, ipfs, config);
  const server = createApp(service, deployment).listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  const read = reader({ rpcUrl: config.rpcUrl, contractAddress: deployment.address, abi: deployment.abi });
  t.after(() => { server.close(); db.close(); chain.provider.destroy(); read.provider.destroy(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = (id, method, path, body) => signedFetch(id, method, path, body, base);
  const [alice, bob, outsider] = await Promise.all(['Live Alice', 'Live Bob', 'Live outsider'].map(identity));
  for (const id of [alice, bob, outsider]) {
    const r = await fetch(base + '/users/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(await registration(id)) });
    assert.equal(r.status, 200);
  }
  const g = (await call(alice, 'POST', '/groups', { name: 'Live integration' })).groupId;
  await t.test('onlyProxy rejects another chain account', async () => {
    const attacker = new Contract(deployment.address, deployment.abi, await chain.provider.getSigner(1));
    await assert.rejects(attacker.logGroupEvent('0x' + g.padEnd(64, '0'), 0, '0x' + outsider.userId, 1));
  });
  await call(bob, 'POST', `/groups/${g}/join-requests`);
  await call(alice, 'POST', `/groups/${g}/members`, { userId: bob.userId, decision: 'approve' });
  const keys = await fetchKey(bob, g, 1, base), plain = utf8('Live IPFS ciphertext roundtrip 🗝');
  let original;
  await t.test('real upload/download, provenance and outsider isolation', async () => {
    original = await upload(alice, g, plain, base, undefined, undefined, { filename: 'research.pdf', mimeType: 'application/pdf' });
    assert.ok(original.cid.startsWith('bafy') || original.cid.startsWith('bafk'));
    const result = await download(bob, original.recordId, read, base);
    assert.deepEqual(result.plain, plain);
    assert.equal(result.filename, 'research.pdf');
    assert.equal(result.mimeType, 'application/pdf');
    await assert.rejects(fetchKey(outsider, g, 1, base), e => e.code === 'NOT_MEMBER');
    assert.equal((await fetch(base + `/public/ipfs/${original.cid}`)).status, 200);
  });
  await t.test('lazy revoke preserves old ciphertext and blocks keys', async () => {
    const r = await call(alice, 'DELETE', `/groups/${g}/members/${bob.userId}?mode=lazy`);
    assert.equal(r.filesReencrypted, 0);
    for (const v of [1, 'current']) await assert.rejects(fetchKey(bob, g, v, base), e => e.code === 'NOT_MEMBER');
    const { unpackFile } = await import('../client-core/src/filePayload.js');
    assert.deepEqual(unpackFile(await decryptBlob(keys.aesKey, await ipfs.cat(original.cid), g, 1), original.recordId).plain, plain);
  });
  await t.test('migration follows stable handle, verifies signature, purges and garbage collects', async () => {
    const result = await call(alice, 'POST', `/admin/groups/${g}/reencrypt`);
    assert.equal(result.migrated, 1);
    assert.deepEqual(result.purgedVersions, [1]);
    const latest = await download(alice, original.recordId, read, base);
    assert.deepEqual(latest.plain, plain);
    assert.equal(latest.filename, 'research.pdf');
    assert.equal(latest.mimeType, 'application/pdf');
    assert.equal(latest.record.keyVersion, 2);
    assert.ok(latest.record.supersedes);
    // Offline daemon returns quickly for missing local content when local-only is requested.
    const has = await fetch(config.ipfsApi + `/api/v0/block/stat?arg=${original.cid}&offline=true`, { method: 'POST' });
    assert.equal(has.ok, false);
    assert.equal((await call(alice, 'POST', `/admin/groups/${g}/reencrypt`)).migrated, 0);
    assert.ok((await read.audit(g)).some(e => e.event === 'FileSuperseded'));
    await call(alice, 'DELETE', `/groups/${g}/files/${latest.record.recordId}`);
    assert.equal((await read.get(latest.record.recordId)).status, 'removed');
  });
});
