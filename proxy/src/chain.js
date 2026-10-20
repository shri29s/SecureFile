import { Contract, JsonRpcProvider, NonceManager, Wallet, zeroPadBytes } from 'ethers';
export const chainGroup = g => zeroPadBytes('0x' + g, 32);
export function plainRecord(r, id) {
  return { recordId: Number(id), groupId: r.groupId.slice(2, 34), uploaderId: r.uploaderId.slice(2), contentMac: r.contentMac.slice(2), ctHash: r.ctHash.slice(2), cid: r.cid,
    keyVersion: Number(r.keyVersion), size: Number(r.size), timestamp: Number(r.timestamp), supersedes: Number(r.supersedes), supersededBy: Number(r.supersededBy), status: ['active', 'superseded', 'removed'][Number(r.status)], uploaderSig: r.uploaderSig };
}
export function chainAdapter(config, deployment) {
  const provider = new JsonRpcProvider(config.rpcUrl);
  const signer = new NonceManager(new Wallet(config.privateKey, provider));
  const contract = new Contract(deployment.address, deployment.abi, signer);
  const receipt = async tx => (await tx).wait();
  const recordResult = r => {
    const event = r.logs.map(l => { try { return contract.interface.parseLog(l); } catch { return null; } }).find(e => e?.name === 'FileRecorded');
    return { recordId: Number(event.args.recordId), txHash: r.hash };
  };
  return {
    provider, contract,
    health: async () => { if ((await provider.getNetwork()).chainId !== 31337n || await provider.getCode(deployment.address) === '0x') throw new Error('Local chain/deployment missing'); return true; },
    get: async id => plainRecord(await contract.getRecord(id), id),
    count: async () => Number(await contract.recordCount()),
    add: async (m, cid) => recordResult(await receipt(contract.addRecord(chainGroup(m.groupId), '0x' + m.uploaderId, '0x' + m.contentMac, '0x' + m.ctHash, cid, m.keyVersion, m.size, '0x' + Buffer.from(m.uploaderSig, 'base64').toString('hex')))),
    supersede: async (id, cid, version, hash, size) => recordResult(await receipt(contract.supersede(id, cid, version, '0x' + hash, size))),
    remove: async (id, user) => receipt(contract.markRemoved(id, '0x' + user)),
    event: async (g, kind, subject, v) => receipt(contract.logGroupEvent(chainGroup(g), kind, '0x' + subject, v))
  };
}
