import { Contract, JsonRpcProvider, zeroPadBytes } from 'ethers';
import { decryptBlob, hash, hmac, toHex, unb64, verify } from './crypto.js';
import { fetchKey, signedFetch } from './api.js';
import { canonicalManifest } from './manifest.js';
import { unpackFile } from './filePayload.js';
export function reader(config) {
  const provider = new JsonRpcProvider(config.rpcUrl);
  const contract = new Contract(config.contractAddress, config.abi, provider);
  const get = async id => {
    const r = await contract.getRecord(id);
    return { recordId: Number(id), groupId: r.groupId.slice(2, 34), uploaderId: r.uploaderId.slice(2), contentMac: r.contentMac.slice(2), ctHash: r.ctHash.slice(2), cid: r.cid, keyVersion: Number(r.keyVersion), size: Number(r.size), timestamp: Number(r.timestamp), supersedes: Number(r.supersedes), supersededBy: Number(r.supersededBy), status: ['active', 'superseded', 'removed'][Number(r.status)], uploaderSig: r.uploaderSig };
  };
  return {
    get, provider,
    resolve: async id => { let r = await get(id); const seen = new Set(); while (r.supersededBy) { if (seen.has(r.recordId)) throw Error('Invalid record chain'); seen.add(r.recordId); r = await get(r.supersededBy); } return r; },
    audit: async group => {
      const ids = new Set((await contract.getGroupRecords(zeroPadBytes('0x' + group, 32))).map(String));
      const logs = await contract.queryFilter('*', 0, 'latest');
      const GROUP_KINDS = ['GroupCreated', 'MemberAdded', 'MemberRemoved', 'KeyRotated', 'KeyPurged', 'MemberLeft', 'OwnershipTransferred', 'RoleChanged', 'GroupDissolved'];
      return logs.filter(e => e.args && (e.args.groupId === zeroPadBytes('0x' + group, 32) || ids.has(String(e.args.recordId ?? e.args.oldId))))
        .map(e => {
          let event = e.fragment.name;
          let details = e.args.toArray().map(String).join(' · ');
          if (event === 'GroupEvent' && e.args.kind !== undefined) {
            const kind = Number(e.args.kind);
            event = GROUP_KINDS[kind] || `GroupEvent #${kind}`;
            details = `Subject: ${String(e.args.subjectId).slice(0, 10)}… · Version: v${e.args.keyVersion}`;
          }
          return { event, block: e.blockNumber, txHash: e.transactionHash, details };
        }).reverse();
    }
  };
}
export async function download(id, recordId, chain, base = '', onStage = () => {}, onKey = () => {}) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const r = await chain.resolve(recordId);
    if (r.status !== 'active') throw Error('File has been removed');
    onStage('Chain record verified');
    try {
      const keys = await fetchKey(id, r.groupId, r.keyVersion, base); await onKey(keys, r.groupId);
      const blob = await signedFetch(id, 'GET', `/ipfs/${r.cid}`, undefined, base);
      if (await hash(blob) !== r.ctHash || blob.length !== r.size) throw Error('Ciphertext hash mismatch');
      onStage('Chain record ✓ · Ciphertext hash ✓');
      const plain = await decryptBlob(keys.aesKey, blob, r.groupId, r.keyVersion);
      if (await hmac(keys.hmacKey, plain) !== r.contentMac) throw Error('Content MAC mismatch');
      onStage('Chain record ✓ · Ciphertext hash ✓ · GCM tag ✓ · Content MAC ✓');
      let original = r;
      while (original.supersedes) original = await chain.get(original.supersedes);
      const manifest = await signedFetch(id, 'GET', `/groups/${r.groupId}/files/${original.recordId}/manifest`, undefined, base);
      for (const k of ['groupId', 'uploaderId', 'contentMac', 'ctHash', 'keyVersion', 'size']) if (manifest[k] !== original[k]) throw Error('Manifest does not match chain');
      if (r.contentMac !== original.contentMac || r.uploaderId !== original.uploaderId || r.groupId !== original.groupId) throw Error('Invalid provenance');
      const uploader = await signedFetch(id, 'GET', `/users/${original.uploaderId}`, undefined, base);
      if ('0x' + toHex(unb64(manifest.uploaderSig)) !== original.uploaderSig || !await verify(uploader.signPub, manifest.uploaderSig, canonicalManifest(manifest))) throw Error('Uploader signature invalid');
      onStage('Chain record ✓ · Ciphertext hash ✓ · GCM tag ✓ · Content MAC ✓ · Uploader signature ✓');
      return { ...unpackFile(plain, recordId), record: r };
    } catch (e) { if (attempt || e.code !== 'KEY_PURGED') throw e; onStage('Key purged; resolving latest record'); }
  }
}
