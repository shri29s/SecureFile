import { sha } from '../proxy/src/crypto.js';
export function memoryAdapters() {
  const records = [], blobs = new Map(), pins = new Set(), events = [];
  const chain = {
    health: async () => true, count: async () => records.length,
    get: async id => { if (!records[id - 1]) throw Error('NO_RECORD'); return { ...records[id - 1] }; },
    event: async (...args) => { events.push(args); },
    add: async (m, cid) => {
      const id = records.length + 1;
      records.push({ ...m, recordId: id, cid, status: 'active', timestamp: Math.floor(Date.now() / 1000), supersedes: 0, supersededBy: 0 });
      return { recordId: id, txHash: '0x' + sha(String(id)) };
    },
    supersede: async (id, cid, keyVersion, ctHash, size) => {
      const old = records[id - 1];
      if (old.status !== 'active' || keyVersion <= old.keyVersion) throw Error('NOT_ACTIVE_OR_NEWER');
      const result = await chain.add({ ...old, keyVersion, ctHash, size, uploaderSig: '' }, cid);
      records[result.recordId - 1].supersedes = id;
      old.status = 'superseded'; old.supersededBy = result.recordId;
      return result;
    },
    remove: async id => { records[id - 1].status = 'removed'; }
  };
  const ipfs = {
    health: async () => true,
    add: async b => { const cid = 'test-' + sha(b); blobs.set(cid, Buffer.from(b)); pins.add(cid); return cid; },
    cat: async cid => { if (!blobs.has(cid)) throw Error('Missing'); return Buffer.from(blobs.get(cid)); },
    unpin: async cid => { pins.delete(cid); },
    gc: async () => { for (const cid of blobs.keys()) if (!pins.has(cid)) blobs.delete(cid); }
  };
  return { chain, ipfs, records, blobs, events };
}
