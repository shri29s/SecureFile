import { create } from 'kubo-rpc-client';
export function ipfsAdapter(url) {
  const client = create({ url, timeout: 30000 });
  return {
    health: async () => { await client.id(); return true; },
    add: async blob => (await client.add(blob, { pin: true, cidVersion: 1 })).cid.toString(),
    cat: async cid => { const chunks = []; for await (const chunk of client.cat(cid)) chunks.push(chunk); return Buffer.concat(chunks); },
    unpin: async cid => { try { await client.pin.rm(cid); } catch (e) { if (!/not pinned|not found/i.test(e.message)) throw e; } },
    gc: async () => { for await (const result of client.repo.gc()) if (result.err) throw result.err; }
  };
}
