export function configuration(env = process.env) {
  if (!/^[a-f0-9]{64}$/i.test(env.PROXY_MASTER_KEY || '')) throw new Error('PROXY_MASTER_KEY must contain 64 hex characters. Run npm run setup.');
  const threshold = Number(env.REENCRYPT_T ?? 3);
  const maxUploadMb = Number(env.MAX_UPLOAD_MB ?? 100);
  if (!Number.isInteger(threshold) || threshold < 0 || !Number.isFinite(maxUploadMb) || maxUploadMb <= 0) throw new Error('Invalid threshold or upload limit');
  return { port: Number(env.PORT || 3001), demo: env.DEMO_MODE === '1', rpcUrl: env.RPC_URL || 'http://127.0.0.1:8545', ipfsApi: env.IPFS_API || 'http://127.0.0.1:5001',
    privateKey: env.PROXY_PK, masterKey: Buffer.from(env.PROXY_MASTER_KEY, 'hex'), threshold, maxBytes: maxUploadMb * 1024 * 1024, dbPath: env.DB_PATH || 'data/sfs.sqlite' };
}
