import express from 'express';
import { resolve } from 'node:path';
import { HttpError } from './service.js';
export function createApp(service, deployment = { address: '', abi: [] }) {
  const app = express(), s = service;
  app.disable('x-powered-by');
  app.use((_req, res, next) => { res.set('X-Content-Type-Options', 'nosniff'); res.set('Cache-Control', 'no-store'); next(); });
  app.use(express.json({ limit: Math.ceil(s.config.maxBytes * 1.4) + 16384, verify: (req, _res, body) => { req.rawBody = body; } }));
  const route = (method, path, fn, auth = true) => app[method](path, (req, res, next) => {
    s.exclusive(async () => {
      const u = auth ? s.auth(req).user_id : null;
      const result = await fn(req, u);
      if (Buffer.isBuffer(result)) res.type('application/octet-stream').send(result);
      else res.json(result);
    }).catch(next);
  });
  app.get('/public/config', (_req, res) => res.json({ rpcUrl: s.config.rpcUrl, contractAddress: deployment.address, abi: deployment.abi, demoMode: s.config.demo, T: s.config.threshold }));
  app.get('/health', async (_req, res) => {
    const results = await Promise.allSettled([s.chain.health(), s.ipfs.health()]);
    const health = { proxy: true, chain: results[0].status === 'fulfilled', ipfs: results[1].status === 'fulfilled' };
    res.status(health.chain && health.ipfs ? 200 : 503).json(health);
  });
  if (s.config.demo) route('get', '/public/ipfs/:cid', async req => {
    try { return await s.ipfs.cat(req.params.cid); } catch { throw new HttpError(404, 'NO_BLOB'); }
  }, false);
  route('post', '/users/register', req => s.register(req.body || {}), false);
  route('get', '/users/:id', req => {
    const u = s.user(req.params.id); if (!u) throw new HttpError(404, 'UNKNOWN_USER');
    return { userId: u.user_id, name: u.name, signPub: u.sign_pub, encPub: u.enc_pub };
  });
  route('get', '/me/groups', (_req, u) => s.myGroups(u));
  route('post', '/groups', (req, u) => s.createGroup(u, req.body?.name));
  route('get', '/groups/:g', (req, u) => s.info(req.params.g, u));
  route('post', '/groups/:g/join-requests', (req, u) => s.join(req.params.g, u));
  route('get', '/groups/:g/join-requests', (req, u) => { s.owner(req.params.g, u); return s.info(req.params.g, u).members.filter(m => m.status === 'pending'); });
  route('post', '/groups/:g/members', (req, u) => s.decide(req.params.g, u, req.body?.userId, req.body?.decision));
  route('get', '/groups/:g/keys/:version', (req, u) => s.keys(req.params.g, u, req.params.version));
  route('post', '/groups/:g/files', (req, u) => s.upload(req.params.g, u, req.body || {}));
  route('get', '/groups/:g/files', (req, u) => s.listFiles(req.params.g, u, req.query.all === '1'));
  route('get', '/groups/:g/files/:id/manifest', (req, u) => {
    s.active(req.params.g, u);
    const row = s.db.prepare('SELECT manifest FROM files WHERE record_id=? AND group_id=?').get(req.params.id, req.params.g);
    if (!row?.manifest) throw new HttpError(404, 'NO_MANIFEST');
    return JSON.parse(row.manifest);
  });
  route('get', '/ipfs/:cid', (req, u) => s.blob(req.params.cid, u));
  route('delete', '/groups/:g/files/:id', (req, u) => s.remove(req.params.g, u, Number(req.params.id)));
  route('delete', '/groups/:g/members/:id', (req, u) => s.revoke(req.params.g, u, req.params.id, false, req.query.mode || 'lazy'));
  route('post', '/groups/:g/leave', (req, u) => s.revoke(req.params.g, u, u, true, 'lazy'));
  route('get', '/admin/groups/:g/status', (req, u) => { s.owner(req.params.g, u); return s.status(req.params.g); });
  route('post', '/admin/groups/:g/reencrypt', (req, u) => { s.owner(req.params.g, u); return s.reencrypt(req.params.g); });
  app.use(express.static(resolve('ui/dist'), { index: 'index.html' }));
  app.use((req, res) => res.status(404).json({ code: 'NOT_FOUND', message: 'Endpoint not found' }));
  app.use((error, _req, res, _next) => {
    const status = error.status || (error.type === 'entity.too.large' ? 413 : 500);
    res.status(status).json({ code: error.code || (status === 413 ? 'TOO_LARGE' : status === 400 ? 'BAD_REQUEST' : 'INTERNAL_ERROR'), message: error instanceof HttpError ? error.message : 'Request could not be completed' });
    if (status >= 500) console.error('Request failed:', error.code || error.name);
  });
  return app;
}
