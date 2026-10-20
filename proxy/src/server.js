import { readFileSync } from 'node:fs';
import { configuration } from './config.js';
import { openDb } from './db.js';
import { chainAdapter } from './chain.js';
import { ipfsAdapter } from './ipfs.js';
import { Service } from './service.js';
import { createApp } from './app.js';
const config = configuration();
const deployment = JSON.parse(readFileSync('deployment.json'));
const db = openDb(config.dbPath);
const service = new Service(db, chainAdapter(config, deployment), ipfsAdapter(config.ipfsApi), config);
await Promise.all([service.chain.health(), service.ipfs.health()]);
const previous = db.prepare("SELECT value FROM meta WHERE key='deployment'").get();
if (previous && previous.value !== deployment.address) throw new Error('Deployment differs from database; use a fresh DB_PATH');
db.prepare("INSERT OR IGNORE INTO meta VALUES ('deployment',?)").run(deployment.address);
await service.reconcile();
await service.flushEvents();
const server = createApp(service, deployment).listen(config.port, '127.0.0.1', () => console.log(`SecureFile: http://127.0.0.1:${config.port}`));
let working = false;
const timer = setInterval(() => {
  if (working) return;
  working = true;
  service.exclusive(async () => {
    await service.flushEvents();
    for (const g of db.prepare('SELECT group_id FROM groups').all()) {
      if (service.status(g.group_id).triggerFires) service.enqueue(g.group_id);
    }
    const groups = db.prepare("SELECT DISTINCT group_id FROM reencrypt_jobs WHERE state!='DONE'").all();
    for (const g of groups) await service.reencrypt(g.group_id);
  }).catch(e => console.error('Background migration paused:', e.name)).finally(() => { working = false; });
}, 3000);
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { clearInterval(timer); server.close(() => service.tail.finally(() => { db.close(); process.exit(); })); });
