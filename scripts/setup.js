import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
mkdirSync('data', { recursive: true });
if (!existsSync('.env')) {
  writeFileSync('.env', readFileSync('.env.example', 'utf8').replace('PROXY_MASTER_KEY=\n', `PROXY_MASTER_KEY=${randomBytes(32).toString('hex')}\n`));
  console.log('Created .env with a random master key. Preserve this file with your database.');
} else console.log('.env already exists; preserved.');
