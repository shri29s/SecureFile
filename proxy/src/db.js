import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
export function openDb(path) {
  if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
  const db = new Database(path);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, name TEXT NOT NULL, sign_pub TEXT NOT NULL, enc_pub TEXT NOT NULL, created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS groups (group_id TEXT PRIMARY KEY, name TEXT NOT NULL, owner_id TEXT REFERENCES users(user_id), current_version INTEGER NOT NULL, hash_key_sealed BLOB NOT NULL, created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS group_members (group_id TEXT REFERENCES groups(group_id), user_id TEXT REFERENCES users(user_id), role TEXT NOT NULL, status TEXT NOT NULL, joined_at INTEGER, ended_at_version INTEGER, PRIMARY KEY(group_id,user_id));
    CREATE TABLE IF NOT EXISTS group_keys (group_id TEXT REFERENCES groups(group_id), version INTEGER, key_sealed BLOB, reason TEXT, created_at INTEGER, purged_at INTEGER, PRIMARY KEY(group_id,version));
    CREATE TABLE IF NOT EXISTS files (record_id INTEGER PRIMARY KEY, group_id TEXT, uploader_id TEXT, cid TEXT, key_version INTEGER, status TEXT, size INTEGER, tx_hash TEXT, created_at INTEGER, manifest TEXT);
    CREATE TABLE IF NOT EXISTS nonces (user_id TEXT, nonce TEXT, expires_at INTEGER, PRIMARY KEY(user_id,nonce));
    CREATE TABLE IF NOT EXISTS reencrypt_jobs (old_record_id INTEGER PRIMARY KEY, group_id TEXT, state TEXT, new_cid TEXT, new_record_id INTEGER, target_version INTEGER, new_blob BLOB, attempts INTEGER DEFAULT 0, updated_at INTEGER);
    CREATE TABLE IF NOT EXISTS event_outbox (id INTEGER PRIMARY KEY, group_id TEXT, kind INTEGER, subject_id TEXT, version INTEGER);
  `);
  return db;
}
