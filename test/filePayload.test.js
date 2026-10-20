import test from 'node:test';
import assert from 'node:assert/strict';
import { packFile, unpackFile, safeFilename } from '../client-core/src/filePayload.js';
import { utf8 } from '../client-core/src/crypto.js';

test('file metadata preserves PDF name, MIME type and exact binary bytes', () => {
  const plain = new Uint8Array([37, 80, 68, 70, 45, 49, 46, 55, 0, 255]);
  const result = unpackFile(packFile(plain, { filename: 'Research résumé.pdf', mimeType: 'application/pdf' }), 42);
  assert.deepEqual(result, { plain, filename: 'Research résumé.pdf', mimeType: 'application/pdf' });
});
test('unknown MIME types keep original extension; legacy uploads still download', () => {
  const plain = utf8('legacy file');
  assert.deepEqual(unpackFile(plain, 7), { plain, filename: 'securefile-7.bin', mimeType: 'application/octet-stream' });
  assert.equal(unpackFile(packFile(plain, { filename: 'archive.tar.gz' }), 7).filename, 'archive.tar.gz');
  assert.equal(unpackFile(packFile(plain, { filename: 'empty.pdf', mimeType: '' }), 7).mimeType, 'application/octet-stream');
  assert.equal(unpackFile(packFile(new Uint8Array(), { filename: 'empty.txt' }), 7).plain.length, 0);
});
test('malformed metadata is rejected and filenames cannot contain paths', () => {
  assert.equal(safeFilename('../../report.pdf'), 'report.pdf');
  assert.equal(safeFilename('C:\\private\\report.pdf'), 'report.pdf');
  const payload = packFile(utf8('test'), { filename: 'report.pdf' });
  assert.throws(() => unpackFile(payload.slice(0, 17), 7), /header/);
});
