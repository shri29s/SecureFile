export const canonicalManifest = m => `SFS-UPLOAD-v1|${m.groupId}|${m.uploaderId}|${m.contentMac}|${m.ctHash}|${m.keyVersion}|${m.size}|${m.clientTs}|${m.nonce}`;
