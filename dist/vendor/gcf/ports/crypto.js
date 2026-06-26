// CryptoPort 契約（§5.4）。shape を JSDoc で明示（実装は adapters/）。

/**
 * @typedef {Object} CryptoPort
 * @property {(masterKey:Uint8Array, fileSalt:Uint8Array)=>Promise<Uint8Array>} deriveFileKeyRaw  // 32B
 * @property {(fileKeyRaw:Uint8Array, nonce:Uint8Array, plaintext:Uint8Array)=>Promise<Uint8Array>} encryptFrame // ct||tag
 * @property {(fileKeyRaw:Uint8Array, nonce:Uint8Array, body:Uint8Array)=>Promise<Uint8Array>} decryptFrame     // plaintext / throw DecryptError
 * @property {(bytes:Uint8Array)=>Promise<Uint8Array>} sha256 // 32B
 */

export {};
