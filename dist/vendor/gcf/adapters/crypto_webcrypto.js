// WebCrypto 実装（§4.1/§4.2・§5.5）。HKDF / AES-GCM / SHA-256。
// 標準 crypto.subtle のみ（依存追加なし）。offline 完結・network/storage 非依存。

import { HKDF_INFO, TAG_LEN } from "../config/constants.js";
import { DecryptError } from "../domain/errors.js";

const subtle = globalThis.crypto.subtle;

/**
 * §4.1/§4.2 の WebCrypto 実装を返す。
 * file_key の AES-GCM key import は同一 fileKeyRaw 参照に対し 1 回だけ行い使い回す（SHOULD・性能）。
 * @returns {import("../ports/crypto.js").CryptoPort}
 */
export function webCryptoPort() {
  let cachedRaw = null;
  let cachedKey = null;

  async function aesKeyFor(fileKeyRaw) {
    if (cachedRaw === fileKeyRaw && cachedKey) return cachedKey;
    cachedKey = await subtle.importKey("raw", fileKeyRaw, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
    cachedRaw = fileKeyRaw;
    return cachedKey;
  }

  return {
    async deriveFileKeyRaw(masterKey, fileSalt) {
      const base = await subtle.importKey("raw", masterKey, "HKDF", false, ["deriveBits"]);
      const bits = await subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: fileSalt, info: HKDF_INFO },
        base,
        256,
      );
      return new Uint8Array(bits); // 32B（§8: fixture.file_key と一致 MUST）
    },

    async encryptFrame(fileKeyRaw, nonce, plaintext) {
      const key = await aesKeyFor(fileKeyRaw);
      const ctTag = await subtle.encrypt(
        { name: "AES-GCM", iv: nonce, tagLength: 128 },
        key,
        plaintext,
      );
      return new Uint8Array(ctTag); // ct ‖ tag(16)（WebCrypto は tag を末尾連結）
    },

    async decryptFrame(fileKeyRaw, nonce, body) {
      const key = await aesKeyFor(fileKeyRaw);
      try {
        const pt = await subtle.decrypt(
          { name: "AES-GCM", iv: nonce, tagLength: 128 },
          key,
          body,
        );
        return new Uint8Array(pt);
      } catch (e) {
        // WebCrypto は tag 不一致を OperationError で投げる → DecryptError に wrap（§5.5）。
        throw new DecryptError(`AES-GCM 復号失敗（誤鍵 or 改竄）: ${e?.message ?? e}`);
      }
    },

    async sha256(bytes) {
      const d = await subtle.digest("SHA-256", bytes);
      return new Uint8Array(d);
    },
  };
}

export { TAG_LEN };
