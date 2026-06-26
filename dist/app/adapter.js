// P-reskin port 実装（裁定3）。UI が依存する唯一の crypto-call-surface。
// これは thin 層: vendored GCF v2 client（../vendor/gcf）の AsyncGenerator を
// download 用 Blob に集約するだけ。crypto は再実装しない（§6 MUST NOT）。
//
// 不変条件 P-reskin: presentation ⊥ crypto-call-surface
//   UI は本 module の encryptFile/decryptFile/inspectFile（+ error class）だけを呼ぶ。
//   v2 client / crypto.subtle を直接触らない。
//   ∴ 将来 streaming sink（showSaveFilePicker 等・M2）へ差し替えても UI 不変。

import {
  encryptStream,
  decryptStream,
  inspect,
} from "../vendor/gcf/index.js";

// 裁定2: client の GcfError 階層を素通しする（adapter は wrap/rename しない）。
// UI 側 messageForError(e) が class → 利用者向け文へ map するため re-export する。
export {
  GcfError,
  InvalidFormatError,
  TruncatedError,
  ManifestChecksumError,
  FrameChecksumError,
  DecryptError,
} from "../vendor/gcf/index.js";

const HEX64 = /^[0-9a-fA-F]{64}$/;

/**
 * UI の 64-hex master key（裁定1）→ Uint8Array(32)。adapter 入口で1回だけ変換する。
 * client の HKDF は無改変（masterKey をそのまま受ける）。
 * @param {string} hex
 * @returns {Uint8Array} 32B
 */
export function keyFromHex(hex) {
  const h = (hex ?? "").trim();
  if (!HEX64.test(h)) throw new RangeError("master key must be 64 hex chars (32 bytes)");
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

/**
 * encryptFile（port §4.1）: 平文 File → GCF v2 .gcf Blob。
 * keyGenId/fileSalt/chunkSize は渡さない = client default（D6: internal）。
 * @param {File|Blob} file
 * @param {Uint8Array} masterKeyU8 32B
 * @returns {Promise<Blob>}
 */
export async function encryptFile(file, masterKeyU8) {
  const parts = [];
  for await (const chunk of encryptStream(file, masterKeyU8)) parts.push(chunk);
  return new Blob(parts);
}

/**
 * decryptFile（port §4.1）: GCF v2 .gcf → 平文 Blob + 元名。
 * GcfError subclass（bit-rot=FrameChecksumError ⊥ wrong-key=DecryptError 等）は素通しで throw。
 * @param {File|Blob} blob
 * @param {Uint8Array} masterKeyU8 32B
 * @param {string} [inputName]
 * @returns {Promise<{plaintext: Blob, name: string}>}
 */
export async function decryptFile(blob, masterKeyU8, inputName = "") {
  const parts = [];
  for await (const chunk of decryptStream(blob, masterKeyU8)) parts.push(chunk);
  const name = inputName.replace(/\.gcf$/i, "") || "decrypted.out";
  return { plaintext: new Blob(parts), name };
}

/**
 * inspectFile（port §4.1・B-5）: 鍵不要の integrity view。
 * client.inspect は throw でなく構造体を返す（裁定2）→ そのまま透過。
 * @param {File|Blob} blob
 * @returns {Promise<object>} {version, keyGenId, chunkSize, frameCount, originalSize,
 *                             manifestOk, frames:[{index,frameLen,checksumOk}], truncated}
 */
export function inspectFile(blob) {
  return inspect(blob);
}
