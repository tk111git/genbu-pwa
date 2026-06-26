// decryptStream（§5.7・§4.7）。検証順序を厳守し平文 chunk を逐次 yield。
// §4.7: 1 構造検査 → 2 manifest 照合（鍵不要）→ 3 frame_checksum 照合（bit-rot）→ 4 GCM 復号（誤鍵/改竄）。
// peak memory = O(chunk_size)：manifest 照合は frame prefix(36B) のみ走査し、body は復号 pass で 1 回だけ読む。

import { HEADER_LEN, FRAME_PREFIX_LEN, TRAILER_LEN, TAG_LEN, MAGIC_END } from "../config/constants.js";
import { unpackHeader, unpackFramePrefix, bytesEqual } from "../domain/layout.js";
import { nonceForFrame } from "../domain/nonce.js";
import { Sha256 } from "../domain/sha256.js";
import { webCryptoPort } from "../adapters/crypto_webcrypto.js";
import {
  InvalidFormatError,
  TruncatedError,
  ManifestChecksumError,
  FrameChecksumError,
  DecryptError,
} from "../domain/errors.js";
import { sourceSize, readRange } from "./_io.js";

function manifestItem(i, frameLen, frameChecksum) {
  const buf = new Uint8Array(8 + 32);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, i, false);
  dv.setUint32(4, frameLen, false);
  buf.set(frameChecksum, 8);
  return buf;
}

function checkFrameLen(frameLen, chunkSize) {
  if (!(frameLen > TAG_LEN && frameLen <= chunkSize + TAG_LEN))
    throw new InvalidFormatError(`frame_len 範囲外: ${frameLen}`);
}

/**
 * @param {Blob|Uint8Array} gcf
 * @param {Uint8Array} masterKey 32B
 * @param {{crypto?:import("../ports/crypto.js").CryptoPort}} [opts]
 * @returns {AsyncGenerator<Uint8Array>}  // 平文 chunk を逐次 yield
 */
export async function* decryptStream(gcf, masterKey, opts = {}) {
  const crypto = opts.crypto ?? webCryptoPort();
  const total = sourceSize(gcf);

  // --- 1. 構造検査（長さ / magic / version / magic_end）---
  if (total < HEADER_LEN + TRAILER_LEN) throw new TruncatedError("file が header+trailer 未満");

  const header = await readRange(gcf, 0, HEADER_LEN);
  const { keyGenId, fileSalt, chunkSize, frameCount, originalSize } = unpackHeader(header);

  const trailer = await readRange(gcf, total - TRAILER_LEN, TRAILER_LEN);
  const storedManifest = trailer.slice(0, 32);
  if (!bytesEqual(trailer.subarray(32, 36), MAGIC_END))
    throw new TruncatedError("magic_end != BNEG（切詰め）");

  // --- 2. manifest 照合（全体・鍵不要）: header ‖ Σ(i, frame_len, frame_checksum) ---
  const manifest = new Sha256();
  manifest.update(header);
  let off = HEADER_LEN;
  for (let i = 0; i < frameCount; i++) {
    if (off + FRAME_PREFIX_LEN > total - TRAILER_LEN)
      throw new TruncatedError(`frame[${i}] prefix が途中切れ`);
    const prefixBytes = await readRange(gcf, off, FRAME_PREFIX_LEN);
    const { frameLen, frameChecksum } = unpackFramePrefix(prefixBytes);
    checkFrameLen(frameLen, chunkSize);
    if (off + FRAME_PREFIX_LEN + frameLen > total - TRAILER_LEN)
      throw new TruncatedError(`frame[${i}] body が途中切れ`);
    manifest.update(manifestItem(i, frameLen, frameChecksum));
    off += FRAME_PREFIX_LEN + frameLen;
  }
  // N frame 走査後、ちょうど trailer 直前に到達していること（個数整合）。
  if (off !== total - TRAILER_LEN) throw new ManifestChecksumError("frame 連鎖が trailer と不整合");
  if (!bytesEqual(manifest.digest(), storedManifest))
    throw new ManifestChecksumError("manifest_checksum 不一致");

  // --- 3/4. 各 frame: frame_checksum 照合（bit-rot）→ GCM 復号（誤鍵/改竄）→ yield ---
  const fileKey = await crypto.deriveFileKeyRaw(masterKey, fileSalt);
  let emitted = 0n;
  off = HEADER_LEN;
  for (let i = 0; i < frameCount; i++) {
    const prefixBytes = await readRange(gcf, off, FRAME_PREFIX_LEN);
    const { frameLen, frameChecksum } = unpackFramePrefix(prefixBytes);
    const body = await readRange(gcf, off + FRAME_PREFIX_LEN, frameLen);

    const actual = await crypto.sha256(body);
    if (!bytesEqual(actual, frameChecksum))
      throw new FrameChecksumError(`frame[${i}] checksum 不一致（bit-rot）`, i);

    const nonce = nonceForFrame(i);
    let plaintext;
    try {
      plaintext = await crypto.decryptFrame(fileKey, nonce, body);
    } catch (e) {
      // port は frame index を知らないため usecase で frameIndex を付与する（§6）。
      if (e instanceof DecryptError) e.frameIndex = i;
      throw e;
    }
    emitted += BigInt(plaintext.length);
    yield plaintext;
    off += FRAME_PREFIX_LEN + frameLen;
    // body / plaintext はここで解放（INV-5）
  }

  // --- 末尾整合: Σ emitted == original_size ---
  if (emitted !== BigInt(originalSize))
    throw new TruncatedError(`復元長 ${emitted} != original_size ${originalSize}`);

  void keyGenId;
}
