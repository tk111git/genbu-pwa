// inspect（§5.8・keyless）。master_key 不要。header 表示 + 層1(frame_checksum)/層2(manifest) 検査のみ。
// GCM decrypt はしない。整合エラーは throw せず boolean フラグで報告する（診断用途）。

import { HEADER_LEN, FRAME_PREFIX_LEN, TRAILER_LEN, TAG_LEN, MAGIC_END } from "../config/constants.js";
import { unpackHeader, unpackFramePrefix, bytesEqual } from "../domain/layout.js";
import { Sha256 } from "../domain/sha256.js";
import { webCryptoPort } from "../adapters/crypto_webcrypto.js";
import { InvalidFormatError } from "../domain/errors.js";
import { sourceSize, readRange } from "./_io.js";

function manifestItem(i, frameLen, frameChecksum) {
  const buf = new Uint8Array(8 + 32);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, i, false);
  dv.setUint32(4, frameLen, false);
  buf.set(frameChecksum, 8);
  return buf;
}

/**
 * @param {Blob|Uint8Array} gcf
 * @param {{crypto?:import("../ports/crypto.js").CryptoPort}} [opts]
 * @returns {Promise<{version, keyGenId, chunkSize, frameCount, originalSize,
 *   manifestOk:boolean, frames:Array<{index, frameLen, checksumOk:boolean}>, truncated:boolean}>}
 */
export async function inspect(gcf, opts = {}) {
  const crypto = opts.crypto ?? webCryptoPort();
  const total = sourceSize(gcf);

  if (total < HEADER_LEN) throw new InvalidFormatError("header が 40B 未満");
  const header = await readRange(gcf, 0, HEADER_LEN);
  const { version, keyGenId, chunkSize, frameCount, originalSize } = unpackHeader(header);

  const out = {
    version,
    keyGenId,
    chunkSize,
    frameCount,
    originalSize: Number(originalSize),
    manifestOk: false,
    frames: [],
    truncated: false,
  };

  if (total < HEADER_LEN + TRAILER_LEN) {
    out.truncated = true;
    return out;
  }

  const trailer = await readRange(gcf, total - TRAILER_LEN, TRAILER_LEN);
  const storedManifest = trailer.slice(0, 32);
  if (!bytesEqual(trailer.subarray(32, 36), MAGIC_END)) out.truncated = true;

  const manifest = new Sha256();
  manifest.update(header);
  let off = HEADER_LEN;
  const bodyLimit = total - TRAILER_LEN;
  let walkOk = true;

  for (let i = 0; i < frameCount; i++) {
    if (off + FRAME_PREFIX_LEN > bodyLimit) {
      out.truncated = true;
      walkOk = false;
      break;
    }
    const prefixBytes = await readRange(gcf, off, FRAME_PREFIX_LEN);
    const { frameLen, frameChecksum } = unpackFramePrefix(prefixBytes);
    const frameLenOk = frameLen > TAG_LEN && frameLen <= chunkSize + TAG_LEN;
    if (!frameLenOk || off + FRAME_PREFIX_LEN + frameLen > bodyLimit) {
      out.truncated = true;
      walkOk = false;
      break;
    }
    const body = await readRange(gcf, off + FRAME_PREFIX_LEN, frameLen);
    const actual = await crypto.sha256(body);
    out.frames.push({ index: i, frameLen, checksumOk: bytesEqual(actual, frameChecksum) });
    manifest.update(manifestItem(i, frameLen, frameChecksum));
    off += FRAME_PREFIX_LEN + frameLen;
  }

  out.manifestOk =
    walkOk && off === bodyLimit && !out.truncated && bytesEqual(manifest.digest(), storedManifest);

  return out;
}
