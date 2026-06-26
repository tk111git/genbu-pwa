// encryptStream（§5.6・§7）。header → frame* → trailer を順次 yield。
// peak memory = O(chunk_size)（Blob.slice で 1 chunk のみ読む・manifest は逐次 hash）。

import { DEFAULT_CHUNK_SIZE, TAG_LEN } from "../config/constants.js";
import { packHeader, packFramePrefix, packTrailer } from "../domain/layout.js";
import { nonceForFrame } from "../domain/nonce.js";
import { Sha256 } from "../domain/sha256.js";
import { webCryptoPort } from "../adapters/crypto_webcrypto.js";
import { sourceSize, readRange } from "./_io.js";

function manifestItem(i, frameLen, frameChecksum) {
  const buf = new Uint8Array(8 + 32);
  const dv = new DataView(buf.buffer);
  dv.setUint32(0, i, false); // uint32_BE(i)
  dv.setUint32(4, frameLen, false); // uint32_BE(frame_len)
  buf.set(frameChecksum, 8);
  return buf;
}

/**
 * @param {Blob|Uint8Array} plaintext
 * @param {Uint8Array} masterKey 32B
 * @param {{keyGenId?:number, chunkSize?:number, crypto?:import("../ports/crypto.js").CryptoPort}} [opts]
 * @returns {AsyncGenerator<Uint8Array>}  // .gcf を成す byte 片を順次 yield
 */
export async function* encryptStream(plaintext, masterKey, opts = {}) {
  const crypto = opts.crypto ?? webCryptoPort();
  const keyGenId = opts.keyGenId ?? 0;
  const chunkSize = opts.chunkSize ?? DEFAULT_CHUNK_SIZE;
  if (!(keyGenId >= 0 && keyGenId <= 0xffff)) throw new RangeError("key_gen_id は 0..65535");
  if (!(chunkSize > 0)) throw new RangeError("chunk_size は正");

  const originalSize = sourceSize(plaintext);
  const frameCount = originalSize === 0 ? 0 : Math.ceil(originalSize / chunkSize);

  // file_salt（header 平文 16B・HKDF salt）。本番は file 毎にランダム生成（一意性は構造で担保）。
  // §8 conformance では opts.fileSalt に fixture の固定 salt を注入し byte 一致させる。
  const fileSalt = opts.fileSalt ?? globalThis.crypto.getRandomValues(new Uint8Array(16));
  if (fileSalt.length !== 16) throw new RangeError("file_salt は 16B");

  const fileKey = await crypto.deriveFileKeyRaw(masterKey, fileSalt);

  const header = packHeader({ keyGenId, fileSalt, chunkSize, frameCount, originalSize });

  const manifest = new Sha256();
  manifest.update(header);
  yield header;

  for (let i = 0; i < frameCount; i++) {
    const off = i * chunkSize;
    const chunk = await readRange(plaintext, off, chunkSize);
    const nonce = nonceForFrame(i);
    const body = await crypto.encryptFrame(fileKey, nonce, chunk); // ct ‖ tag
    const frameLen = body.length; // == chunk.length + TAG_LEN
    const fcsum = await crypto.sha256(body);

    manifest.update(manifestItem(i, frameLen, fcsum));
    yield packFramePrefix(frameLen, fcsum);
    yield body;
    // chunk / body はここで参照を失い解放される（INV-5）
  }

  yield packTrailer(manifest.digest());
}

export { TAG_LEN };
