// nonce 導出（§4.3・P2）。pure・crypto 非依存。

import { NONCE_LEN } from "../config/constants.js";

/**
 * nonce_i = uint96_BE(i)。12 byte の big-endian、i は最下位側へ詰める。
 * i < 2^32 では上位 8 byte = 0。nonce は GCF に保存しない（index から導出）。
 * @param {number|bigint} i frame index
 * @returns {Uint8Array} 12B
 */
export function nonceForFrame(i) {
  const b = new Uint8Array(NONCE_LEN);
  let v = BigInt(i);
  if (v < 0n) throw new RangeError("frame index は非負");
  for (let p = NONCE_LEN - 1; p >= 0 && v > 0n; p--) {
    b[p] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}
