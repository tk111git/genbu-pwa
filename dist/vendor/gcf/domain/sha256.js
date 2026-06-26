// 逐次 SHA-256（§7・INV-5）。pure・crypto 非依存。
// WebCrypto の digest は incremental API を持たないため、manifest を「全 frame を貯めずに」
// 算出するために streaming hash を用いる。出力は WebCrypto SHA-256 と byte 一致（unit test で担保）。
// 実装は FIPS 180-4 に従う標準 SHA-256。

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

export class Sha256 {
  constructor() {
    this._h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    this._block = new Uint8Array(64);
    this._blockLen = 0; // 現 block に溜まった byte 数
    this._len = 0n; // 総 byte 数（bit 長計算用）
    this._w = new Uint32Array(64);
  }

  /** @param {Uint8Array} data */
  update(data) {
    this._len += BigInt(data.length);
    let off = 0;
    // 端数 block を埋める
    if (this._blockLen > 0) {
      const need = 64 - this._blockLen;
      const take = Math.min(need, data.length);
      this._block.set(data.subarray(0, take), this._blockLen);
      this._blockLen += take;
      off = take;
      if (this._blockLen === 64) {
        this._compress(this._block, 0);
        this._blockLen = 0;
      }
    }
    // full block を直接処理
    while (off + 64 <= data.length) {
      this._compress(data, off);
      off += 64;
    }
    // 残りを退避
    if (off < data.length) {
      this._block.set(data.subarray(off), this._blockLen);
      this._blockLen += data.length - off;
    }
    return this;
  }

  /** @returns {Uint8Array} 32B digest（呼び出し後は再利用しない） */
  digest() {
    const bitLen = this._len * 8n;
    // padding: 0x80 ‖ 0x00... ‖ uint64_BE(bitLen)
    const pad = [];
    pad.push(0x80);
    let totalLen = this._blockLen + 1;
    while ((totalLen + 8) % 64 !== 0) {
      pad.push(0x00);
      totalLen++;
    }
    const lenBytes = new Uint8Array(8);
    new DataView(lenBytes.buffer).setBigUint64(0, bitLen, false);
    this.update(new Uint8Array(pad));
    // この時点で blockLen は 56 → update で 8 足すと 64 になり compress される
    this.update(lenBytes);

    const out = new Uint8Array(32);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) dv.setUint32(i * 4, this._h[i], false);
    return out;
  }

  _compress(buf, off) {
    const w = this._w;
    const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = this._h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    const H = this._h;
    H[0] = (H[0] + a) | 0;
    H[1] = (H[1] + b) | 0;
    H[2] = (H[2] + c) | 0;
    H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0;
    H[5] = (H[5] + f) | 0;
    H[6] = (H[6] + g) | 0;
    H[7] = (H[7] + h) | 0;
  }
}

/** one-shot helper（pure）。 */
export function sha256(bytes) {
  return new Sha256().update(bytes).digest();
}
