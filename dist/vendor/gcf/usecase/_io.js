// bounded IO（INV-5・§7）。Blob|Uint8Array を共通の「サイズ取得 + 範囲読込」に正規化する。
// Blob は slice→arrayBuffer で 1 範囲のみ実体化する（peak memory = O(range)）。

/**
 * @param {Blob|Uint8Array} src
 * @returns {number} 総 byte 数
 */
export function sourceSize(src) {
  if (src instanceof Uint8Array) return src.length;
  if (src && typeof src.size === "number") return src.size; // Blob
  throw new TypeError("入力は Blob または Uint8Array");
}

/**
 * [off, off+len) を Uint8Array で返す（end は size で clamp）。
 * @param {Blob|Uint8Array} src
 * @param {number} off
 * @param {number} len
 * @returns {Promise<Uint8Array>}
 */
export async function readRange(src, off, len) {
  if (src instanceof Uint8Array) {
    return src.subarray(off, off + len);
  }
  // Blob: 1 範囲のみ実体化
  const ab = await src.slice(off, off + len).arrayBuffer();
  return new Uint8Array(ab);
}
