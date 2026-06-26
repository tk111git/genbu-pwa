// header/frame/trailer の pack/unpack（§5.1）。pure・crypto 非依存。
// すべて big-endian。original_size は uint64（DataView.setBigUint64/getBigUint64）。

import {
  MAGIC,
  MAGIC_END,
  VERSION,
  HEADER_LEN,
  FRAME_PREFIX_LEN,
  TRAILER_LEN,
  SALT_LEN,
} from "../config/constants.js";
import { InvalidFormatError } from "./errors.js";

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * file_header（固定 40 byte・§4.4）`>4sBBH16sIIQ`。
 * @param {{keyGenId:number, fileSalt:Uint8Array, chunkSize:number, frameCount:number, originalSize:number|bigint}} h
 * @returns {Uint8Array} 40B
 */
export function packHeader({ keyGenId, fileSalt, chunkSize, frameCount, originalSize }) {
  if (!(keyGenId >= 0 && keyGenId <= 0xffff)) throw new RangeError("key_gen_id は uint16 範囲");
  if (!(chunkSize > 0 && chunkSize <= 0xffffffff)) throw new RangeError("chunk_size は uint32 正");
  if (!(frameCount >= 0 && frameCount <= 0xffffffff)) throw new RangeError("frame_count は uint32");
  if (!fileSalt || fileSalt.length !== SALT_LEN) throw new RangeError("file_salt は 16B");

  const buf = new Uint8Array(HEADER_LEN);
  const dv = new DataView(buf.buffer);
  buf.set(MAGIC, 0); // 0..4   magic "GENB"
  buf[4] = VERSION; // 4       version
  buf[5] = 0x00; // 5          flags (reserved, MUST be 0)
  dv.setUint16(6, keyGenId, false); // 6..8   key_gen_id
  buf.set(fileSalt, 8); // 8..24  file_salt
  dv.setUint32(24, chunkSize, false); // 24..28 chunk_size
  dv.setUint32(28, frameCount, false); // 28..32 frame_count
  dv.setBigUint64(32, BigInt(originalSize), false); // 32..40 original_size
  return buf;
}

/**
 * @param {Uint8Array} bytes >=40
 * @returns {{version:number, flags:number, keyGenId:number, fileSalt:Uint8Array,
 *            chunkSize:number, frameCount:number, originalSize:bigint}}
 */
export function unpackHeader(bytes) {
  if (!bytes || bytes.length < HEADER_LEN) throw new InvalidFormatError("header が 40B 未満");
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  if (!bytesEqual(bytes.subarray(0, 4), MAGIC)) throw new InvalidFormatError("magic != GENB");
  const version = bytes[4];
  if (version !== VERSION) throw new InvalidFormatError(`version != 2 (${version})`);
  const flags = bytes[5];
  if (flags !== 0) throw new InvalidFormatError(`flags != 0 (${flags})`);
  const keyGenId = dv.getUint16(6, false);
  const fileSalt = bytes.slice(8, 24);
  const chunkSize = dv.getUint32(24, false);
  if (chunkSize <= 0) throw new InvalidFormatError("chunk_size <= 0");
  const frameCount = dv.getUint32(28, false);
  const originalSize = dv.getBigUint64(32, false);

  return { version, flags, keyGenId, fileSalt, chunkSize, frameCount, originalSize };
}

/**
 * frame prefix（§4.5）= frame_len(4) ‖ frame_checksum(32)。
 * @param {number} frameLen
 * @param {Uint8Array} frameChecksum 32B
 * @returns {Uint8Array} 36B
 */
export function packFramePrefix(frameLen, frameChecksum) {
  if (!(frameLen >= 0 && frameLen <= 0xffffffff)) throw new RangeError("frame_len は uint32");
  if (!frameChecksum || frameChecksum.length !== 32) throw new RangeError("frame_checksum は 32B");
  const buf = new Uint8Array(FRAME_PREFIX_LEN);
  new DataView(buf.buffer).setUint32(0, frameLen, false);
  buf.set(frameChecksum, 4);
  return buf;
}

/**
 * @param {Uint8Array} bytes >=36
 * @returns {{frameLen:number, frameChecksum:Uint8Array}}
 */
export function unpackFramePrefix(bytes) {
  if (!bytes || bytes.length < FRAME_PREFIX_LEN)
    throw new InvalidFormatError("frame prefix が 36B 未満");
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const frameLen = dv.getUint32(0, false);
  const frameChecksum = bytes.slice(4, 36);
  return { frameLen, frameChecksum };
}

/**
 * trailer（固定 36 byte・§4.6）= manifest_checksum(32) ‖ magic_end "BNEG"(4)。
 * @param {Uint8Array} manifestChecksum 32B
 * @returns {Uint8Array} 36B
 */
export function packTrailer(manifestChecksum) {
  if (!manifestChecksum || manifestChecksum.length !== 32)
    throw new RangeError("manifest_checksum は 32B");
  const buf = new Uint8Array(TRAILER_LEN);
  buf.set(manifestChecksum, 0);
  buf.set(MAGIC_END, 32);
  return buf;
}

export { bytesEqual };
