// GCF v2 wire 定数（§4.0）。すべて normative・golden vector で裏取り済。

export const MAGIC = new Uint8Array([0x47, 0x45, 0x4e, 0x42]); // "GENB"
export const MAGIC_END = new Uint8Array([0x42, 0x4e, 0x45, 0x47]); // "BNEG"
export const VERSION = 0x02;
export const HEADER_LEN = 40;
export const FRAME_PREFIX_LEN = 36; // frame_len(4) + frame_checksum(32)
export const TRAILER_LEN = 36; // manifest(32) + magic_end(4)
export const TAG_LEN = 16; // GCM tag 128-bit
export const NONCE_LEN = 12; // 96-bit
export const KEY_LEN = 32;
export const SALT_LEN = 16;
export const HKDF_INFO = new TextEncoder().encode("GENBU-GCF-v2-filekey"); // UTF-8, null 終端なし
export const DEFAULT_CHUNK_SIZE = 64 * 1024 * 1024; // 67108864 (64 MiB)
