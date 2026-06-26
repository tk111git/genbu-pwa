// INV-4 例外 taxonomy（§5.3 / §6）。
// JS 側 taxonomy は本書で定義する（Python class 名を mirror しない）。
// wire 形式が契約であり、識別可能性（§4.7）が test される不変条件。

export class GcfError extends Error {
  constructor(msg) {
    super(msg);
    this.name = new.target.name;
  }
}

// magic/version/flags/長さ/frame_len 範囲外（§4.7 段1）
export class InvalidFormatError extends GcfError {}

// magic_end 欠落 / 途中切れ / emitted≠original_size（§4.7 段1・末尾）
export class TruncatedError extends GcfError {}

// manifest_checksum 不一致（header改竄/順序/個数/切詰め・§4.7 段2）
export class ManifestChecksumError extends GcfError {}

// frame_checksum 不一致（bit-rot・§4.7 段3）
export class FrameChecksumError extends GcfError {
  constructor(msg, frameIndex) {
    super(msg);
    this.frameIndex = frameIndex;
  }
}

// GCM tag 不一致（誤鍵 / body 改竄・§4.7 段4）
export class DecryptError extends GcfError {
  constructor(msg, frameIndex) {
    super(msg);
    this.frameIndex = frameIndex;
  }
}
