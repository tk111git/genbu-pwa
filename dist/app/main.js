// 公開 UI 配線。UI は adapter（port）にのみ依存する（P-reskin）。
// v2 client / crypto.subtle を直接呼ばない。error は class → 文へ map する（裁定2）。

import {
  encryptFile,
  decryptFile,
  inspectFile,
  keyFromHex,
  InvalidFormatError,
  TruncatedError,
  ManifestChecksumError,
  FrameChecksumError,
  DecryptError,
} from "./adapter.js";

// --- 裁定2: GcfError subclass → 利用者向け文（bit-rot ⊥ wrong-key を区別表示・F5）---
function messageForError(e) {
  if (e instanceof FrameChecksumError)
    return "File is corrupted (bit-rot) — this is not a key error.";
  if (e instanceof DecryptError)
    return "Wrong key, or the file was tampered with — not bit-rot.";
  if (e instanceof ManifestChecksumError)
    return "File header is corrupted or tampered with.";
  if (e instanceof TruncatedError)
    return "File is incomplete or truncated — the download may have been interrupted.";
  if (e instanceof InvalidFormatError)
    return "Not a GENBU file (or unsupported version).";
  if (e instanceof RangeError) return e.message; // key 形式エラー等
  return String(e?.message ?? e);
}

// --- helpers ---
const $ = (id) => document.getElementById(id);
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

function pickFile(el) {
  const f = el.files && el.files[0];
  if (!f) throw new Error("choose a file first");
  return f;
}

function download(blob, name) {
  const u = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = u;
  a.download = name;
  a.click();
  URL.revokeObjectURL(u);
}

// --- key panel（裁定1: raw-key hex64 + Generate）---
function genKey() {
  $("key").value = hex(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

// --- encrypt ---
async function doEncrypt() {
  const o = $("encOut");
  try {
    const key = keyFromHex($("key").value);
    const file = pickFile($("encFile"));
    const blob = await encryptFile(file, key);
    download(blob, file.name + ".gcf");
    o.innerHTML = `<span class="ok">✅ encrypted</span>  ${blob.size} bytes\ndownloaded: ${file.name}.gcf`;
  } catch (e) {
    o.innerHTML = `<span class="bad">❌ ${messageForError(e)}</span>`;
  }
}

// --- decrypt ---
async function doDecrypt() {
  const o = $("decOut");
  try {
    const key = keyFromHex($("key").value);
    const file = pickFile($("decFile"));
    const { plaintext, name } = await decryptFile(file, key, file.name);
    download(plaintext, name);
    o.innerHTML = `<span class="ok">✅ decrypted</span>  ${plaintext.size} bytes\ndownloaded: ${name}`;
  } catch (e) {
    o.innerHTML = `<span class="bad">❌ ${messageForError(e)}</span>`;
  }
}

// --- inspect（鍵不要・B-5）: 構造体を読む（例外 map と二重化しない・裁定2）---
async function doInspect() {
  const o = $("decOut");
  try {
    const file = pickFile($("decFile"));
    const r = await inspectFile(file);
    const framesOk = r.frames.length > 0 && r.frames.every((f) => f.checksumOk);
    let integrity;
    if (r.truncated)
      integrity = '<span class="bad">INCOMPLETE / truncated</span>';
    else if (!r.manifestOk)
      integrity = '<span class="bad">HEADER corrupted or tampered</span>';
    else if (!framesOk)
      integrity = '<span class="bad">CORRUPT (bit-rot)</span>';
    else integrity = '<span class="ok">OK</span>';

    o.innerHTML = `version     : ${r.version}
frames      : ${r.frameCount}
size        : ${r.originalSize} bytes
integrity   : ${integrity}  <span class="acc">(read with NO key)</span>`;
  } catch (e) {
    o.innerHTML = `<span class="bad">❌ ${messageForError(e)}</span>`;
  }
}

// --- wire（UI は adapter 経由のみ。inline onclick を使わず module scope で束ねる）---
$("genKey").addEventListener("click", genKey);
$("doEncrypt").addEventListener("click", doEncrypt);
$("doInspect").addEventListener("click", doInspect);
$("doDecrypt").addEventListener("click", doDecrypt);

genKey(); // 初回 key を提示（Generate を主要動線に）
