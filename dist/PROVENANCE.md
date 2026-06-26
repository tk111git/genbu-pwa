# GENBU public deploy — provenance

This `dist/` tree is the **public deploy snapshot** for `genbu.info-shared.com`
(repo `genbu-pwa`, public, dist-only). It is built from — and a **frozen snapshot of**
— the crypto SSoT in the private `encrypt_pwa` repo. Do not hand-edit the vendored
client; change it in the SSoT and re-vendor.

## Vendored GCF v2 client — `vendor/gcf/`

| field | value |
|---|---|
| source | `encrypt_pwa/web/src/gcf/` (系統② — GCF data crypto only) |
| provenance commit | `1abd423` — `feat(gcf): GCF v2 JS client (encrypt/decrypt/inspect, streaming, golden-vector conformance)` |
| copy method | **byte-copy** (`cmp` byte-identical, no edits — MUST NOT per INSTRUCTION §6) |
| SSoT | `encrypt_pwa` (private). This copy is a frozen snapshot. |

**Not included (P-e / scope):** 系統① (`web/src/entitlement`, Ed25519 / signing /
token gate) is absent by design. The vendored client holds no signing key or other
secret — it is pure WebCrypto (HKDF-SHA256 + AES-256-GCM + SHA-256) and safe to
publish.

## App layer — `app/`

- `adapter.js` — P-reskin port (`encryptFile` / `decryptFile` / `inspectFile` +
  `keyFromHex` + re-exported `GcfError` subclasses). Thin: collects the client's
  streaming `AsyncGenerator` output into a download `Blob`. No crypto re-implemented.
- `main.js` — UI wiring. Depends **only** on `adapter.js` (never on `vendor/gcf` nor
  `crypto.subtle` directly). Maps `GcfError` subclasses → user-facing messages
  (bit-rot ⊥ wrong-key preserved).

## Rulings applied (INSTRUCTION_genbu_reskin_v2_PHASE1_ruling.md)

- 裁定1 — key = raw-key hex64 (`master key · 64 hex (32 bytes)`) + Generate.
- 裁定2 — error = `GcfError` subclass pass-through + UI `messageForError` map.
- 裁定3 — adapter absorbs streaming-only client into `Blob` aggregation.
- 裁定4 — in-browser self-test omitted from the public shell (dev-only; not shipped).
