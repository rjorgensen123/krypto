# SPEC-secretstore — the on-disk format of `SecretStore`

**Status:** normative · **Spec version:** 1.0 (2026-11-16) · **Applies to:** krypto 0.9.0 and later; version 1 files remain readable

This document is self-contained. It specifies the on-disk format of krypto's
`SecretStore` — file format versions 1 and 2 — and the rules for reading, writing,
upgrading, rotating, and anchoring store files. It does not depend on any other
document.

## 1. Scope and definitions

- A **store file** is the on-disk form of a `SecretStore`: one header followed by zero
  or more entries.
- The 4 bytes at offset 0 are the magic `FST1` in every version. The format version is
  the single byte at offset 4.
- An **entry** is `name_len (u16 LE) | name | blob_len (u32 LE) | blob`, where `blob` is
  a FAFN AEAD blob. The entry encoding is identical in versions 1 and 2.
- **Key names** are non-empty, at most 512 bytes, printable ASCII (`0x20`–`0x7E`),
  validated on both read and write. Names are not secret; they are listed by `list()`.
- `MAX_STORE_BYTES` (16 MiB) caps the whole file, header included, on both read and
  write.
- Each entry blob is sealed with a per-name key derived as
  `HKDF-SHA256(master, salt, info = "krypto/store/v1|" || name)`, and the store's
  `key_id` is the blob's AAD. This is identical in versions 1 and 2. The context
  string `krypto/store/v1|` is frozen: stored data depends on it.
- HKDF is HKDF-SHA256 (RFC 5869), HMAC is HMAC-SHA256 (RFC 2104). krypto implements no
  cryptography of its own.

## 2. Why version 2 exists

Reviews of version 1 identified that v1 authenticates each entry individually but not
the file as a whole: an actor able to write the file could remove an entry, swap
entries, inject names visible in `list()`, or restore an older copy of the file, and
`open` did not detect any of it. `open` also did not check the master key. Version 2
adds a container-level MAC, a key-check value, and a counter that enables rollback
detection. Version 1 is frozen and remains readable.

## 3. Header

### 3.1 Version 1 (frozen; every reader must accept it)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `FST1` |
| 4 | 1 | version = 1 |
| 5 | 16 | salt |
| 21 | 16 | key_id |
| 37 | … | entries |

Version 1 has no container MAC and no key-check value. `open` on a v1 file does not
verify the master key; a wrong key surfaces as `Auth` from `get`.

### 3.2 Version 2

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `FST1` |
| 4 | 1 | version = 2 |
| 5 | 16 | salt |
| 21 | 16 | key_id |
| 37 | 32 | `key_check` = HMAC-SHA256(K_check, `"FST1" \|\| ver \|\| salt`) |
| 69 | 8 | `counter`, u64 LE |
| 77 | 32 | `container_mac` = HMAC-SHA256(K_mac, `header[0..77] \|\| entries`) |
| 109 | … | entries |

- `K_check` = HKDF-SHA256(master, salt, info = `"krypto/store/v2|key-check"`)
- `K_mac` = HKDF-SHA256(master, salt, info = `"krypto/store/v2|container-mac"`)
- MACs are compared in constant time.
- `counter` starts at 0 for a new store, increases by 1 on every write, is covered by
  `container_mac`, and resets to 0 on rotation (new salt and `key_id` mark a new
  generation).
- The v2 context strings `krypto/store/v2|key-check` and `krypto/store/v2|container-mac`
  are frozen from the first v2 file written.

## 4. Reading a store (`open`)

Checks run in this order:

1. The path exists, opens, and is a regular file (FIFOs and other special files do not
   block and are rejected).
2. The file size is within `MAX_STORE_BYTES`.
3. Magic: not `FST1` → `Format`.
4. Version: 1 → v1 parser; 2 → v2 parser; anything else → `Format` with
   `unsupported store version N`.
5. Structure: all length arithmetic is checked (no panics on any input); invalid UTF-8
   or illegal key names → `Format`; duplicate names → `Format`.
6. If version 2: `key_check` mismatch → `Auth`; `container_mac` mismatch → `Auth`.

Error classes:

| Class | Meaning |
|---|---|
| `Format` | the input is not a store file, is structurally invalid, or has an unknown version |
| `Auth` | authenticated content does not verify: wrong master key, or tampering with a v2 header or entry table |
| `Rollback` | v2 only, and only when the caller supplies an anchor: the file's `counter` is below the caller's minimum |

## 5. Writing a store

- A store file is always written atomically: a temporary file created with
  `create_new`, mode `0600` from its first byte, unpredictable name; fsync; rename;
  directory fsync.
- The written version equals the opened file's version (sticky versioning). A store
  created new is version 2 unless the caller explicitly requests version 1.
- After the rename, memory follows the file: a failed directory sync after the rename
  is reported as an I/O error and is not rolled back.
- One handle per file: `open` takes an exclusive `flock` on `.<name>.lock` beside the
  store for the handle's lifetime. A symlink at the lock name is never followed; a
  non-regular file there is rejected.

## 6. Upgrade and rotation

- **Upgrade** (`v1 → v2`) is explicit and chosen by the caller, and is one-way. All
  entries are decrypted and verified first; any `Auth` aborts with the file untouched.
  The file is then written as version 2 in a single atomic write. Because salt,
  `key_id`, and the entry key context are unchanged, upgrade re-wraps the existing
  blobs without re-encrypting them. After an upgrade, binaries that accept only
  version 1 can no longer read the file; they report `unsupported store version 2`.
- **Rotation** (`rotate(new_master)`) decrypts every entry with the old master first
  (any `Auth` aborts, file untouched), then writes a new file with a fresh salt, a
  fresh `key_id`, all entries re-sealed under the new master, `counter` reset to 0, in
  one atomic rename. The file's version is preserved.

## 7. Rollback detection (optional, caller-anchored)

krypto is stateless: it stores nothing outside the store file. The v2 `counter` is
covered by `container_mac`, so it cannot be lowered without breaking the MAC; rolling
back the whole file to an older valid copy is detected by comparing the file's
`counter` against a minimum kept outside the file. krypto exposes `version()` and
`counter()` for this, and an anchored open that takes a minimum counter and fails with
`Rollback` when the file's counter is lower. If the caller supplies no anchor, no
freshness check is performed; for version 2, `key_check` and `container_mac` are
always verified.

## 8. Compatibility summary

| File version | Read by this code | Written by this code | Readable by pre-v2 binaries |
|---|---|---|---|
| 1 | yes (frozen parser, no MAC) | only if the file is already v1 (sticky), or v1 explicitly requested for a new store | yes |
| 2 | yes (`key_check` + `container_mac` verified) | default for new stores; after an explicit upgrade | no — `Format`, `unsupported store version 2` |
