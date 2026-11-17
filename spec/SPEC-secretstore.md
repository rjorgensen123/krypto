# SPEC-secretstore — the on-disk format of `SecretStore`

**Status:** normative · **Spec version:** 2.0 (2026-11-17) · **Applies from:** krypto 0.9.0; store files of version 1 remain readable

This document specifies the on-disk format of krypto's `SecretStore` — file format
versions 1 and 2 — and the rules for reading, writing, upgrading and rotating store
files, and for detecting that an older copy has been put back.

It stands on krypto alone. What it uses from elsewhere in krypto is named where it is
used, and everything it uses from outside krypto is listed under References.

## 1. Scope and definitions

- A **store file** is the on-disk form of a `SecretStore`: one header followed by zero
  or more entries.
- The 4 bytes at offset 0 are the magic `FST1` in every version. The format version is
  the single byte at offset 4.
- An **entry** is `name_len (u16 LE) | name | blob_len (u32 LE) | blob`, where `blob` is
  a FAFN AEAD blob. The entry encoding is identical in versions 1 and 2.
- **Entry names** are non-empty, at most 512 bytes, printable ASCII (`0x20`–`0x7E`),
  validated on both read and write. Names are not secret; they are listed by `list()`.
- `MAX_STORE_BYTES` (16 MiB) caps the whole file, header included, on both read and
  write.
- Each entry blob is sealed with a per-name key derived as
  `HKDF-SHA256(master, salt, info = "krypto/store/v1|" || name)`, and the blob carries
  the store's `key_id` in its header, which is the blob's AAD. This is identical in
  versions 1 and 2. The context string `krypto/store/v1|` is frozen: stored data
  depends on it.
- `key_id` is 16 random bytes that krypto generates when a store is created and again at
  each rotation. It names the store's current generation: it stays the same until the
  next rotation, and no two stores share one in practice. It is not secret: it can be
  read from the file without the master key, and from an open store. Reading it gives
  the value or fails: `Io` if the file cannot be opened, `Format` if it is not a store
  file. Read without the master key, it is what the file says and is not authenticated.
  krypto keeps no record of which master key a store is under. A caller that wants that
  overview keeps it, and can use `key_id` as the store's id in it. A store file is not
  tied to its path: which file belongs where is the caller's to know, and `key_id` is
  what tells two stores apart.
- An **anchor** is a minimum `counter` that a caller keeps outside the file and gives
  to an **anchored open** (section 7).
- HKDF is HKDF-SHA256 (RFC 5869), HMAC is HMAC-SHA256 (RFC 2104). krypto implements no
  cryptography of its own.

## 2. Why version 2 exists

Version 1 was the starting point, and a deliberate one. Several reviews of it, by AI
models and by a person, pointed out the same weakness: v1 authenticates each entry
individually but not the file as a whole. An actor able to write the file could remove
an entry, swap entries, inject names visible in `list()`, or restore an older copy of
the file, and `open` did not detect any of it. `open` also did not check the master key.
Version 2 adds a container-level MAC, a key-check value, and a counter that enables
rollback detection. Version 1 is frozen and remains readable.

## 3. Header

### 3.1 Version 1 (frozen)

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
- `key_check` says whether the master key fits the file; `container_mac` says whether
  the file is what was written. They are two checks so that the two failures get two
  different answers (section 4).
- `counter` starts at 0 for a new store, increases by 1 on every write, is covered by
  `container_mac`, and resets to 0 on rotation (new salt and `key_id` mark a new
  generation). It is an unsigned 64-bit number that only goes up and never wraps: a
  store whose counter is at its maximum refuses to write. The write fails with
  `Hardening`, the error says that the counter is at its maximum and that the store must
  be rotated, and nothing is written.
- The v2 context strings `krypto/store/v2|key-check` and `krypto/store/v2|container-mac`
  are frozen from the first v2 file written.

## 4. Reading a store (`open`)

Checks run in this order:

1. If there is no file at the path, a store is created and the checks below do not
   apply; the one exception is an anchored open with an anchor above 0, which fails with
   `Io` (section 7). Otherwise the path opens, or the answer is `Io`, and is a regular
   file, or the answer is `Format` (FIFOs and other special files do not block).
2. The file size is within `MAX_STORE_BYTES`, otherwise `Format`.
3. Magic: not `FST1` → `Format`.
4. Version: 1 → the version 1 rules; 2 → the version 2 rules; anything else → `Format`
   with `unsupported store version N`. A version other than the one the open names →
   `Format` (section 4.1).
5. Version 2 only, before anything else in the file is interpreted, in this order:
   - the file holds the whole 109-byte header, otherwise `Auth`;
   - `key_check` matches, otherwise `WrongKey`: the master key does not fit this file;
   - `container_mac` matches over `header[0..77]` followed by every byte after the
     header, otherwise `Auth`: the key fits, and the file is not what was written.
6. Structure: all length arithmetic is checked (no panics on any input); invalid UTF-8
   or illegal entry names → `Format`; duplicate names → `Format`.

Error classes:

| Class | Meaning |
|---|---|
| `Format` | the input is not a store file, has an unknown version, or is of another version than the one the open names; or its structure is invalid, which in a version 2 file whose MAC holds means it was written that way |
| `WrongKey` | version 2 only: the master key does not fit the file. A changed salt or `key_check` gives the same answer and cannot be told from a wrong key, so a caller that knows its key is the right one treats `WrongKey` as a changed file |
| `Auth` | a version 2 file is not what was written, whatever the cause: it is cut short of its header, or the master key fits and something else in the file was changed, added or removed |
| `Rollback` | version 2 only, and only in an anchored open: the file's `counter` is below the anchor |
| `Io` | the file cannot be opened, read or written; or an anchored open with an anchor above 0 found no file (section 7) |

### 4.1 Choosing the version

`open` reads both versions and says which one it read (`version()`). An open that names
a version accepts only a file of that version, and creates one of that version if there
is none; a file of another version is refused with `Format`, and the error says which
version the file is. An anchored open (section 7) names version 2 by its nature.

`open` cannot tell a version 1 file from a version 2 file that has been made into one:
it reads it as version 1, with what version 1 protects and no more. A caller that
relies on what version 2 adds names version 2.

## 5. Writing a store

- A store file is always written atomically: a temporary file created with
  `create_new`, mode `0600` from its first byte, unpredictable name; fsync; rename;
  directory fsync.
- The written version equals the opened file's version (sticky versioning); upgrade
  (section 6) is the one operation that changes it. A store created new is version 2
  unless the caller names version 1.
- After the rename, memory follows the file: a failed directory sync after the rename
  is reported as an I/O error and is not rolled back.
- One handle per file: `open` takes an exclusive `flock` on `.<name>.lock` beside the
  store for the handle's lifetime. A symlink at the lock name is never followed; a
  non-regular file there is rejected.

## 6. Upgrade and rotation

- **Upgrade** (`v1 → v2`) is explicit and chosen by the caller, and is one-way. All
  entries are decrypted and verified first; any `Auth` aborts with the file untouched.
  The file is then written as version 2 in a single atomic write, with `counter` at 0:
  it is the first version 2 state of the store. Because salt, `key_id`, and the entry
  key context are unchanged, the entry blobs are written to the new file as they are,
  without being encrypted again. After an upgrade, a krypto that accepts only version 1
  can no longer read the file; it reports `unsupported store version 2`.
- **Rotation** (`rotate(new_master)`) decrypts every entry with the old master first
  (any `Auth` aborts, file untouched), then writes a new file with a fresh salt, a
  fresh `key_id`, all entries re-sealed under the new master, `counter` reset to 0, in
  one atomic rename. The file's version is preserved. The new master may be the same
  key as the old one.

## 7. Rollback detection (optional, caller-anchored)

krypto keeps no state of its own: nothing about a store's contents or history is
recorded outside its file. The version 2 `counter` is covered by `container_mac`, so it
cannot be lowered without breaking the MAC; an older valid copy of the whole file put
back is detected by comparing the file's `counter` with the caller's anchor. krypto
gives out `version()` and `counter()` for this, and an anchored open that takes the
anchor and fails with `Rollback` when the file's counter is lower. The counter is
compared only after the file has passed the checks in section 4, so a counter that
cannot be trusted is never compared. Without an anchor no such comparison is made; for
version 2, `key_check` and `container_mac` are always verified.

Keeping an anchor is the caller's choice. A caller that keeps none trusts that the file
is not replaced by an earlier copy. A rotation starts a new generation with `counter`
at 0, and upgrade starts version 2 at 0; a caller that keeps an anchor starts it again
from there. krypto does what it is told and keeps no record of its own.

A missing file is not a rollback, and there are two cases. A file that has not been
created yet: without an anchor, or with an anchor of 0, it is created as an empty store.
A file that should be there and is not: an anchored open with an anchor above 0 does not
create a store; it fails with `Io`, a file error, and the error says that the store
file is missing.

### 7.1 What a caller can rely on

A caller that names version 2, keeps the store's `key_id` and `counter` outside the file
after each write, and compares them with the file when it opens it, knows that the file
is a state of that store that it wrote itself, and no older than the counter it kept.

What is inside the file is protected in both versions, and does not depend on those
three: each value is sealed under a key derived from the master key, the store's salt
and the entry's name. Without the master key no value can be read, made, or moved to
another name.

## 8. Compatibility summary

| File version | Read by krypto 0.9.0 and later | Written by krypto 0.9.0 and later | Read by krypto before 0.9.0 |
|---|---|---|---|
| 1 | yes (no MAC, no key check), unless the open names version 2 | when the file is already version 1, or version 1 is named for a new store | yes |
| 2 | yes (`key_check` and `container_mac` verified), unless the open names version 1 | by default for a new store; after an explicit upgrade | no — `Format`, `unsupported store version 2` |

## 9. References

Inside krypto:

- The FAFN blob that holds each entry. It is krypto's own format and has no spec file
  of its own yet; until it has one, it is described in `docs/API.md`, "The blob format".

Outside krypto:

- RFC 5869 — HKDF
- RFC 2104 — HMAC
- FIPS 180-4 — SHA-256
- draft-irtf-cfrg-aegis-aead — AEGIS-256, the algorithm the entry blobs are sealed with

## 10. Revision history

| Spec version | Date | What changed |
|---|---|---|
| 1.0 | 2026-11-16 | First version: file format versions 1 and 2 |
| 2.0 | 2026-11-17 | The order of the checks at open and the answer each gives, with the key check and the MAC before the structure and a separate answer for a master key that does not fit; an open that names a version; a missing file as a file error; a counter that never wraps; what `key_id` is and that it can be read; what a caller can rely on; References |
