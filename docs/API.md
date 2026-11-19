# API — reference (v0.9.0)

**The version is a floor: v0.9.0 is the LOWEST krypto this contract describes.** Every krypto from
0.9.0 onwards has what is written here. The number is raised only when the public surface itself
changes — to the crate version at that moment. Each part also carries the version it applies from,
as *(x.y.z)*, so a part can be added, changed or phased out on its own timeline.

Every public type and function in `krypto`.

This is a **reference**. To get started, or to understand why things are done the way they are,
read **[How to use krypto](Usage.md)** first. What the crate is and is not lives in
**[Home](Home.md)**.

Everything that can fail returns `Result<_, Error>`. The crate does not panic on input.

**This document is the contract** for the surface: every public type and function, and what each
answers in every case. It ships with the module. Why krypto is built as it is, what it protects
against, and its stored formats are in the [specification](../spec/README.md). Two normative rules
bind whoever *changes* the surface:

- **Verify input and output.** Input is validated (type, range, character set and length —
  fail-closed; unknown values are rejected, not ignored), and output never carries secrets or
  unexpected structure. *(0.9.0)* Every input has an upper bound, stated in this document, with
  these exceptions: `sha256` and `ct_eq`, which cannot fail and reserve no memory; paths, which
  the operating system bounds (a path it refuses gives `Io`); and `random_bytes_with_limit` and
  `SecretBuf::random_with_limit`, whose limit is the caller's own. An uncovered case → update
  this document.
- **The feedback contract.** What the crate answers — success, errors and status — lives HERE: the
  library through `Result` and [`Error`](#error--error) (the crate never logs — logging belongs to
  the consumer), *(0.8.0)* Python through the same values and one exception per `Error` variant. No
  error path carries key material or plaintext. An answer not written here is a gap in the contract
  and should be reported — not interpreted.

---

## Root

```rust
pub const VERSION: &str;  // new in 0.6.0 — the crate version (mirrors Cargo.toml), for About pages

pub use secret::{SecretBuf, SecretString};
pub use kdf::{MasterKey, DerivedKey, hmac_sha256, MAX_MASTER_KEY_BYTES, MAX_DERIVE_INPUT_BYTES};
pub use aead::{seal, open, reseal, blob_key_id, Alg, seal_with_aad, open_with_aad, reseal_with_aad, MAX_AAD_BYTES};  // reseal: 0.6.0; seal_with_aad, open_with_aad, reseal_with_aad and MAX_AAD_BYTES: 0.9.0
pub use store::{SecretStore, MAX_STORE_BYTES};
pub use error::Error;
pub use harden::{close_inherited_fds, drop_filesystem, harden_process, no_new_privs};
pub use util::{ct_eq, random_bytes, random_bytes_with_limit, sha256, MAX_DATA_BYTES, MAX_RANDOM_BYTES};  // random_bytes_with_limit and MAX_RANDOM_BYTES: 0.7.3; MAX_DATA_BYTES: 0.9.0

pub mod error;
pub mod exchange;
pub mod harden;
pub mod hex;
pub mod base64;   // 0.5.1
pub mod password;
pub mod sign;
```

That is the entire root surface. If something is listed here and not exported, this document is
wrong.

The size caps: `MAX_MASTER_KEY_BYTES` (4 KiB) and `MAX_STORE_BYTES` (16 MiB) *(0.5.0)*;
`MAX_DERIVE_INPUT_BYTES` (1 KiB) *(0.7.0)* for the `info` and `salt` of `derive`, and *(0.8.2)* for
the salt of `password::derive_key`; `MAX_RANDOM_BYTES` (1 MiB) *(0.7.3)* for `random_bytes` and
`SecretBuf::random`; `MAX_AAD_BYTES` (1 KiB) *(0.9.0)* for the AAD functions. *(0.9.0)*
`MAX_DATA_BYTES` (64 MiB) for every amount of data: the plaintext of `seal`, a blob
(`MAX_DATA_BYTES` + 86 bytes, its header and longest tag), the data of `hmac_sha256`, a message to
sign or verify, the bytes `hex` and `base64` encode or decode to, and the content of
`SecretBuf::from_vec` and `SecretString::from_string`. *(0.9.0)* `password::MAX_PASSWORD_BYTES`
(1 KiB) and `password::MAX_PHC_BYTES` (512 bytes), and `sign::MAX_ECDSA_P256_PUBLIC_BYTES` (65),
`sign::MAX_ECDSA_P256_SIG_BYTES` (72) and `sign::MAX_ECDSA_P256_PKCS8_BYTES` (512). Store names
have their own rules (below). An input over its cap is `Format`. ⚠ *(0.9.0)* That holds also for
what was accepted before: a blob over the limit that an older krypto sealed does not open, and a
password over 1024 bytes is not hashed, verified or used to derive a key.

---

## The secret types

The foundation. Anything secret crosses a boundary as one of these. It comes in as a `Vec<u8>` or
`String` only through `from_vec` and `from_string`, which zeroize the source, and otherwise never
as `String`, `&str` or `Vec<u8>`.

### `SecretBuf`

Owned byte buffer in locked memory. Zeroized when dropped.

*(0.7.2)* Each buffer has whole memory pages of its own, shared with nothing else: they are locked
in RAM and, on Linux, excluded from core dumps, with an inaccessible guard page on each side. A
non-empty buffer therefore counts at least one page (usually 4 KiB) against `RLIMIT_MEMLOCK`,
however short it is; an empty one counts none. If the pages cannot be mapped, locked or excluded
from dumps, construction fails with `Error::Hardening`. Plaintexts from `open` and
`SecretStore::get`, and keys such as `MasterKey` and `DerivedKey`, hold a buffer too and count
while they live. The limit is set outside krypto, and its default differs between systems: at
64 KiB, a common default, and with 4 KiB pages, about 16 non-empty buffers of up to one page each
can be alive at once. When it is reached, locking fails, and so does construction, with
`Error::Hardening`. Raise it outside krypto, with `ulimit -l` or in the service manager; on Linux,
a process with `CAP_IPC_LOCK` is not limited by it. Outside Linux the pages are locked, fenced and
wiped, but not excluded from core dumps, and no error says so.

Derived keys, the key of `password::derive_key` and the bytes of `SecretBuf::random` are written
straight into locked memory. Four secrets are made in an ordinary buffer first, copied into locked
memory, and the buffer is wiped: the plaintext of `open` (and of `SecretStore::get`), the shared
secret of `x25519_shared`, the private key of `ecdsa_p256_keypair`, and the key
`MasterKey::from_secret_file` reads. [SPEC-memory](../spec/SPEC-memory.md) says where a secret is
at each step, and what the protection does not reach.

```rust
impl SecretBuf {
    pub fn from_vec(v: Vec<u8>) -> Result<Self, Error>;   // copies in, zeroizes the source; at most MAX_DATA_BYTES (0.9.0)
    pub fn random(len: usize) -> Result<Self, Error>;     // from the OS CSPRNG, at most MAX_RANDOM_BYTES (0.7.3)
    pub fn random_with_limit(len: usize, limit: usize) -> Result<Self, Error>; // your own cap (0.7.3)
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn expose<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R;
}
```

`expose` is the **only** path to the plaintext, and the reference cannot escape the closure.

*(0.9.0)* `from_vec` takes at most `MAX_DATA_BYTES` (64 MiB); more is `Format`, refused before any
memory is locked, and the source is zeroized on that path too. `from_string` has the same limit,
counted in bytes.

### `SecretString`

Like `SecretBuf`, but guaranteed valid UTF-8.

```rust
impl SecretString {
    pub fn from_string(s: String) -> Result<Self, Error>;   // zeroizes the source; at most MAX_DATA_BYTES bytes (0.9.0)
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn expose_str<R>(&self, f: impl FnOnce(&str) -> R) -> R;
}
```

### What they do *not* have

The absences are part of the contract:

| | `SecretBuf` | `SecretString` |
|---|---|---|
| `Clone` | ❌ | ❌ |
| `Serialize` | ❌ | ❌ |
| `PartialEq` | ❌ | ❌ |
| `Default` | ❌ | ❌ |
| `Debug` / `Display` | ✅ — always `SecretBuf([REDACTED], len=N)` | ✅ — always `SecretString([REDACTED], len=N)` |
| `Drop` | ✅ | *(through the inner buffer)* |

The length is the one thing the printed form shows, so a secret printed by mistake, such as a
password, gives away how long it is.

### What is left on the stack *(0.8.2)*

The libraries krypto uses for encryption, HMAC, HKDF and Argon2 leave copies of the key, and of
their own state, in the stack memory they used. After `seal`, `open` and `reseal` (and their
`_with_aad` variants), `MasterKey::derive` and `key_id`, `hmac_sha256`, and `password::hash`,
`verify` and `derive_key`, krypto overwrites that stack with zeros.

Where a library has a `zeroize` feature, krypto turns it on, so its types wipe what they hold when
they are dropped: AES-256-GCM, XChaCha20-Poly1305 (except the Poly1305 state it makes for each
message), HMAC and SHA-256. AEGIS-256 and HKDF have no such feature: for AEGIS-256 only the
overwrite removes its copy of the key, and HKDF's state is an HMAC over SHA-256, which is wiped.
Argon2 wipes only its initial and final hash. Its working memory, 64 to 320 MiB per call, is
ordinary memory: not locked and not excluded from core dumps. `password::derive_key` *(0.9.0)*
holds that memory itself and overwrites it with zeros before releasing it. In `password::hash` and
`verify` the Argon2 library holds it and releases it without wiping, and what is released unwiped
can be read from the machine's memory until it is reused.

This is a measure, not a guarantee. What is left on the stack depends on the compiler, the build
and the platform, and how much is overwritten was set from measurements on x86-64 Linux. Signing
and key exchange are not covered by the overwrite.

---

## Keys

### `MasterKey`

The root key. Comes from outside — the crate does not create it. It must be unpredictable: krypto
takes any 32 to 4096 bytes and cannot tell a random key from a passphrase in a file. With a key
that can be guessed, every blob under it and its `key_id` are a check for a guess; a key from a
password goes through `password::derive_key` first.

```rust
pub const MAX_MASTER_KEY_BYTES: usize = 4096;
pub const MAX_DERIVE_INPUT_BYTES: usize = 1024;   // 0.7.0

impl MasterKey {
    pub fn from_secret_file(path: impl AsRef<Path>) -> Result<Self, Error>;
    pub fn from_bytes(key: SecretBuf) -> Result<Self, Error>;   // consumes the buffer
    pub fn derive(&self, info: &[u8], salt: &[u8]) -> Result<DerivedKey, Error>; // empty info: Format (0.7.3)
    pub fn key_id(&self) -> Result<[u8; 16], Error>;   // 0.8.0
}
```

`derive` is HKDF-SHA256. `info` is your own context string — the crate does not know your purpose
names. Different `info` gives different keys, and that is how you keep purposes apart. **An
empty `info` is rejected** — it IS the purpose separation — with `Format` *(0.7.3)*. An empty
`salt` is allowed, as RFC 5869 permits. Both `info` and `salt` are capped *(0.7.0)* at
`MAX_DERIVE_INPUT_BYTES` (1024), and a longer one is `Format`; they reach the API from command
lines and config files, and the longest real one is the store's prefix plus a key name — 16 + 512
bytes. The checks run in this order: an empty `info`, the length of `info`, the length of `salt`.

Contexts that begin with `krypto/` are krypto's own: `krypto/key-id/v1` for `key_id`, and
`krypto/store/v1|` and `krypto/store/v2|…` for the keys of a `SecretStore`. `derive` does not
refuse them, so begin your own otherwise. A store's salt is public, so a caller that lets a sender
of input choose a context or a salt can be made to derive a store's entry keys or the key of its
MAC. Nor does krypto stop one working key from being used with every cipher and with
`hmac_sha256`: keeping uses apart is done with contexts, and is yours.

The key must be 32..=`MAX_MASTER_KEY_BYTES` (4096) bytes, on **both** ways in *(0.7.0)*; a shorter
or longer one is `Format`. File reads are bounded (never OOM). The file's bytes are the key as they
are, a line break at the end included. `from_secret_file` opens the path in blocking mode, so a
named pipe there makes it wait until something opens the pipe for writing.
`from_bytes` **consumes** the buffer (the key cannot be read back out) and is the path for a
key that must never touch disk.

*(0.8.0)* `key_id` is the master key's key id: which key generation a blob was sealed under, safe to
publish. HMAC-SHA256 over `key-id`, keyed with the key `derive` gives for the context
`krypto/key-id/v1` and an empty salt; the first 16 bytes. It is frozen, because blobs carry it.
It depends on the master key alone, so it is the same wherever that key is used, and shows that
blobs carrying it belong to one master key, also across installations.

### `DerivedKey`

A working key of 32 bytes. Opaque — no public methods. Used by `seal`, `open`, `reseal`, their
`_with_aad` variants and `hmac_sha256`.

### `hmac_sha256`

```rust
pub fn hmac_sha256(key: &DerivedKey, data: &[u8]) -> Result<[u8; 32], Error>;
```

*(0.9.0)* `data` is at most `MAX_DATA_BYTES` (64 MiB); more is `Format`, refused before the key is
used.

---

## Encryption

```rust
pub enum Alg { Aegis256, XChaCha20Poly1305, Aes256Gcm }   // #[non_exhaustive]
pub const MAX_AAD_BYTES: usize = 1024;                    // 0.9.0

pub fn seal(key: &DerivedKey, key_id: &[u8; 16], plaintext: &SecretBuf, alg: Alg)
    -> Result<Vec<u8>, Error>;
pub fn open(key: &DerivedKey, blob: &[u8]) -> Result<SecretBuf, Error>;   // any change past FAFN: Auth (0.7.3); header cut short: Auth (0.9.0)
pub fn blob_key_id(blob: &[u8]) -> Result<[u8; 16], Error>;   // unknown version or alg: Auth (0.7.3); header cut short: Auth (0.9.0)
pub fn reseal(old: &DerivedKey, new: &DerivedKey, new_key_id: &[u8; 16], blob: &[u8])
    -> Result<Vec<u8>, Error>;   // 0.6.0 — key rotation; reads the header as open (0.7.3)
pub fn seal_with_aad(key: &DerivedKey, key_id: &[u8; 16], plaintext: &SecretBuf, alg: Alg, aad: &[u8])
    -> Result<Vec<u8>, Error>;   // 0.9.0 — caller AAD appended after the 54-byte header; aad over MAX_AAD_BYTES (1024): Format
pub fn open_with_aad(key: &DerivedKey, blob: &[u8], aad: &[u8])
    -> Result<SecretBuf, Error>;   // 0.9.0 — wrong or missing aad: Auth; aad over MAX_AAD_BYTES (1024): Format
pub fn reseal_with_aad(old: &DerivedKey, new: &DerivedKey, new_key_id: &[u8; 16], blob: &[u8],
    old_aad: &[u8], new_aad: &[u8]) -> Result<Vec<u8>, Error>;   // 0.9.0 — rotation with AAD; either aad over MAX_AAD_BYTES (1024): Format
```

There is no default: every seal names its algorithm, so the choice stands in your code and in the
blob. `Alg::Aegis256` is the first choice. The other two exist for compatibility with systems that
require them.

`blob_key_id` reads which key a blob was made with — **without opening it**. Useful when you hold
several keys and must find the right one first. Note that the value is a *hint about where to
look*, not proof: tampering is discovered when `open` is called, as `Error::Auth`. *(0.7.3)*
`blob_key_id` reads the header as `open` does: a version or algorithm krypto does not know is
`Auth` already there, and data that is not a krypto blob is `Format`. *(0.9.0)* A blob that starts
with `FAFN` but is cut short of the 54-byte header is `Auth` there too.

`reseal` *(0.6.0)* is the rotation **action**: open with the old key, seal with the new one
under a new generation id — the blob's algorithm is preserved. Both keys come from you (krypto
is stateless and never owns keys); a wrong old key or tampering gives `Auth`, and nothing is
produced.

`seal_with_aad`, `open_with_aad` and `reseal_with_aad` *(0.9.0)* add **caller-supplied associated
data**: the AEAD's AAD is the 54-byte header followed by `aad` — the header has a fixed length,
so the concatenation is unambiguous, and an empty `aad` is exactly the AAD `seal`/`open` use.
The blob format is unchanged and every existing blob opens as before. The `aad` is **not stored
in the blob**: supply the same value at open, and a missing or different one fails with `Auth`
like any other tampering. Use it to bind a blob to a context the plaintext should not carry — a
record id, a channel, a timestamp. `reseal_with_aad` takes the old AAD (to open) and the new AAD
(to seal under); the algorithm is preserved as in `reseal`.

*(0.9.0)* Each AAD is at most `MAX_AAD_BYTES` (1024) bytes; a longer one is `Format`, refused
before a nonce is drawn, the blob is read or a key is used. The AAD is public data to krypto: it is
held in ordinary memory, not locked and not wiped, so nothing secret belongs in it. The blob does
not record whether an AAD was used, so a blob sealed with an AAD and opened without it, by `open`
or by a krypto older than 0.9.0, fails with `Auth`. AAD binds one blob to a context you give at
each call, under one key; `derive(info, …)` gives a key per context, as `SecretStore` does per
name.

krypto promises no binding of a blob to one key: with AES-256-GCM and XChaCha20-Poly1305, someone
who knows two keys can make one blob that opens under both. A caller that opens blobs from others
under a key derived from a password, and shows whether that worked, takes this into account.

*(0.9.0)* **The size of the plaintext and the blob.** The plaintext of `seal` and `seal_with_aad`
is at most `MAX_DATA_BYTES` (64 MiB); more is `Format`, refused before a nonce is drawn or the key
is used (after the AAD check in `seal_with_aad`). The blob given to `open`, `open_with_aad`,
`reseal`, `reseal_with_aad` and `blob_key_id` is at most `MAX_DATA_BYTES` + 86 bytes — the 54-byte
header and the longest tag, AEGIS-256's 32 bytes — so every blob `seal` makes opens. A longer blob
is `Format`, refused before its magic is looked at (after the AAD checks in the `_with_aad`
functions). A blob within that limit can still hold a plaintext up to 16 bytes longer than
`MAX_DATA_BYTES`, with a 16-byte tag; `seal` never makes one, and `open` refuses it with `Format`
after it has been authenticated, when the plaintext is placed in locked memory.

Sealing and opening also need ordinary memory of about the size of the data, in the cipher
implementations. If the system cannot give it, the process is ended, not answered with an error,
so how many large operations run at once is yours to limit.

> **Tampering gives `Auth`, never wrong plaintext.** The whole blob header is part of the
> authentication, so changing the algorithm id, key id or version makes the open fail with `Auth`
> — *(0.7.3)* a version or algorithm krypto does not know included. Only data that is not a krypto
> blob at all gives `Format`. *(0.9.0)* That is data shorter than its 4-byte magic, or not starting
> with `FAFN`; a blob starting with `FAFN` but cut short of the 54-byte header is a changed blob
> and gives `Auth` too, so the alarm class is not the tamperer's choice. The one exception is
> size: data longer than the blob limit above gives `Format`, whatever it starts with. Never wrong
> plaintext is an absolute guarantee, not a detail.

### The blob format (`FAFN`, format_ver 1)

The format is specified in [SPEC-blob](../spec/SPEC-blob.md), exact enough to make and read a blob
without krypto. In brief:

```text
magic "FAFN" (4) | format_ver (1) | alg_id (1) | key_id (16) | nonce (32) | ciphertext | tag
```

- `alg_id`: 1 = AEGIS-256 (256-bit tag) · 2 = XChaCha20-Poly1305 · 3 = AES-256-GCM.
- **The AAD contract (absolute):** the whole header up to and including the nonce (**54 bytes**)
  is associated data — the "key-id swap test": a changed header never yields a mis-decrypt.
  *(0.9.0)* `seal_with_aad` appends caller-supplied AAD after that fixed-length header; an empty
  caller AAD is identical to before, so the format does not change.
  *(0.7.3)* A changed version, alg_id, key_id or nonce, or a body cut short, yields `Auth` when
  the blob is opened, in `open` and `reseal` (and, from 0.9.0, their `_with_aad` variants).
  `blob_key_id` authenticates nothing: a version or alg_id krypto does not know yields `Auth`
  there too; a changed key_id or nonce, an alg_id changed to another one krypto knows, or a body
  cut short does not. *(0.9.0)* A blob longer than `MAX_DATA_BYTES` + 86 bytes yields `Format`
  first. Then the magic is checked before the length: data shorter
  than the 4-byte magic, or not starting with `FAFN`, yields `Format`; a blob that starts with
  `FAFN` but is cut short of the 54-byte header yields `Auth`, in `blob_key_id` too.
- The nonce is random per blob from the OS CSPRNG. The 32-byte field is used partially:
  AEGIS-256 all 32, XChaCha 24, AES-GCM 12 — the rest zero when krypto seals. Those unused bytes
  are authenticated with the header and not otherwise checked: a blob with other bytes there opens
  if its tag holds.
- A format version or `alg_id` krypto does not know is `Auth`, so a blob of a newer format reads
  as a changed blob to an older krypto: readers are updated before writers.
- *(0.7.2)* **AES-256-GCM: at most 2³² blobs per key.** With a 12-byte random nonce, NIST SP 800-38D
  (§8.3) allows one key at most 2³² encryptions. Beyond that a repeated nonce becomes too likely, and
  one lets an attacker read the XOR of two plaintexts and forge blobs. krypto keeps no count — the
  caller knows its volume. AEGIS-256 (32-byte nonce) and XChaCha (24-byte) have no limit that matters
  in practice.
- **Verified against official vectors** (0.5.0): AEGIS-256 against RFC 10032 (Appendix A.3),
  XChaCha against draft-arciszewski A.1, AES-256-GCM against NIST CAVS.

---

## `SecretStore` — encrypted store on file

```rust
pub const MAX_STORE_BYTES: usize = 16 * 1024 * 1024;
pub struct SecretStore<'a>;   // borrows &MasterKey for its lifetime

impl<'a> SecretStore<'a> {
    pub fn open(path: impl AsRef<Path>, master: &'a MasterKey) -> Result<Self, Error>;   // reads v1 and v2; a new store is v2 (0.9.0)
    pub fn open_with_version(path: impl AsRef<Path>, master: &'a MasterKey, version: u8) -> Result<Self, Error>;   // 0.9.0: only that version
    pub fn open_with_min_counter(path: impl AsRef<Path>, master: &'a MasterKey, min_counter: u64) -> Result<Self, Error>;   // 0.9.0: v2 only
    pub fn put(&mut self, name: &str, secret: &SecretBuf) -> Result<(), Error>;
    pub fn get(&self, name: &str) -> Result<SecretBuf, Error>;   // Auth if the key id does not match the store's (0.7.3); a name that breaks the rules: Format (0.9.0)
    pub fn delete(&mut self, name: &str) -> Result<(), Error>;   // a name that breaks the rules: Format (0.9.0)
    pub fn contains(&self, name: &str) -> bool;   // a name that breaks the rules: false (0.9.0)
    pub fn list(&self, prefix: &str) -> Vec<String>;   // a prefix no name can start with: empty (0.9.0)
    pub fn version(&self) -> u8;    // 0.9.0: the file's format version, 1 or 2
    pub fn counter(&self) -> u64;   // 0.9.0: the write counter, 0 on a v1 store
    pub fn key_id(&self) -> [u8; 16];   // 0.9.0: the store's key_id, not secret
    pub fn key_id_from_file(path: impl AsRef<Path>) -> Result<[u8; 16], Error>;   // 0.9.0: without the master key; not authenticated
    pub fn upgrade(self) -> Result<SecretStore<'a>, Error>;   // 0.9.0: v1 → v2, one-way
    pub fn rotate(self, new_master: &MasterKey) -> Result<SecretStore<'_>, Error>;  // 0.6.0
}
```

Each entry gets its own key derived from its name (`info = "krypto/store/v1|" + name`). A blob
therefore cannot be moved to another name — the open fails. Writes are atomic (tmp + fsync +
rename), and the file is private (0600). *(0.7.2)* The tmp file is new, with an unpredictable name,
so nothing planted at that name is followed or reused, and the directory is synced after the
rename. A crash after the tmp file is written and before the rename, or a failed rename whose tmp
file cannot be removed, leaves that tmp file (`.tmp-…` beside the store): a complete store file
with the next counter. The next write
uses that counter again, so two different states of a v2 store can carry one counter, and whoever
can write in the directory can put the leftover file in place past an anchor at that counter.
*(0.7.2)* An existing file with any other mode gets 0600 when opened. If the process may
not change it — it does not own the file, or *(0.8.2)* the file system is read-only — the file is
left as it is and `open` goes on. *(0.8.2)* The mode is changed only once `open` has read the file
as a store, so a file that is not a store keeps its mode.
*(0.8.2)* If what is at the store path can be opened but is not a regular file, such as a FIFO, a
device or a directory, `open` fails with `Format`; what cannot be opened, for example for lack of
permission or because it is a socket, gives the `Error::Io` from opening it. A FIFO at the store
path does not make `open` wait. A symbolic link at the store path is followed, so a link to a store
file is read through; the first write replaces the link with a regular file, and the file the link
pointed to keeps its old contents.
File reads are capped at `MAX_STORE_BYTES` (16 MiB), and *(0.7.2)* so are writes: a `put` that would
grow the file past it fails with `Format`, so the store always opens again. The cap counts the
whole file, header included — 37 bytes in v1, 109 in v2 — and *(0.9.0)* `put` checks it on the
prospective file size before the value is sealed.
Name rules: non-empty, ≤ 512 bytes, printable ASCII only (`[\x20-\x7e]`) — names are
addresses, not secrets, and get listed out. Checked on read as well as on write
*(0.7.0)*: a store file need not have come from `put`.

`put` checks in this order: the name, then the size cap — both `Format` — then it seals the value,
and last the counter (below). *(0.9.0)* The name rules hold at lookup too, checked first: `get`
and `delete` give `Format` for a name that breaks them, and `delete` then writes nothing;
`contains` gives `false`; and `list` gives an empty list for a prefix longer than 512 bytes or with
a character outside printable ASCII, since no name can start with it. A legal name that is not in
the store is `KeyNotFound` from `get`. An entry whose blob is not a krypto blob gives `Format` from
`get`, and stops `rotate` and `upgrade` with the same error. `delete` of a legal name that is not
in the store returns `Ok`, writes nothing and leaves the counter where it was. `list` gives the
names sorted, and an empty prefix lists them all.

*(0.9.0)* **The store file: format versions 1 and 2.** The normative description is
[`spec/SPEC-secretstore.md`](../spec/SPEC-secretstore.md); what follows is the contract in brief.
The 4 bytes at offset 0 are the magic `FST1` in every version, and the byte at offset 4 is the
format version. An entry is `name_len (u16 LE) | name | blob_len (u32 LE) | blob`, where `blob` is
a FAFN blob — identical in both versions, as are the per-name key context `krypto/store/v1|` +
name and the blob's AAD: its 54-byte header, which carries the store's `key_id`. krypto seals each
blob with `Alg::Aegis256` under the entry's key (derived with the store's salt), and writes the
entries sorted by name.

| Offset | Size | Version 1 (frozen) | Version 2 *(0.9.0)* |
|---|---|---|---|
| 0 | 4 | magic `FST1` | magic `FST1` |
| 4 | 1 | version = 1 | version = 2 |
| 5 | 16 | salt | salt |
| 21 | 16 | key_id | key_id |
| 37 | 32 | — | `key_check` = HMAC-SHA256(K_check, `"FST1" \|\| ver \|\| salt`) |
| 69 | 8 | — | `counter`, u64 LE: starts at 0, +1 on every write, reset to 0 on `rotate` |
| 77 | 32 | — | `container_mac` = HMAC-SHA256(K_mac, `header[0..77] \|\| entries`) |
| 37 / 109 | … | entries | entries |

`K_check` = HKDF-SHA256(master, salt, info = `krypto/store/v2|key-check`) and `K_mac` =
HKDF-SHA256(master, salt, info = `krypto/store/v2|container-mac`); both context strings are
frozen. MACs are compared in constant time. The v2 header is 109 bytes.

*(0.9.0)* **What `open` verifies.** If there is no file at the path, a new store is created and
the checks below do not apply, except that an open anchored above counter 0 fails with `Io`
(below). The lock is taken before the file is looked at (below; a failure there is `Io`).
Otherwise the checks run in this order: the path opens, else `Io`, and is a regular file,
else `Format`; the size is within `MAX_STORE_BYTES` (the whole file, header included, on read and
on write), else `Format`; the file holds the magic `FST1` and the version byte, else `Format`; the
version byte is 1 or 2, anything else is `Format` with `unsupported store version N`, and a
version other than the one the open names is `Format` too, with the version the file is. A v1
file shorter than its 37-byte header is `Format`. On a **v2** file three checks then run,
before anything else in the file is interpreted: the file holds the whole 109-byte header, else
`Auth`; `key_check` matches, else `WrongKey` — the master key does not fit the file;
`container_mac` matches over `header[0..77]` followed by every byte after the header, else `Auth`
— the key fits, and the file is not what was written. Last, the structure parses — checked length
arithmetic, no panic on any input, valid UTF-8, legal names, no duplicate names, else `Format`; in
a v2 file whose MAC holds, an invalid structure was written that way. So on a v2 file `open` itself
proves the master key and the file as a whole: a wrong key fails at `open` with `WrongKey`, and a
file cut short after its version byte, or a removed, swapped or injected entry, with `Auth`. A
changed salt or `key_check` gives `WrongKey` too and cannot be told from a wrong key, so a caller
that knows its key is the right one treats `WrongKey` as a changed file. On a **v1** file nothing extra is verified: `open`
still does not check the master key, and a wrong key shows as `Auth` from `get`.

*(0.9.0)* **Sticky versioning; new stores are v2.** A store is always written in the version it was
loaded in: every `put`, `delete` and `rotate` writes that same version, and `upgrade` is the one
operation that changes it. A store created new by `open` is **version 2** by default. Version 1
files remain readable and, once opened as v1, stay v1 until upgraded. A v2 file read by a pre-0.9.0
krypto is `Format` (`unsupported store version 2`). `open` reads both versions and says which one it
read (`version()`). An open that names a version accepts only a file of that version, and creates
one of that version when there is none: `open_with_version(path, master, version)` names 1 or 2 —
anything else is `Format`, before the path is looked at or the lock is taken — and
`open_with_min_counter` names 2. A file of another version is
refused with `Format`, and the error says which version the file is. `open` cannot tell a v1 file
from a v2 file that has been made into one: it reads it as v1, with what v1 protects and no more. A
caller that relies on what v2 adds names version 2.

*(0.9.0)* **`upgrade`: v1 → v2, one-way.** `upgrade(self)` consumes the handle and turns a
version 1 store into a version 2 one. All entries are decrypted and verified FIRST — any `Auth`
aborts with the file untouched and the error. The file is then written as version 2 in a single
atomic write. Salt, `key_id` and the per-name key context are unchanged, so the existing blobs
are re-wrapped, not re-encrypted. There is no way back: after an upgrade, binaries that accept
only version 1 report `unsupported store version 2`. On a store already at version 2 there is
nothing to upgrade: `upgrade` returns `Ok` with the store as it was and writes nothing. The v2
header is 72 bytes longer than the v1 header, so a v1 file within 72 bytes of `MAX_STORE_BYTES`
does not fit as v2: `upgrade` fails with `Format` and the file is untouched.

*(0.9.0)* **Rollback detection, anchored by the caller.** krypto is stateless — it stores nothing
outside the store file, so the anchor is yours. The v2 `counter` is covered by `container_mac`,
so it cannot be lowered without breaking the MAC; what remains is putting back an older,
still-valid copy of the whole file, and that is what the counter detects:
`open_with_min_counter(path, master, min_counter)` names version 2, so a v1 file is `Format` for
every `min_counter`, 0 included. It loads the store as `open` does and then fails with
`Error::Rollback { file_counter, min_counter }` when the file's `counter` is below `min_counter`.
The counter is compared only after the file has passed the checks above, so a counter that cannot
be trusted is never compared. Without an anchor, no freshness check is performed — on a v2 file,
`key_check` and `container_mac` are verified either way. A missing file is not a rollback: with
`min_counter` above 0 the open creates no store and fails with `Error::Io`, saying that the store
file is missing; the file is looked for before the lock is taken, so no lock file is made either,
unless the file is removed while the open runs. With 0 it creates an empty v2 store, as `open`
does.

*(0.9.0)* `version()`, `counter()` and `key_id()` are there for an anchor of your own: after each write,
keep the store's `key_id` and `counter` outside the file; when you open it, pass that counter as
`min_counter` and check that `key_id()` is the one you kept. A rotation starts a new generation,
with a new `key_id` and the counter at 0, and an upgrade starts version 2 at counter 0; start your
anchor again from there. A caller that names version 2 and does this knows that the file is a
state of that store that it wrote itself, and no older than the counter it kept. The anchored open
compares only the counter, never the `key_id`: without your comparison of `key_id()`, another
store's file under the same master key opens and passes, and so does a copy from before a rotation
to the same master key.

*(0.9.0)* The counter never wraps: a v2 store whose counter is at the maximum of a u64 refuses to
write.
`put` and `delete` fail with `Error::Hardening`, the error says that the counter is at its maximum
and that the store must be rotated, and nothing is written.

*(0.9.0)* **`key_id`.** 16 random bytes that krypto draws when a store is created and again at each
`rotate`. It names the store's current generation and is not secret. `key_id()` gives it from an
open store. `SecretStore::key_id_from_file(path)` reads it from the file without the master key:
it takes no lock, creates nothing and reads no more than the header, and the value is what the
file says and is **not authenticated**. It fails with `Io` if the file cannot be opened, a missing
file included, and with `Format` if it is not a store file: not a regular file, larger than
`MAX_STORE_BYTES`, the wrong magic, an unknown version, or shorter than the header of its version.
krypto keeps no record of which master key a store is under; a caller that wants that overview
keeps it, and can use `key_id` as the store's id in it. A store file is not tied to its path:
which file belongs where is the caller's to know, and `key_id` is what tells two stores apart.

*(0.8.2)* **A write that fails.** The directory is opened before the rename, so a directory that
cannot be opened fails the write while the old file still stands. A write that fails before the
rename leaves the file as it was, and `put` and `delete` leave the handle as it was. If only the
sync of the directory after the rename fails, `put`, `delete`, `rotate`, `upgrade`, and an `open`
that creates a new store return `Error::Io` although the change is in the file, and the error says
so; `put` and `delete` keep the change in the handle too. After `rotate` the file is then under
the new master key, and after `upgrade` it is version 2.

**What the store protects.** krypto protects the contents, in both versions: without the master
key nobody can read a value, or make or change one that `get` accepts. Who may write to the file
is the caller's to decide.

A **v1** file is not authenticated as a whole: whoever can write to it can remove an entry, or put
back an older copy of an entry or of the file, and `get` then answers `KeyNotFound` or returns the
older value (a copy from before a `rotate` gives `Auth`).

*(0.9.0)* A **v2** file is authenticated as a whole: `container_mac` covers the header and every
entry, and `key_check` proves the master key — both at `open`. Removing, swapping or injecting an
entry, or changing the key id or the counter, fails with `Auth` there; changing the salt or
`key_check` fails with `WrongKey`, as a wrong master key does. Two things remain. Putting back an
older, still-valid copy of the whole file is what the `counter` and `open_with_min_counter` answer
(above). And a v2 file made into a v1 file is read by `open` as v1, and stays v1 through the
writes that follow; only an open that names version 2 refuses it (above).

Writes go by path, and only the file's own name is guarded: whoever can write in the store's
directory, or in a directory above it, can redirect a write between its steps, so those
directories are yours to keep. A reader of the file learns more than names and sizes: from two
copies, which entry changed and, on a v2 file, how many writes lie between them; and the lock file
shows that a store is there. What krypto protects, against whom, and what it leaves to you is in
the [threat model](../spec/THREAT-MODEL.md).

On a **v1** file `open` does not check the master key: it reads the file and decrypts nothing, and
neither do `contains` and `list`. A wrong master key shows as `Auth` from `get`. A `put` under a
wrong master key stores that entry under that key (and replaces an entry of the same name, as
`put` always does): each key then reads only its own entries, and `rotate` fails with `Auth` and
leaves the file untouched. *(0.9.0)* On a v2 file `key_check` makes `open` itself fail with
`WrongKey` on a wrong master key.

*(0.7.2)* **One handle per file.** A `SecretStore` reads the whole file into memory and writes the
whole file back, so two handles on one file would overwrite each other's writes, and a change made
to the file by anything else while a handle is open is overwritten by that handle's next write.
Keeping to one handle per file is the caller's responsibility. krypto also guards it on its side:
`open` takes an exclusive lock for as long as the handle lives, and a second `open` of the same
file through the same path, in this or another process, fails at once with `Error::Io`
(`WouldBlock`). You can rely on that guard, or keep to one handle in your own code as well — your
choice. The lock is the kernel's (`flock`) on an empty `.<name>.lock` beside the path given to
`open`: it goes with the handle or the process, also after a crash, so it never goes stale. The
same file opened through another name, such as a link, takes another lock. If the path has no
file name, or its file name is not valid UTF-8, the lock file is `.store.lock`, so two such stores
in one directory, or one beside a store named `store`, share one lock. If the lock file is replaced
or removed each time right after `open` has locked it, `open` gives up after three tries with
`Error::Io`. *(0.8.2)* A symbolic link at the lock file's
name is not followed, and something there that is not a regular file, such as a FIFO, is not used
as the lock: `open` fails with `Error::Io` either way, and a FIFO there does not make it wait.
`open` goes ahead without a lock only on a read-only file system, or when there is no lock file and
the process may not create one in the directory, where a write could not create its tmp file
either. The lock does not keep out someone who can write in the directory: they can remove or
replace the lock file. Whoever can open the lock file, also only for reading, can hold the lock
and make every `open` fail with `Io`. On a network filesystem the lock may not hold between
machines. Nor does the guard hold in two cases inside the program, and neither gives an error.
`close_inherited_fds` closes the lock, after which a second `open` of the file succeeds: call it
before opening a store.
After a `fork` without `exec`, parent and child share the lock, and it is held until both copies of
the handle are gone. Both can write through their copies, and the last to write overwrites what the
other wrote: open the store after the fork, or use it in one process only.

`rotate` *(0.6.0)* re-encrypts the whole store under a new master key: everything is decrypted
with the old one FIRST (if anything fails, the file is untouched), and a completely new file
with a fresh salt and a fresh generation id replaces the old one in a single atomic rename —
never a half-rotated store. `rotate` consumes the handle (it is bound to the old key) and gives a
new one back, bound to the new key. When it fails, the handle is consumed all the same and there
is no new one. Open the file again; it is unchanged, except in one case *(0.8.2)*: if only the
sync of the directory after the rename failed, the file is under the new master key, and the
`Error::Io` says so; reopen it with the new master key then.

*(0.9.0)* `rotate` keeps the file's version — a v2 store stays v2, a v1 store stays v1 — with a
fresh salt and a fresh key id, all entries re-sealed, and on a v2 file the `counter` reset to 0
with `key_check` and `container_mac` recomputed.

`rotate` holds every value of the store in locked memory at once, so the locked-memory limit
bounds how many entries a store can rotate; `upgrade` decrypts them one at a time.

---

## `password` — passwords

Argon2id, in **two roles that must not be confused**:

| Role | Function | What you store |
|---|---|---|
| Is the password correct? | `hash` / `verify` | the PHC string |
| Give me the key this password unlocks | `derive_key` | **nothing** — only the salt |

```rust
pub enum Preset { Interactive, Balanced, High }
pub const MAX_PASSWORD_BYTES: usize = 1024;   // 0.9.0
pub const MAX_PHC_BYTES: usize = 512;         // 0.9.0

pub fn hash(password: &SecretString, preset: Preset) -> Result<String, Error>;
pub fn verify(password: &SecretString, phc: &str) -> Result<(), Error>;
pub fn derive_key(password: &SecretString, salt: &[u8], preset: Preset)
    -> Result<SecretBuf, Error>;
```

- `verify` is constant-time. `Auth` means the password does not match: a **wrong password**, or a
  PHC string that can be read but was cut short or altered. `Format` means the PHC string cannot
  be read or is foreign. Do not merge them.
- `hash` gives a PHC string for Argon2id, version 19 (`v=19`), with the preset's parameters, a
  random salt of 16 bytes and a hash of 32 bytes.
- *(0.8.2)* `verify` accepts **Argon2id, version 19** with the `v=19` field present, and parameters
  between the floor and a ceiling a little above `High`: `65 536 ≤ m ≤ 327 680` KiB (64–320 MiB),
  `2 ≤ t ≤ 5`, `1 ≤ p ≤ 5`. The ceiling is `High` plus a margin (m + 25 %, t + 1, p + 1) and moves
  with it. That is wider than what krypto writes: the parameters may come in any order, a string
  that leaves out `t` or `p` is read with Argon2's defaults (`t=2`, `p=1`), the salt may be 8 to 48
  bytes and the hash 10 to 64 bytes, and the length of the stored hash is the length of the output
  compared. Associated data (`data=`) of up to 32 bytes is accepted and given to Argon2; krypto
  never writes it. Anything else — Argon2i, Argon2d, version 16, a string without `v=`, a `keyid`
  (it names a secret key krypto does not have), parameters outside the range — is `Format`,
  refused before Argon2 runs, so a stored string cannot make one call use more memory or time than
  that.
- When the working memory of Argon2 cannot be had, `hash` and, *(0.9.0)*, `derive_key` answer
  `Hardening`, while `verify` answers `Format`; when Argon2 fails in another way, `hash` answers
  `Hardening`, and `verify` and `derive_key` answer `Format`.
- `derive_key` requires a salt of **at least 16 bytes** and, *(0.8.2)*, at most
  `MAX_DERIVE_INPUT_BYTES` (1024); a shorter or longer salt is `Format`. The key it gives is 32
  bytes. The salt is not secret and is stored in plaintext next to the encrypted data.
- *(0.9.0)* The password of `hash`, `verify` and `derive_key` is at most `MAX_PASSWORD_BYTES`
  (1024) bytes, and the PHC string of `verify` at most `MAX_PHC_BYTES` (512) bytes; a longer one is
  `Format`, refused before Argon2 runs. The password is checked first, then the salt or the PHC
  string, and the PHC string before it is parsed. No string krypto accepts comes near 512 bytes.
  The password is already a `SecretString` in locked memory, up to `MAX_DATA_BYTES`, when its
  length is checked, so bound what you take from outside before you make it one.

> **Never store a verification hash next to the ciphertext.** If the password is wrong, the open
> fails by itself. A stored hash would additionally hand an attacker with the disk a separate
> oracle to guess against.

### The presets

The crate owns the numbers. You pick a profile and store its **name**, not the numbers.

| Preset | Memory | Intended for |
|---|---|---|
| `Interactive` | 64 MiB (t=3, p=2) | login |
| `Balanced` | 128 MiB (t=3, p=3) | the middle ground *(0.5.0; p = 3 from 0.6.0)* |
| `High` | 256 MiB (t=4, p=4) | high value, or anything an attacker can attack offline |

The floor is `m ≥ 64 MiB, t ≥ 2, p ≥ 1` — every preset sits on or above it, and *(0.8.2)*
`verify` refuses a PHC string below it. The numbers may be tuned: old PHC strings keep verifying
unchanged as long as they stay within the range `verify` accepts (the parameters live in the
string; *rehash on login* is the consumer's part of a raise), but **`derive_key` is
parameter-dependent** — a preset adjustment changes the key it yields.

---

## `sign` — signatures *(new in 0.5.0)*

Ed25519 with **raw** keys (32-byte seed/public, 64-byte signature) and ECDSA P-256 with a
**PKCS#8** private key, a **SEC1** public point (65 bytes, leading `0x04`; verification also takes
the 33-byte forms: compressed, leading `0x02` or `0x03`, and compact, leading `0x05`) and an
**ASN.1 DER** signature over SHA-256 — the same wire form as `ring`'s `ECDSA_P256_SHA256_ASN1`.

```rust
pub const ED25519_SEED_LEN: usize = 32;
pub const ED25519_PUBLIC_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;
pub const MAX_ECDSA_P256_PUBLIC_BYTES: usize = 65;    // 0.9.0
pub const MAX_ECDSA_P256_SIG_BYTES: usize = 72;       // 0.9.0
pub const MAX_ECDSA_P256_PKCS8_BYTES: usize = 512;    // 0.9.0

pub fn ed25519_keypair() -> Result<(SecretBuf, [u8; 32]), Error>;
pub fn ed25519_public(seed: &SecretBuf) -> Result<[u8; 32], Error>;
pub fn ed25519_sign(seed: &SecretBuf, message: &[u8]) -> Result<[u8; 64], Error>;
pub fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error>;   // strict (0.8.2)
pub fn ed25519_verify_relaxed(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error>;   // 0.8.2

pub fn ecdsa_p256_keypair() -> Result<(SecretBuf, Vec<u8>), Error>;   // (PKCS#8, SEC1 65B)
pub fn ecdsa_p256_public(pkcs8: &SecretBuf) -> Result<Vec<u8>, Error>;
pub fn ecdsa_p256_sign(pkcs8: &SecretBuf, message: &[u8]) -> Result<Vec<u8>, Error>;  // DER
pub fn ecdsa_p256_verify(public_sec1: &[u8], message: &[u8], sig_der: &[u8]) -> Result<(), Error>;
```

A signature that does not hold → `Auth`. For Ed25519, a public key that is not 32 bytes or not a
point on the curve, and a signature that is not 64 bytes, are `Format`; in a signature of 64 bytes,
an S that is not below the group order or an R that is not the canonical encoding of a point is
`Auth` (see below). For P-256, a public key is `Format` unless it is a point on the curve other than
the identity, given as 65 bytes starting with `0x04` or as 33 bytes starting with `0x02`, `0x03` or
`0x05`; and a signature is `Format` unless it is ASN.1 DER of two integers r and s, each from 1 to
below the group order. Signing is RFC 6979 deterministic; the verifier also accepts randomized
signatures (same wire form). Tested against RFC 8032 (TEST 1+2) and RFC 6979 A.2.5.

An ECDSA signature is given as RFC 6979 computes it, with no rule on S, and `ecdsa_p256_verify`
accepts both (r, s) and (r, n − s): anyone can make a second valid signature from a first, so the
bytes of a signature cannot serve as its identity. Neither scheme separates one use of a key from
another: both sign the message as given, so a signing key serves one purpose.

*(0.9.0)* **Sizes.** The message of every sign and verify function is at most `MAX_DATA_BYTES`
(64 MiB); more is `Format`, checked first. For P-256, the public key is at most
`MAX_ECDSA_P256_PUBLIC_BYTES` (65), the signature at most `MAX_ECDSA_P256_SIG_BYTES` (72) and the
PKCS#8 private key at most `MAX_ECDSA_P256_PKCS8_BYTES` (512) bytes; a longer one is `Format`,
refused before it is parsed. `ecdsa_p256_verify` checks the message, the public key and the
signature in that order; `ecdsa_p256_sign` the message, then the key.

*(0.8.2)* **Two Ed25519
verifiers.** `ed25519_verify` is strict: a public key of small order (a *weak* key) or an R of
small order in the signature → `Auth`, and a public key that is not the canonical 32-byte encoding
of its point → `Format`. So `Ok` means the signature was made with the private key that belongs to
that public key. `ed25519_verify_relaxed` checks that the signature equation holds and, as
`ed25519_verify` does, refuses with `Auth` an R that is not the canonical encoding of a point; it
does not refuse weak keys, an R of small order or non-canonical key encodings, and for a weak key
anyone can make signatures that hold, without a private key. Use it only where such keys must be
accepted, never to check who signed with a public key that came from someone else. Keys from
`ed25519_keypair` and signatures from `ed25519_sign` verify with both. Both refuse, with `Auth`,
an S that is not below the group order, as long as no crate in your build turns on the
`legacy_compatibility` feature of `ed25519-dalek`; Cargo merges features across a build, and with
that feature both accept such an S if its top three bits are clear.

---

## `exchange` — X25519 key agreement *(new in 0.5.0)*

```rust
pub const X25519_KEY_LEN: usize = 32;

pub fn x25519_keypair() -> Result<(SecretBuf, [u8; 32]), Error>;
pub fn x25519_public(secret: &SecretBuf) -> Result<[u8; 32], Error>;
pub fn x25519_shared(secret: &SecretBuf, peer_public: &[u8]) -> Result<SecretBuf, Error>;
```

The primitive under sealed envelopes (RFC 7748) — the envelope **format** belongs to the
consumer. `x25519_shared` rejects a non-contributory result (a low-order peer point) with
`Auth`, and the result is keying *material*: run it through HKDF (`MasterKey::derive`) before
use. A private key or a peer public key that is not exactly 32 bytes is `Format`, checked before
the shared secret is computed. Tested against RFC 7748 §6.1.

The all-zero result is the only one refused, and key agreement authenticates no one. Different
peer public keys can give the same secret, since the top bit of a public key is ignored and
small-order components drop out. Authenticate the peer's public key by your own means, and bind
both public keys into the derivation, in the context or the salt.

---

## `hex` — canonical hex *(new in 0.5.0)*

```rust
pub fn encode(bytes: &[u8]) -> Result<String, Error>;  // lowercase; a Result from 0.9.0
pub fn decode(s: &str) -> Result<Vec<u8>, Error>;      // fail-closed: [0-9a-f] only, even length
```

One canonical form: `decode` rejects UPPERCASE on purpose — two spellings of the same bytes must
not be able to exist in signed forms and fingerprint comparisons. What `decode` rejects is
`Error::Format`; *(0.8.2)* the message for an invalid character names neither the character nor
where it is. *(0.9.0)* The output buffer is reserved with `try_reserve_exact`: a failed
reservation is `Error::Hardening` instead of an abort; a length the system promises but cannot back
still fills the memory.

`hex` and `base64` are for public values: their time depends on the data, and they work in
ordinary memory, which is not wiped when decoding fails.

*(0.9.0)* The limit is on the bytes: `encode` takes at most `MAX_DATA_BYTES` (64 MiB), and `decode`
a text of at most twice that, the hex of `MAX_DATA_BYTES` bytes, so `decode` takes whatever
`encode` makes. More is `Format`, refused before any memory is reserved; for `decode` it is the
first check. `encode` reserves its output with `try_reserve_exact` too, and a failed reservation
is `Hardening`.

---

## `base64` — canonical base64 *(0.5.1)*

```rust
pub fn encode(bytes: &[u8]) -> Result<String, Error>;        // STANDARD, padded (PEM body); a Result from 0.9.0
pub fn encode_nopad(bytes: &[u8]) -> Result<String, Error>;  // the ssh fingerprint form; a Result from 0.9.0
pub fn decode(s: &str) -> Result<Vec<u8>, Error>;            // fail-closed, requires padding
pub fn decode_nopad(s: &str) -> Result<Vec<u8>, Error>;      // fail-closed, rejects padding
```

Same philosophy as `hex`: one spelling — whitespace, wrong padding and non-canonical trailing
bits are rejected, as `Error::Format`. *(0.8.2)* The message for an invalid character names
neither the character nor where it is. Keys and signatures on the wire are still HEX; base64 exists
only for formats that ARE base64 by nature (`SHA256:<base64-no-pad>` fingerprints, PEM).
*(0.9.0)* `decode` and `decode_nopad` reserve the output buffer with `try_reserve_exact`: a failed
reservation is `Error::Hardening` instead of an abort; a length the system promises but cannot back
still fills the memory.

*(0.9.0)* The limit is on the bytes: `encode` and `encode_nopad` take at most `MAX_DATA_BYTES`
(64 MiB), and `decode` and `decode_nopad` decode to at most that many, so they take whatever the
encoders make. A text longer than the encoding of `MAX_DATA_BYTES` bytes (padded for `decode`,
unpadded for `decode_nopad`) is `Format`, the first check; so is a padded text of that length that
would decode to more, with one `=` or none where the encoding of `MAX_DATA_BYTES` bytes has two.
Both are refused before any memory is reserved. The encoders reserve their output with
`try_reserve_exact`, and a failed reservation is `Hardening`.

---

## Root utilities *(new in 0.5.0)*

```rust
pub fn sha256(data: &[u8]) -> [u8; 32];                     // FIPS 180-4 — fingerprints
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool;                   // constant-time; length mismatch → false
pub fn random_bytes(len: usize) -> Result<Vec<u8>, Error>;  // OS CSPRNG for NON-secrets, at most MAX_RANDOM_BYTES (0.7.3)
pub fn random_bytes_with_limit(len: usize, limit: usize) -> Result<Vec<u8>, Error>; // 0.7.3
pub const MAX_RANDOM_BYTES: usize = 1 << 20;                // 0.7.3
pub const MAX_DATA_BYTES: usize = 64 * 1024 * 1024;         // 0.9.0 — the shared limit on an amount of data
```

`sha256` is not authentication (use `hmac_sha256`) and not passwords (use `password`).
*(0.9.0)* `sha256` and `ct_eq` have no size limit: they cannot fail and reserve no memory.
`random_bytes` is for salts/ids/jitter — secrets go in `SecretBuf::random`.

*(0.7.3)* **The size of one call is capped.** `random_bytes` and `SecretBuf::random` give at most
`MAX_RANDOM_BYTES` (1 MiB) per call; more is `Format`. A program that needs more in one call states
its own cap with `random_bytes_with_limit(len, limit)` or `SecretBuf::random_with_limit(len, limit)`:
`len` above `limit` is `Format`. The cap is per call, never a setting for the process. Memory that
cannot be had is `Hardening`, never a crash; a high `limit` is your choice, and a length the system
promises but cannot back still fills the memory.

---

## `harden` — process hardening

```rust
pub fn harden_process() -> Result<(), Error>;       // core dumps off + non-dumpable (Linux)
pub fn no_new_privs() -> Result<(), Error>;         // never gain privileges (PR_SET_NO_NEW_PRIVS)
pub fn close_inherited_fds() -> Result<(), Error>;  // closes EVERYTHING above stderr (close_range, Linux 5.9+)
pub fn drop_filesystem(dir: impl AsRef<Path>) -> Result<(), Error>; // chroot into an EMPTY dir, the process inside it
```

On Linux, the platform krypto supports, all of them are **fail-closed**: if the call cannot
deliver, you get `Err` — never silent degradation. On other systems `no_new_privs` and
`close_inherited_fds` fail with `Hardening`, and so does `drop_filesystem` once it has checked the
directory; `harden_process` only sets the core-dump limit to zero and reports success, and fails
with `Hardening` only if it cannot set that limit. Each step
is its own deliberate choice. Recommended order: `harden_process()` and
`no_new_privs()` first in `main` · `close_inherited_fds()` early, before opening your own files
(NB: it also kills deliberately inherited sockets, e.g. socket activation — hence a separate
call) · `drop_filesystem(dir)` **after** key material is read — irreversible, needs privileges
(root or `CAP_SYS_CHROOT`), and the directory must be empty (verified before the chroot).
*(0.7.3)* Use a directory only root can write to, such as `/var/empty`. The chroot applies to the
directory that was checked, and the root changes as the last step, with the process already
inside; on `Err` the root has not changed and the process stands where it stood, unless stepping
back out of the directory fails too; then it stays in the directory, and the error says so. After
the chroot krypto needs no filesystem, with two exceptions. An open `SecretStore` can no longer
write its file, since writes go by path and the path now resolves inside the new root. And
randomness comes from the `getrandom` syscall (Linux 3.17 and later), but where that call is
unavailable or blocked (`ENOSYS`, or `EPERM` from a seccomp filter), the `getrandom` crate reads
`/dev/urandom` instead on most Linux targets, x86-64 and AArch64 among them, through a descriptor
it keeps open; if it had not opened it before the chroot, random calls fail with `Hardening`.
AEAD, KDF, signing and passwords touch no files. A directory that is missing or cannot be opened
or read is `Io`; one that is not a directory or is not empty, and any failure from the step into
it up to the change of root, are `Hardening`.

`close_inherited_fds` also closes the lock of a
[`SecretStore`](#secretstore--encrypted-store-on-file) that is already open, after which a second
`open` of that file succeeds: call it before opening a store, and before anything has asked for
random bytes (see what the steps leave open, below).

What the steps leave open: a later change of user or group id resets the mark `harden_process`
sets to the machine's setting, so call it again after one, and crash handlers inside the process
are not reached by it. `close_inherited_fds` also closes descriptors libraries hold, and the
`/dev/urandom` descriptor where the `getrandom` crate has fallen back to it, after which later
random bytes are read from whatever is opened next under that number. `drop_filesystem` does not
hold against a process that keeps the privilege to change its root, so giving that up afterwards
is yours, and descriptors opened before it stay usable. The steps, and what each leaves open, are
in [SPEC-memory](../spec/SPEC-memory.md).

Hardening is process-local: it protects the process that calls it. *(0.8.0)* From Python,
`krypto-py` hardens the Python process with these same functions.

One protection lies outside the process, and krypto cannot turn it on: the Linux kernel setting
`init_on_free=1`, set on the kernel command line by whoever runs the machine, makes the kernel
overwrite memory with zeros when it is released to it. krypto recommends turning it on, so that
ordinary memory a secret has passed through, above all the Argon2 working memory of
`password::hash` and `verify`, is not left readable once it has gone back to the kernel. With
glibc's allocator at its default settings, a block as large as that working memory goes back as
soon as it is released; another allocator, or other settings, can keep it in the process. See
[What is left on the stack](#what-is-left-on-the-stack-082).

---

## `error` — `Error`

```rust
pub enum Error { Io(io::Error), Hardening(String), Format(String), Auth, KeyNotFound, WrongKey, Rollback { file_counter: u64, min_counter: u64 } }   // Rollback: 0.9.0
```
`#[non_exhaustive]`. Implements `Display`, `std::error::Error` (its `source()` is the inner
`io::Error` for `Io`, and `None` for the others) and `From<std::io::Error>`.

| Variant | Means |
|---|---|
| `Io` | file or directory: also a store that is already open through another handle, a lock file that is a symbolic link or not a regular file, and a store write whose file is replaced but whose directory could not be synced afterwards, so the change is in the file; *(0.9.0)* also a store file that `open_with_min_counter` with `min_counter` above 0 did not find |
| `Hardening` | a protection step or the environment failed: locked or protected memory, randomness, process hardening, Argon2 failing in `password::hash`, and an internal step no input can cause — never a verdict on the data; treated fail-closed. *(0.9.0)* Also a `SecretStore` write refused because the store's counter is at its maximum: rotate the store |
| `Format` | the input had the wrong shape. *(0.7.3)* Data that is not a krypto blob, or a malformed key, signature, PHC string, encoding or parameter, such as an empty `info`. *(0.9.0)* Not a krypto blob means shorter than its 4-byte magic, or not starting with `FAFN`. *(0.9.0)* An input over its size limit, a blob over its limit included. For a `SecretStore`: not a store file, an unknown version, an invalid structure, or *(0.9.0)* another version than the open names, and a name that breaks the name rules at `get` or `delete` |
| `Auth` | **wrong key, wrong password, or someone tampered** — *(0.7.3)* any change to a blob past its `FAFN` magic, a header cut short past the magic included *(0.9.0)*, that leaves the blob within its size limit *(0.9.0)*, and a key id in a `SecretStore` that does not match. *(0.9.0)* At the open of a v2 store file: the file is not what was written — cut short of its header, or the master key fits and something else was changed, added or removed |
| `KeyNotFound` | the name does not exist in the store |
| `WrongKey` | the key does not fit *(0.5.0)*. *(0.9.0)* At the open of a v2 store file: the master key does not fit the file; a changed salt or `key_check` gives the same answer, so a caller that knows its key is the right one treats it as a changed file. No blob function returns it: a blob opened with a key of another generation is `Auth`. It is also the answer for a caller's own code that routes blobs between key generations |
| `Rollback { file_counter, min_counter }` | *(0.9.0)* only from `SecretStore::open_with_min_counter`: a v2 store file whose `counter` (`file_counter`) is below the caller's minimum (`min_counter`) — an older copy of the file may have been put back. Distinct from `Auth`, which means the content itself does not verify |

No variant carries key material or plaintext.

In a blob every change past the magic is `Auth`, except a blob made larger than its limit. Outside
the blob, a writer of stored data can sometimes get another answer: `Format` for a store file with
a changed magic or version byte, or cut to less than those five bytes, a v1 file cut short or
broken, or a PHC string changed until it no longer reads; `WrongKey` for a changed salt or
`key_check` of a v2 file; `Io` for a store file made unreadable or replaced by a socket. A caller
that stores krypto's data where others can write treats an unexpected `Format`, `WrongKey` or `Io`
on data it wrote itself as a warning.
[SPEC-answers](../spec/SPEC-answers.md) gives every class, and where a writer can choose one.

**The distinction that is the whole point:** `Auth` means that what was given does not verify —
tampering, or for a blob a wrong key — and **should be alarmed on**. `WrongKey` means that the key
is not the one for this data, and says nothing against the data. *(0.9.0)* At the open of a v2
store file the library gives both: `WrongKey` when the master key does not fit the file, `Auth` when the file
is not what was written. For a blob the library gives `Auth` in both cases, so a caller that holds
several key generations reads `blob_key_id` and picks the key before it opens; then a blob from
another generation is routed, not alarmed on.

---

## Trait implementations

Part of the contract on equal footing with the functions — especially the **absent** ones:

| Type | Impls |
|---|---|
| `SecretBuf` | `Drop`, `Debug`, `Display` *(always redacted)*, `Send`, `Sync` |
| `SecretString` | `Debug`, `Display`, `Send`, `Sync` *(no own `Drop` — the inner buffer carries it)* |
| `Error` | `Debug`, `Display`, `std::error::Error`, `From<std::io::Error>` |
| `Alg` | `Clone`, `Copy`, `PartialEq`, `Eq`, `Debug` |
| `Preset` | `Clone`, `Copy`, `Debug` |
| `MasterKey`, `DerivedKey`, `SecretStore<'a>` | `Send`, `Sync` and the other auto traits; **no written or derived impl** |

No secret-bearing type has `Clone`, `Serialize`, `PartialEq` or `Default` — absence is
enforcement. The modules `sign`/`exchange`/`hex`/`base64` are free functions + constants.

---

## Python — `krypto-py` *(0.8.0)*

The same API from Python 3.11 or newer: `pip install krypto-py`, then `import krypto_py`. Every
function, type, constant and module in this document exists there, with the same name, and does the
same thing; there is no function that only one of them has, and a test fails the build if a name is
on one side only. What differs is what can be guaranteed (below). What one seals, stores, signs or
hashes, the other opens, reads and verifies. How to use it, with examples: **[Python](Python.md)**.

How the Rust forms read in Python:

| Rust | Python |
|---|---|
| `krypto::seal`, `krypto::sign::ed25519_sign`, … | `krypto_py.seal`, `krypto_py.sign.ed25519_sign`, … — the modules `sign`, `exchange`, `password`, `hex`, `base64`, `harden` and `error` too |
| `&[u8]`, `Vec<u8>`, `[u8; N]` | `bytes`; a wrong length for `[u8; N]` is `FormatError` |
| `&str`, `String` | `str` |
| `impl AsRef<Path>` | `str` or a path object |
| `usize`, `u8`, `u64` | `int`; a negative number, or one too large for the Rust type, is Python's `OverflowError`, raised before krypto runs |
| A function on a type without `self`: `SecretBuf::from_vec`, `MasterKey::from_bytes`, `SecretStore::open`, … | A static method on the class: `SecretBuf.from_vec(…)`, `MasterKey.from_bytes(…)`, `SecretStore.open(…)`, … |
| `Result<T, Error>` | `T`, or an exception; *(0.9.0)* so `hex.encode`, `base64.encode` and `base64.encode_nopad` return a `str` or raise |
| `Error::Io`, `Hardening`, `Format`, `Auth`, `KeyNotFound`, `WrongKey`, `Rollback` *(0.9.0)* | `IoError`, `HardeningError`, `FormatError`, `AuthError`, `KeyNotFoundError`, `WrongKeyError`, `RollbackError`, all subclasses of `krypto_py.Error`, which is a subclass of `Exception`; they are at the module root and in `krypto_py.error`. `RollbackError` has the attributes `file_counter` and `min_counter` |
| `VERSION` | `VERSION`, and the same value as `__version__` |
| `SecretBuf::len`, `SecretString::len` | `len()`, and also Python's `len(secret)` |
| `Alg::Aegis256`, `Preset::High`, … | `Alg.Aegis256`, `password.Preset.High`, …; both compare with `==`, though Rust's `Preset` has no `PartialEq`. They also compare equal to their position as an `int` (0, 1, 2 — not the blob's `alg_id`), and they are not hashable |
| A value taken by value: `MasterKey::from_bytes(SecretBuf)`, `SecretStore::rotate(self, …)`, `SecretStore::upgrade(self)` | The object is consumed, also when the operation itself fails, and also when `upgrade` on a v2 store writes nothing; using it afterwards is a `ValueError`. An argument of the wrong type is rejected with `TypeError` before anything is consumed |
| `expose(\|b\| …)`, `expose_str(\|s\| …)` | `expose(f)`, `expose_str(f)`: `f` is called with a copy, and what it returns is returned |
| `SecretStore<'a>` borrows the `MasterKey` | `SecretStore` keeps the `MasterKey` object alive |
| `Debug` (redacted, where the type has it) | `repr()` on every class, and so printing, never the contents: `SecretBuf([REDACTED], len=N)` (`SecretBuf(<consumed>)` once consumed), `SecretString([REDACTED], len=N)`, `MasterKey([REDACTED])`, `DerivedKey([REDACTED])`, `SecretStore` |

### What is guaranteed, and where Python differs

| | Rust | Python |
|---|---|---|
| `SecretBuf`, `SecretString`, `MasterKey`, `DerivedKey`, and in a `SecretStore` the keys and the plaintext it returns | In locked memory, kept out of core dumps on Linux, guard pages, wiped on drop; a store's names and sealed blobs are in ordinary memory | The same: the objects hold Rust memory |
| What goes in | Moved in, or zeroized by `from_vec` | Copied in. The `bytes` or `str` passed stays as Python keeps it, neither locked nor wiped; a `bytearray` given to `SecretBuf.from_vec` is zeroed, also when the call fails |
| What comes out | Seen inside the closure, in locked memory | `expose` and `expose_str` hand `f` a Python copy, neither locked nor wiped. `open` and `get` return a `SecretBuf`, so plaintext stays locked until exposed |
| Locked memory | Counted against `RLIMIT_MEMLOCK` of the process | The same, in the Python process |
| `fork` | The child's copies of locked pages are not locked | The same |
| `harden` | Applies to the process | Applies to the Python process; `close_inherited_fds` closes the interpreter's own descriptors too |
| The GIL | — | *(0.8.2)* The module declares that it needs the GIL (`gil_used = true`): krypto-py is built and tested only with Python that has the GIL, not on a free-threaded Python |
| Long calls | — | `password::hash`, `verify` and `derive_key` release the GIL, so threads that run them at once each take Argon2's memory, 64 to 320 MiB per call; the salt of `derive_key` must be `bytes` (a `bytearray` or `memoryview` is a `TypeError`), so it cannot change while Argon2 runs |
| A panic inside krypto | Unwinds to the caller | Becomes `pyo3_runtime.PanicException`, which derives from `BaseException`, so `except Exception` does not catch it |

---

## Further

- **[Home](Home.md)** — what krypto is, and what it does not do
- **[Usage](Usage.md)** — how to do it, with examples in Rust
- **[Python](Python.md)** — the same, with examples in Python
