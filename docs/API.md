# API — reference

Every public type and function in `krypto`.

This is a **reference**. To get started, or to understand why things are done the way they are,
read **[How to use krypto](Usage.md)** first. What the crate is and is not lives in
**[Home](Home.md)**.

Everything that can fail returns `Result<_, Error>`. The crate does not panic on input.

**This document is the contract** — precise enough to reimplement the crate from, and it ships
with the module. Two normative rules bind whoever *changes* the surface:

- **Verify input and output.** All input is validated (type, length, range, character set —
  fail-closed; unknown values are rejected, not ignored), and output never carries secrets or
  unexpected structure. An uncovered case → update this document.
- **The feedback contract.** What the crate answers — success, errors and status — lives HERE:
  the library through `Result` and [`Error`](#error--error) (the crate never logs — logging
  belongs to the consumer), the cli through exit codes, per-command stdout formats and stderr.
  No error path carries key material or plaintext. An answer not written here is a gap in the
  contract and should be reported — not interpreted.

---

## Root

```rust
pub const VERSION: &str;  // 0.6.0 — the crate version (mirrors Cargo.toml), for About pages

pub use secret::{SecretBuf, SecretString};
pub use kdf::{MasterKey, DerivedKey, hmac_sha256, MAX_MASTER_KEY_BYTES, MAX_DERIVE_INPUT_BYTES};
pub use aead::{seal, open, reseal, blob_key_id, Alg};  // reseal: 0.6.0
pub use store::{SecretStore, MAX_STORE_BYTES};
pub use error::Error;
pub use harden::{close_inherited_fds, drop_filesystem, harden_process, no_new_privs};
pub use util::{ct_eq, random_bytes, sha256};

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

*(The size caps `MAX_MASTER_KEY_BYTES` (4 KiB) and `MAX_STORE_BYTES` (16 MiB) became reachable in
0.5.0 — they were named in the contract but lived in private modules. `MAX_DERIVE_INPUT_BYTES`
(1 KiB) joined them in 0.7.0: `derive` took unbounded `info` and `salt`.)*

---

## The secret types

The foundation. Anything secret crosses a boundary as one of these — never as `String`, `&str` or
`Vec<u8>`.

### `SecretBuf`

Owned byte buffer in locked memory. Zeroized when dropped.

```rust
impl SecretBuf {
    pub fn from_vec(v: Vec<u8>) -> Result<Self, Error>;   // copies in, zeroizes the source
    pub fn random(len: usize) -> Result<Self, Error>;     // from the OS CSPRNG
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn expose<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R;
}
```

`expose` is the **only** path to the plaintext, and the reference cannot escape the closure.

### `SecretString`

Like `SecretBuf`, but guaranteed valid UTF-8.

```rust
impl SecretString {
    pub fn from_string(s: String) -> Result<Self, Error>;
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
| `Debug` / `Display` | ✅ — always `SecretBuf([REDACTED], len=N)` | ✅ — same |
| `Drop` | ✅ | *(through the inner buffer)* |

---

## Keys

### `MasterKey`

The root key. Comes from outside — the crate does not create it.

```rust
impl MasterKey {
    pub fn from_secret_file(path: impl AsRef<Path>) -> Result<Self, Error>;
    pub fn from_bytes(key: SecretBuf) -> Result<Self, Error>;   // consumes the buffer
    pub fn derive(&self, info: &[u8], salt: &[u8]) -> Result<DerivedKey, Error>;
}
```

`derive` is HKDF-SHA256. `info` is your own context string — the crate does not know your purpose
names. Different `info` gives different keys, and that is how you keep purposes apart. **An
empty `info` is rejected** — it IS the purpose separation. Both `info` and `salt` are capped
*(0.7.0)* at
`MAX_DERIVE_INPUT_BYTES` (1024); they reach the API from command lines and config files, and the
longest real one is the store's prefix plus a key name — 16 + 512 bytes.

The key must be 32..=`MAX_MASTER_KEY_BYTES` (4096) bytes, on **both** ways in *(0.7.0: the cap
was only on `from_secret_file` before)*; file reads are
bounded (never OOM).
`from_bytes` **consumes** the buffer (the key cannot be read back out) and is the path for a
key that must never touch disk.

### `DerivedKey`

A working key. Opaque — no public methods. Used by `seal`, `open` and `hmac_sha256`.

### `hmac_sha256`

```rust
pub fn hmac_sha256(key: &DerivedKey, data: &[u8]) -> Result<[u8; 32], Error>;
```

---

## Encryption

```rust
pub enum Alg { Aegis256, XChaCha20Poly1305, Aes256Gcm }   // #[non_exhaustive]

pub fn seal(key: &DerivedKey, key_id: &[u8; 16], plaintext: &SecretBuf, alg: Alg)
    -> Result<Vec<u8>, Error>;
pub fn open(key: &DerivedKey, blob: &[u8]) -> Result<SecretBuf, Error>;
pub fn blob_key_id(blob: &[u8]) -> Result<[u8; 16], Error>;
pub fn reseal(old: &DerivedKey, new: &DerivedKey, new_key_id: &[u8; 16], blob: &[u8])
    -> Result<Vec<u8>, Error>;   // 0.6.0 — key rotation
```

`Alg::Aegis256` is the default. The other two exist for compatibility with systems that require
them.

`blob_key_id` reads which key a blob was made with — **without opening it**. Useful when you hold
several keys and must find the right one first. Note that the value is a *hint about where to
look*, not proof: tampering is discovered when `open` is called, as `Error::Auth`.

`reseal` *(0.6.0)* is the rotation **action**: open with the old key, seal with the new one
under a new generation id — the blob's algorithm is preserved. Both keys come from you (krypto
is stateless and never owns keys); a wrong old key or tampering gives `Auth`, and nothing is
produced.

> **Tampering always gives `Auth`, never wrong plaintext.** The whole blob header is part of the
> authentication, so changing the algorithm id, key id or version makes the open fail. That is an
> absolute guarantee, not a detail.

### The blob format (`FAFN`, format_ver 1 — unchanged since 0.2)

```text
magic "FAFN" (4) | format_ver (1) | alg_id (1) | key_id (16) | nonce (32) | ciphertext | tag
```

- `alg_id`: 1 = AEGIS-256 (256-bit tag) · 2 = XChaCha20-Poly1305 · 3 = AES-256-GCM.
- **The AAD contract (absolute):** the whole header up to and including the nonce (**54 bytes**)
  is associated data — the "key-id swap test": tampering with magic/version/alg_id/key_id/nonce
  yields `Auth`, never a mis-decrypt.
- The nonce is random per blob from the OS CSPRNG. The 32-byte field is used partially:
  AEGIS-256 all 32, XChaCha 24, AES-GCM 12 — the rest zero.
- **Verified against official vectors** (0.5.0): AEGIS-256 against `draft-irtf-cfrg-aegis-aead`,
  XChaCha against draft-arciszewski A.1, AES-256-GCM against NIST CAVS. ⚠ 0.5.0 fixed a
  key/nonce swap in the AEGIS layer — AEGIS blobs from ≤ 0.4.4 yield `Auth` on ≥ 0.5.0 and must
  be re-encrypted.

---

## `SecretStore` — encrypted store on file

```rust
pub struct SecretStore<'a>;   // borrows &MasterKey for its lifetime

impl<'a> SecretStore<'a> {
    pub fn open(path: impl AsRef<Path>, master: &'a MasterKey) -> Result<Self, Error>;
    pub fn put(&mut self, name: &str, secret: &SecretBuf) -> Result<(), Error>;
    pub fn get(&self, name: &str) -> Result<SecretBuf, Error>;   // WrongKey on another key generation (0.5.0)
    pub fn delete(&mut self, name: &str) -> Result<(), Error>;
    pub fn contains(&self, name: &str) -> bool;
    pub fn list(&self, prefix: &str) -> Vec<String>;
    pub fn rotate(self, new_master: &MasterKey) -> Result<SecretStore<'_>, Error>;  // 0.6.0
}
```

Each entry gets its own key derived from its name (`info = "krypto/store/v1|" + name`). A blob
therefore cannot be moved to another name — the open fails. Writes are atomic (tmp + fsync +
rename), and the file is private (0600). File reads are capped at `MAX_STORE_BYTES` (16 MiB).
Name rules: non-empty, ≤ 512 bytes, printable ASCII only (`[\x20-\x7e]`) — names are
addresses, not secrets, and get listed out. Checked on read as well as on write
*(0.7.0)*: a store file need not have come from `put`.

`rotate` *(0.6.0)* re-encrypts the whole store under a new master key: everything is decrypted
with the old one FIRST (if anything fails, the file is untouched), and a completely new file
with a fresh salt and a fresh generation id replaces the old one in a single atomic rename —
never a half-rotated store. The handle is consumed (it is bound to the old key); you get a new
one back, bound to the new key.

---

## `password` — passwords

Argon2id, in **two roles that must not be confused**:

| Role | Function | What you store |
|---|---|---|
| Is the password correct? | `hash` / `verify` | the PHC string |
| Give me the key this password unlocks | `derive_key` | **nothing** — only the salt |

```rust
pub enum Preset { Interactive, Balanced, High }   // before 0.5.0: { Interactive, Moderate }

pub fn hash(password: &SecretString, preset: Preset) -> Result<String, Error>;
pub fn verify(password: &SecretString, phc: &str) -> Result<(), Error>;
pub fn derive_key(password: &SecretString, salt: &[u8], preset: Preset)
    -> Result<SecretBuf, Error>;   // named `utled_noekkel` before 0.5.0
```

- `verify` is constant-time. `Auth` means **wrong password**; `Format` means the PHC string itself
  is corrupt or foreign. Do not merge them.
- `derive_key` requires a salt of **at least 16 bytes**. The salt is not secret and is stored in
  plaintext next to the encrypted data.

> **Never store a verification hash next to the ciphertext.** If the password is wrong, the open
> fails by itself. A stored hash would additionally hand an attacker with the disk a separate
> oracle to guess against.

### The presets

The crate owns the numbers. You pick a profile and store its **name**, not the numbers.

| Preset | Memory | Intended for |
|---|---|---|
| `Interactive` | 64 MiB (t=3, p=2) | login |
| `Balanced` | 128 MiB (t=3, p=3) | the middle ground *(new in 0.5.0; p adjusted 2 → 3 in 0.6.0 — note that `derive_key` then yields a different key than 0.5.x)* |
| `High` | 256 MiB (t=4, p=4) | high value, or anything an attacker can attack offline *(named `Moderate` before 0.5.0 — same numbers)* |

The floor is `m ≥ 64 MiB, t ≥ 2, p ≥ 1` — every preset sits on or above it. The numbers may be
tuned: old PHC strings keep verifying unchanged (the parameters live in the string; *rehash on
login* is the consumer's part of a raise), but **`derive_key` is parameter-dependent** — a
preset adjustment changes the key it yields.

---

## `sign` — signatures *(new in 0.5.0)*

Ed25519 with **raw** keys (32-byte seed/public, 64-byte signature) and ECDSA P-256 with a
**PKCS#8** private key, a **SEC1** public point (65 bytes, leading `0x04`) and an **ASN.1 DER**
signature over SHA-256 — bit-compatible with `ring`, cross-verified both ways.

```rust
pub const ED25519_SEED_LEN: usize = 32;
pub const ED25519_PUBLIC_LEN: usize = 32;
pub const ED25519_SIG_LEN: usize = 64;

pub fn ed25519_keypair() -> Result<(SecretBuf, [u8; 32]), Error>;
pub fn ed25519_public(seed: &SecretBuf) -> Result<[u8; 32], Error>;
pub fn ed25519_sign(seed: &SecretBuf, message: &[u8]) -> Result<[u8; 64], Error>;
pub fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error>;

pub fn ecdsa_p256_keypair() -> Result<(SecretBuf, Vec<u8>), Error>;   // (PKCS#8, SEC1 65B)
pub fn ecdsa_p256_public(pkcs8: &SecretBuf) -> Result<Vec<u8>, Error>;
pub fn ecdsa_p256_sign(pkcs8: &SecretBuf, message: &[u8]) -> Result<Vec<u8>, Error>;  // DER
pub fn ecdsa_p256_verify(public_sec1: &[u8], message: &[u8], sig_der: &[u8]) -> Result<(), Error>;
```

A signature that does not hold → `Auth`. Malformed key/signature → `Format`. Signing is RFC 6979
deterministic; the verifier also accepts randomized signatures (same wire form). Tested against
RFC 8032 (TEST 1+2) and RFC 6979 A.2.5.

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
use. Tested against RFC 7748 §6.1.

---

## `hex` — canonical hex *(new in 0.5.0)*

```rust
pub fn encode(bytes: &[u8]) -> String;                 // lowercase
pub fn decode(s: &str) -> Result<Vec<u8>, Error>;      // fail-closed: [0-9a-f] only, even length
```

One canonical form: `decode` rejects UPPERCASE on purpose — two spellings of the same bytes must
not be able to exist in signed forms and fingerprint comparisons.

---

## `base64` — canonical base64 *(new in 0.5.1, wish #1)*

```rust
pub fn encode(bytes: &[u8]) -> String;                     // STANDARD, padded (PEM body)
pub fn encode_nopad(bytes: &[u8]) -> String;               // the ssh fingerprint form
pub fn decode(s: &str) -> Result<Vec<u8>, Error>;          // fail-closed, requires padding
pub fn decode_nopad(s: &str) -> Result<Vec<u8>, Error>;    // fail-closed, rejects padding
```

Same philosophy as `hex`: one spelling — whitespace, wrong padding and non-canonical trailing
bits are rejected. Keys and signatures on the wire are still HEX; base64 exists only for formats
ARE base64 by nature (`SHA256:<base64-no-pad>` fingerprints, PEM).

---

## Root utilities *(new in 0.5.0)*

```rust
pub fn sha256(data: &[u8]) -> [u8; 32];                     // FIPS 180-4 — fingerprints
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool;                   // constant-time; length mismatch → false
pub fn random_bytes(len: usize) -> Result<Vec<u8>, Error>;  // OS CSPRNG for NON-secrets
```

`sha256` is not authentication (use `hmac_sha256`) and not passwords (use `password`).
`random_bytes` is for salts/ids/jitter — secrets go in `SecretBuf::random`.

---

## `harden` — process hardening

```rust
pub fn harden_process() -> Result<(), Error>;       // core dumps off + non-dumpable
pub fn no_new_privs() -> Result<(), Error>;         // never gain privileges (PR_SET_NO_NEW_PRIVS)
pub fn close_inherited_fds() -> Result<(), Error>;  // closes EVERYTHING above stderr (close_range, Linux 5.9+)
pub fn drop_filesystem(dir: impl AsRef<Path>) -> Result<(), Error>; // chroot into an EMPTY dir + chdir("/")
```

All of them are **fail-closed**: if the call cannot deliver, you get `Err` — never silent
degradation. Each step is its own deliberate choice. Recommended order: `harden_process()` and
`no_new_privs()` first in `main` · `close_inherited_fds()` early, before opening your own files
(NB: it also kills deliberately inherited sockets, e.g. socket activation — hence a separate
call) · `drop_filesystem(dir)` **after** key material is read — irreversible, needs privileges
(root or `CAP_SYS_CHROOT`), and the directory must be empty (verified before the chroot). After
the chroot krypto needs no filesystem: randomness comes from the `getrandom` syscall, and
AEAD/KDF/signing/passwords touch no files.

**Deliberately not in `krypto-cli`** (a documented exclusion under the parity rule): hardening is
process-local — hardening a subprocess does not protect the caller. Non-Rust consumers harden
their own process with their own language's tools.

---

## `error` — `Error`

```rust
pub enum Error { Io(io::Error), Hardening(String), Format(String), Auth, KeyNotFound, WrongKey }
```
`#[non_exhaustive]`. Implements `Display`, `std::error::Error` and `From<std::io::Error>`.

| Variant | Means |
|---|---|
| `Io` | file or directory |
| `Hardening` | memory locking or process hardening failed — treated fail-closed |
| `Format` | the blob, the PHC string or the parameters had the wrong shape |
| `Auth` | **wrong key, wrong password, or someone tampered** |
| `KeyNotFound` | the name does not exist in the store |
| `WrongKey` | the blob belongs to another key generation — routing, not tampering *(new in 0.5.0)* |

No variant carries key material or plaintext.

**The distinction that is the whole point:** `Auth` = tampering or a wrong key — **should be
alarmed on**. `WrongKey` = the blob belongs to another key generation — **routing**: find the
right key (`blob_key_id`). Merging them reintroduces a false alarm.

---

## Trait implementations

Part of the contract on equal footing with the functions — especially the **absent** ones:

| Type | Impls |
|---|---|
| `SecretBuf` | `Drop`, `Debug`, `Display` *(always redacted)* |
| `SecretString` | `Debug`, `Display` *(no own `Drop` — the inner buffer carries it)* |
| `Error` | `Debug`, `Display`, `std::error::Error`, `From<std::io::Error>` |
| `Alg` | `Clone`, `Copy`, `PartialEq`, `Eq`, `Debug` |
| `Preset` | `Clone`, `Copy`, `Debug` |
| `MasterKey`, `DerivedKey`, `SecretStore<'a>` | **none** |

No secret-bearing type has `Clone`, `Serialize`, `PartialEq` or `Default` — absence is
enforcement. The modules `sign`/`exchange`/`hex`/`base64` are free functions + constants.

---

## `krypto-cli` — for languages that are not Rust

The crate also builds a small binary, so a program in another language can use it without
reimplementing anything. The key material stays on the Rust side.

| Command | In → out |
|---|---|
| `version` *(0.6.0)* | → the crate version |
| `rand --n <bytes>` *(0.6.0)* | → CSPRNG bytes as hex (1..=1048576; for NON-secrets) |
| `seal --key-file <f> --context <s> --salt <s> [--alg <name>]` | plaintext → blob |
| `reseal --key-file <old> --new-key-file <new> --context <s> --salt <s>` *(0.6.0)* | blob → blob under a new generation (algorithm preserved); old generation against the wrong key → exit **4** |
| `open --key-file <f> --context <s> --salt <s>` | blob → plaintext |
| `mac --key-file <f> --context <s> --salt <s>` | data → hex MAC |
| `keyid --key-file <f>` | → hex key id |
| `b64-encode` / `b64-encode-nopad` | stdin bytes → base64 *(0.5.1)* |
| `b64-decode` / `b64-decode-nopad` | stdin base64 → hex *(0.5.1)* |
| `keygen --alg ed25519\|p256\|x25519 --out <f>` *(0.5.0)* | → public (hex); private key to file (0600, never overwrites) |
| `public --alg … --key-file <f>` *(0.5.0)* | → public (hex) |
| `sign --alg ed25519\|p256 --key-file <f>` *(0.5.0)* | message → signature (hex) |
| `verify --alg … --public <hex> --signature <hex>` *(0.5.0)* | message → exit 0 / 3 |
| `shared --key-file <f> --peer <hex> --out <f>` *(0.5.0)* | shared 32-byte key → file (0600), usable as `--key-file` |
| `derive-key --salt <hex> --preset <p> --out <f>` *(0.5.0)* | password on stdin → 32-byte key to file |
| `password-hash --preset <p>` / `password-verify --phc <s>` *(0.5.0)* | password on stdin → PHC / exit 0 / 3 |
| `sha256` *(0.5.0)* | data → hex |
| `blob-key-id` *(0.5.0)* | blob → key generation id (hex), no key needed |

`--alg` for `seal`: `aegis256` (default) · `xchacha20` · `aes256gcm` — valid only there. For
keygen/public/sign/verify, `--alg` is the key type. **Private key material always goes to files
(0600, never overwritten), never to stdout.** Hex arguments must be canonical (lowercase);
passwords on stdin get one trailing newline stripped.

**Exit codes are part of the contract:** `0` ok · `1` I/O or internal · `2` usage error ·
`3` authentication failed (tampering/wrong key — alert) · `4` another key generation (routing, not
tampering — *new in 0.5.0*). Errors go to stderr — never key material.

The key id in the blob header is derived deterministically from the master key (HKDF with the
context `krypto/key-id/v1`, first 16 bytes) — it identifies the generation without revealing
the key. Stdin is bounded (64 MiB). Error texts are English.

---

## Further

- **[Home](Home.md)** — what krypto is, and what it does not do
- **[Usage](Usage.md)** — how to do it, with examples
