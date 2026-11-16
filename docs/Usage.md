# How to use krypto

**In short:** this is the how-to, with the examples in Rust. **[Home](Home.md)** tells you what
krypto is and what you can use it for; this page shows **how** you actually do it. If you need to
look up a specific type or function, **[API](API.md)** is the reference.

From Python, the same API is **`krypto-py`**: **[How to use krypto from Python](Python.md)** has the
same sections with the Python code, and each section here links to it.

---

## Getting started

```toml
[dependencies]
krypto = "0.9"
```

And first of all in `main`, before anything else:

```rust
krypto::harden_process()?;
```

It disables core dumps and stops other processes without privileges from reading your memory;
root still can. Call it once, early. It is safe to call again, but there is no reason to.

If you want to tighten further, there are three more optional steps — each one call, each
failing hard if it cannot deliver:

```rust
krypto::no_new_privs()?;          // never gain privileges — safe for everyone, call it early
krypto::close_inherited_fds()?;   // close everything above stderr — BEFORE opening your own files
// … read your key material …
krypto::drop_filesystem("/var/empty")?; // chroot: the disk "disappears" — AFTER key reading
```

`drop_filesystem` is irreversible, needs privileges, and the directory must be empty; use one only
root can write to. If it fails, the root is as it was, and so is the working directory, unless
stepping back out of the directory fails too; then the process stays in it, and the error says so.
After it krypto needs no filesystem — randomness comes straight from the operating system, not from
`/dev`. And `close_inherited_fds` also closes sockets you inherited *on purpose* (e.g. socket
activation) — which is why it is its own choice and not part of `harden_process`. It closes the
lock of a [store](#a-small-encrypted-store-on-disk) you have already opened too, after which a
second `open` of that file succeeds, so call it before opening a store.

*In Python: [Getting started](Python.md#getting-started).*

---

## Secrets in memory

Anything secret goes into one of the two types immediately, and is never kept in an ordinary
`String` along the way.

```rust
use krypto::{SecretBuf, SecretString};

let password = SecretString::from_string(input)?;   // `input` is zeroized
let key      = SecretBuf::random(32)?;              // from the OS randomness source
```

If you actually need to *see* the contents, you have to ask — and you only get them inside a
closed block:

```rust
let length = password.expose_str(|s| s.len());
```

The reference cannot slip out of the block. That is the whole point: plaintext exists in a bounded
region, not in a variable that lives on.

**Note:** the types cannot be copied and cannot be serialized, and printing them gives you
`SecretBuf([REDACTED], len=32)`. That is not something you can turn off.

**Locked memory has a limit.** Each secret has memory pages of its own that are locked in RAM, so
every non-empty secret alive at the same time counts at least one page (usually 4 KiB) against the
process's locked-memory limit (`RLIMIT_MEMLOCK`, `ulimit -l`), decrypted plaintexts and derived
keys included; an empty one counts none. At a limit of 8 MiB that is about 2000 at once; at
64 KiB, a common default, about 16. The default differs between systems. When the limit is
reached, creating a secret fails with `Hardening`: raise the limit, which is set outside krypto
(`ulimit -l`, the service manager, or in Docker `--ulimit memlock=…`), or keep fewer secrets alive
at once. On Linux, a process with `CAP_IPC_LOCK` is not limited by it.

*(0.8.2)* **What is left on the stack.** The libraries krypto uses for encryption, HMAC, HKDF and
Argon2 leave copies of keys in the stack memory they used. krypto overwrites that stack after
`seal`, `open`, `reseal`, `derive`, `key_id`, `hmac_sha256` and the password functions. Where a
library has a `zeroize` feature, krypto turns it on, so its types wipe what they hold when they are
dropped: AES-256-GCM, XChaCha20-Poly1305 (except the Poly1305 state it makes for each message),
HMAC and SHA-256. AEGIS-256 and HKDF have no such feature: for AEGIS-256 only the overwrite removes
its copy of the key, and HKDF's state is an HMAC over SHA-256, which is wiped. Argon2 wipes only
its initial and final hash, not its working memory. It is a measure, not a guarantee: what is left
depends on the compiler, the build and the platform. Signing and key exchange are not covered.

*In Python: [Secrets in memory](Python.md#secrets-in-memory).*

---

## The master key

Everything else hangs off one master key. It comes **from outside** — never from the code.

```rust
use krypto::MasterKey;

// From a file (e.g. a Docker secret)
let master = MasterKey::from_secret_file("/run/secrets/master_key")?;

// Or from something already in memory — unpacked from a database,
// derived from a password, anything that never touches disk
let master = MasterKey::from_bytes(key)?;
```

`from_bytes` **consumes** the buffer you give it. The key cannot be read back out afterwards — not
by you, and not by anyone else.

The key file must be at least 32 bytes, and is never read more than one byte past
`MAX_MASTER_KEY_BYTES` (4 KiB), the byte that shows it is too big — a symlink to `/dev/zero` or a
bloated file cannot eat the memory.

### Derive one key per purpose

Never use the master key directly. Make a separate key for each thing you protect:

```rust
let log_key   = master.derive(b"my-app/log/v1",   &salt)?;
let store_key = master.derive(b"my-app/store/v1", &salt)?;
```

The first argument is a **context string you make up yourself**. Krypto does not know what it
means — it only guarantees that two different strings give two different keys, and that none of
them can be computed back to the master key.

Put a version number in the string (`/v1`). Then you can change it later without colliding with
old data.

*In Python: [The master key](Python.md#the-master-key).*

---

## Encrypt and decrypt

```rust
use krypto::{seal, open, Alg};

let blob = seal(&log_key, &key_id, &secret, Alg::Aegis256)?;
// blob is a plain Vec<u8> — store it wherever you like

let back = open(&log_key, &blob)?;   // gives you a SecretBuf
```

`key_id` is 16 bytes you choose yourself, carried in the blob in plaintext. It exists so you can
see **which key generation** a blob belongs to, without opening it:

```rust
let id = krypto::blob_key_id(&blob)?;   // which key do I need?
```

Note that the value is a **hint about where to look**, not proof. If someone tampered with it,
that is discovered when you call `open` — as an authentication failure, never as wrong data.

### About the algorithm choice

`Alg::Aegis256` is the default and what you should use. The other two exist because:

- `XChaCha20Poly1305` — an exit if the analysis of the default should ever turn. Same format, so
  you can switch without converting anything.
- `Aes256Gcm` — to talk to systems that require exactly that one. One key should seal at most
  2³² (about 4.3 billion) blobs with it, because its nonce is only 12 bytes; krypto does not count
  for you. If you seal more than that, use the default or derive a new key in time.

The blob says for itself which one was used, so the reader does not need to know in advance.

### The important part about tampering

The whole blob header — version, algorithm, key id and nonce — is **authenticated**. If anyone
changes a single byte of it, or of what follows, you get `Error::Auth`. Only data that is not a
krypto blob at all — shorter than the 4-byte magic, or not starting with `FAFN` — gives
`Error::Format`. *(0.9.0)* A blob that starts with `FAFN` but is cut short of the 54-byte header
gives `Auth` too. You **never** get wrong plaintext back instead.

That includes someone swapping the key id to trick you into the wrong key. That case has its own
test in the crate.

*In Python: [Encrypt and decrypt](Python.md#encrypt-and-decrypt).*

---

## A small encrypted store on disk

If you need to keep a handful of secrets under names:

```rust
use krypto::SecretStore;

let mut store = SecretStore::open("/data/secrets", &master)?;   // reads v1 and v2; a NEW store is v2 (0.9.0)

store.put("api-token", &token)?;
let token = store.get("api-token")?;

store.contains("api-token");        // does it exist?
store.list("api-");                 // all names with this prefix
store.delete("api-token")?;

store.version();                    // 1 or 2 — the file's format version (0.9.0)
store.counter();                    // the write counter (v2); 0 on a v1 store (0.9.0)
```

The store file is never read more than one byte past `MAX_STORE_BYTES` (16 MiB) — the same guard
against bloated files — and never written past it either: a `put` that would cross it fails with
`Format`. Each value is encrypted with **its own key derived from its name**. If someone moves a
value to another name in the file, `get` fails with `Auth`. Writes are atomic — either the old file
is there, or the new one, never half of one. The file gets mode 0600, and an existing one with any
other mode is set to 0600 when you open it, unless the process may not change it; then it is left
as it is. *(0.8.2)* That happens only once `open` has read the file as a store, so a file that is
not a store keeps its mode. If what is at the store path can be opened but is not a regular file —
a FIFO, a device, a directory — `open` fails with `Format`; what cannot be opened, for example for
lack of permission or because it is a socket, gives the `Io` error from opening it. A FIFO at the
store path does not make `open` wait. A symbolic link at the store path is followed, so a link to a
store file is read through; the first write replaces the link with a regular file, and the file the
link pointed to keeps its old contents.

*(0.8.2)* **A write that fails.** A write that fails before the new file is in place leaves the
file as it was, and `put` and `delete` leave the handle as it was. If only the sync of the
directory after the rename fails, `put`, `delete`, `rotate`, and an `open` that creates a new store
return `Io` although the change is in the file, and the error says so; `put` and `delete` keep the
change in the handle too. After `rotate` the file is then under the new master key, so reopen it
with that key.

*(0.9.0)* **Store file version 2: the file as a whole is sealed.** Version 1 authenticated each
entry but not the file: someone who could write it could remove an entry or put back an older
copy, and `open` noticed neither, nor did it check the master key. Version 2 adds three fields to
the header — a `key_check` (the master key, proven at `open`), a write `counter`, and a
`container_mac` over the header and all entries — so on a v2 file `open` fails with `Auth` on a
wrong key, a changed header, or a removed, swapped or injected entry. The normative format is
`spec/SPEC-secretstore.md`.

Writes keep the version the file was opened in (sticky): a v1 file stays v1, a v2 file stays v2.
To choose the version explicitly when a new store is created:

```rust
let store = SecretStore::open_with_version("/data/secrets", &master, 1)?;   // 1 or 2; anything else is Format (0.9.0)
```

**Upgrading a v1 store** is explicit, one-way and safe: every entry is decrypted and verified
first (any failure leaves the file untouched), then the file is rewritten as v2 in one atomic
write — the values are re-wrapped, not re-encrypted, because the per-name keys do not change.
Afterwards pre-0.9.0 binaries report `unsupported store version 2`.

```rust
let store = SecretStore::open("/data/secrets", &master)?;   // a v1 file
let store = store.upgrade()?;                                // v1 → v2, one-way; consumes the handle (0.9.0)
```

**Rollback detection** needs an anchor of your own — krypto is stateless and stores nothing
outside the file. The v2 `counter` rises by 1 on every write and is covered by the MAC, so it
cannot be lowered without breaking it; putting back an older copy of the whole file is what
remains, and that is what the counter catches. Keep the highest counter you have seen (a file, a
database row, your own state) and open with it:

```rust
let store = SecretStore::open_with_min_counter("/data/secrets", &master, min_counter)?;
// Err(Error::Rollback { file_counter, min_counter }) when the file's counter is lower:
// an older copy of the file may have been put back (0.9.0)
```

Without an anchor, no freshness check runs — the key check and the MAC always do on a v2 file.
`rotate` keeps the file's version, and on a v2 file resets the counter to 0 with a fresh salt and
key id.

**What the store protects.** The store protects what is in it, not the file. Without the master
key nobody can read a value, or make one that `get` accepts. The file is not sealed as a whole:
someone who can write to it can remove an entry or put back an older copy, so who may write there
is yours to decide. `open` does not check the master key — it decrypts nothing. Open with the
wrong key and `get` fails with `Auth`; a `put` with the wrong key stores that value under that
key, where only that key reads it, and `rotate` then fails with `Auth` until that entry is deleted.
*(0.9.0)* On a **v2** file this changes: the file as a whole is sealed (`container_mac`) and
`open` checks the master key (`key_check`), so a wrong key fails at `open` with `Auth`, and so
does removing or swapping an entry. What remains is putting back an older copy of the whole file —
see the counter above. On a **v1** file the old rules stand unchanged.

**One handle per file.** The store reads the whole file into memory and writes the whole file
back, so two handles on the same file would overwrite each other's writes. Making sure you open a
file only once at a time is your job. krypto also guards against it: while a handle lives, a second
`open` of the same file through the same path — in your process or another — fails with `Io`
(`WouldBlock`). You can rely on that, or also keep to one handle in your own code; that is your
choice. Drop the handle to let the next one in. The guard is a lock on an empty `.<name>.lock`
beside the path you open, which the kernel releases when the handle or the process goes, so it
never gets stuck. The same file opened through another name, such as a link, takes another lock.
*(0.8.2)* A symbolic link at the lock file's name is not followed, and something there that is not
a regular file, such as a FIFO, is not used as the lock: `open` fails with `Io` either way, and a
FIFO there does not make it wait. There is no lock only on a read-only file system, or when there
is no lock file and you may not create one in the directory. The lock does not keep out someone
who can write in the directory: they can remove or replace the lock file. Nor does it hold in two
cases inside your program, and neither gives an error. `close_inherited_fds` closes it, after
which a second `open` succeeds: call it before opening a store. After a `fork` without `exec`,
parent and child share the lock, and it is held until both copies of the handle are gone. Both can
write through their copies, and the last to write overwrites what the other wrote: open the store
after the fork, or use it in one process only.

**Rules for names:** non-empty, at most 512 bytes, printable ASCII only (`[\x20-\x7e]`). Names are
not secret — they are listed by `list()` and may end up in the caller's log. A name with a newline
could have shifted lines in someone else's log, and an empty name is nothing you can look up
again. Break the rules and you get `Format`.

**When not to use the store:** if your secrets live in a database rather than in a file, build
directly on `derive` + `seal`/`open` instead. The store solves the file problem; it is not a
general layer.

*In Python: [A small encrypted store on disk](Python.md#a-small-encrypted-store-on-disk).*

---

## Passwords

There are **two completely different jobs** here, and mixing them up is the most common mistake.

### Is the password correct? (login)

```rust
use krypto::password::{self, Preset};

let stored = password::hash(&password, Preset::Interactive)?;   // this is what you store
password::verify(&attempt, &stored)?;                           // Ok(()) = correct
```

The check takes the same time regardless of outcome, so nobody can guess their way in by
measuring the response time.

You get `Error::Auth` when the password does not match: when it is wrong, and also when the stored
string can be read but was cut short or altered. If the stored string cannot be read at all, or is
from another scheme, you get `Error::Format` — so a string krypto cannot check is not taken for a
wrong password.

*(0.8.2)* `verify` accepts only what krypto makes or can make: Argon2id, version 19 (`v=19` in the
string), with parameters from the floor up to a little above `High` — memory 64–320 MiB, t from 2
to 5, p from 1 to 5. Associated data (`data=`) in the string is accepted and used. Anything else,
such as an Argon2i or Argon2d hash from another tool, version 16, a hash made with a secret key
(`keyid=`, which krypto does not have), or numbers outside that range, also gives `Error::Format`,
before Argon2 runs. A stored string therefore cannot make one check use more memory or time than
that.

### Give me the key this password unlocks (encryption at rest)

```rust
let key = password::derive_key(&password, &salt, Preset::High)?;
let master = MasterKey::from_bytes(key)?;
```

The salt must be **at least 16 bytes** and, *(0.8.2)*, at most 1024 bytes; a longer salt gives
`Format`. It is stored in plaintext next to the data. It is not a secret — its job is to make
precomputed tables useless, and it does that just as well in the open.

> **Never store a hash next to the ciphertext here.** If the password is wrong, decryption fails
> by itself. Put a hash there too and you hand an attacker with the disk **something separate to
> guess against** — next to the data he had to crack anyway. You made his job easier, not harder.

### About the presets

You pick a **profile**, not numbers. The numbers live in krypto and must not be repeated in your
code or your documentation — that makes two places to keep in sync, and sooner or later one lies.

- `Interactive` — for login, where someone is waiting for an answer.
- `Balanced` — the middle ground: worth more than a login, not worth 256 MiB per concurrent call.
- `High` — for what is worth the most, or sits on a disk someone can walk away with.

**Store the profile's name** with the data where it is not self-evident. Then profiles can be
tuned later without old data becoming unreadable. For password hashing you do not need to think
about it — the parameters live in the stored string, and `verify` reads them from there, within
the range it accepts *(0.8.2)*.

*In Python: [Passwords](Python.md#passwords).*

---

## Putting a seal on something

If you want to prove a log line was not changed afterwards:

```rust
let seal = krypto::hmac_sha256(&log_key, line.as_bytes())?;
```

Without the key nobody can produce a valid seal, and therefore nobody can change the line
unnoticed. The usual pattern is to include the previous line's seal in the next computation — then
the whole log hangs together as a chain.

*In Python: [Putting a seal on something](Python.md#putting-a-seal-on-something).*

---

## Signing and verifying

If your service needs to prove a message came from it — or check someone else's proof — the
signature layer lives here, so you do not pull in a separate crypto library:

```rust
use krypto::sign;

// Ed25519 — raw 32-byte keys, the form public keys are usually distributed in
let (seed, public) = sign::ed25519_keypair()?;
let sig = sign::ed25519_sign(&seed, message)?;
sign::ed25519_verify(&public, message, &sig)?;        // Auth if it does not hold

// ECDSA P-256 — PKCS#8 private key, DER signature (same wire form as ring/the TLS world)
let (pkcs8, sec1_public) = sign::ecdsa_p256_keypair()?;
let der = sign::ecdsa_p256_sign(&pkcs8, message)?;
sign::ecdsa_p256_verify(&sec1_public, message, &der)?;
```

Private keys live in `SecretBuf` like everything else secret. A malformed key/signature gives
`Format`; a signature that does not hold gives `Auth` — the same split as everywhere else.

*(0.8.2)* **Which Ed25519 verifier to use:** `ed25519_verify`. It refuses the weak public keys —
the few keys of small order, for which anyone can make signatures that hold, without a private
key — with `Auth`, and a public key that is not in its one canonical encoding with `Format`. So a
yes means the signature was made with the private key behind that public key.
`ed25519_verify_relaxed` takes the same arguments and only checks that the signature equation
holds, so it accepts weak keys. It is there for a caller that must accept such keys; never use it
to check who signed with a public key you got from someone else. Keys and signatures made by krypto
verify with both.

*In Python: [Signing and verifying](Python.md#signing-and-verifying).*

## Agreeing on a key with a peer (X25519)

```rust
use krypto::exchange;

let (my_priv, my_pub) = exchange::x25519_keypair()?;
// ... exchange public keys ...
let material = exchange::x25519_shared(&my_priv, &peer_pub)?;
let master = krypto::MasterKey::from_bytes(material)?;
let salt = b"my-app-salt";                               // the same on both sides
let key = master.derive(b"my-app/envelope/v1", salt)?;   // HKDF before use — always
```

The result is keying *material*, not a key — always run it through `derive`. A malicious peer
point that would force a predictable secret is rejected with `Auth`.

*In Python: [Agreeing on a key with a peer](Python.md#agreeing-on-a-key-with-a-peer-x25519).*

## The small utilities

```rust
let fp    = krypto::sha256(cert_der);                 // fingerprint (FIPS 180-4)
let equal = krypto::ct_eq(&fp, &expected);            // constant-time comparison
let hexs  = krypto::hex::encode(&fp);                 // lowercase — one canonical form
let raw   = krypto::hex::decode(&hexs)?;              // fail-closed: rejects UPPERCASE
let salt  = krypto::random_bytes(16)?;                // for NON-secrets (salts, ids)
```

`sha256` is not authentication (use `hmac_sha256`) and not passwords (use `password`).
`random_bytes` is for values stored in the open — secrets go in `SecretBuf::random`.
Both give at most 1 MiB in one call (`MAX_RANDOM_BYTES`); asking for more is `Format`. If your
program really needs more in one call, say so with your own cap: `random_bytes_with_limit(len,
limit)` or `SecretBuf::random_with_limit(len, limit)`. The cap is per call, not a setting.

*In Python: [The small utilities](Python.md#the-small-utilities).*

---

## `krypto-cli` — a tool for testing

The crate also builds `krypto-cli`, a tool for testing, not for production. From a shell it shows
what krypto or `krypto-py` made, and how (`inspect`), checks that a blob opens, and lets you try
things out. **[krypto-cli](Cli.md)** describes it.

---

## Errors you can get

Seven kinds, and they mean different things:

| Error | When | What it means for you |
|---|---|---|
| `Auth` | tampering, wrong key, wrong password | **the only one to alert on** |
| `WrongKey` | the blob belongs to another key generation, for a caller that routes between them | find the right key — routing, not tampering *(new in 0.5.0)* |
| `Format` | input that is not what krypto takes: not a krypto blob, a malformed key, signature or PHC string, a wrong parameter | the data is wrong, not the key — a changed blob is `Auth` |
| `KeyNotFound` | the name does not exist in the store | normal, not an error condition |
| `Rollback` | *(0.9.0)* `open_with_min_counter`: the store file's counter is below the minimum you passed | an older copy of the file may have been put back — alarm |
| `Io` | file/disk trouble | the environment, not the crypto |
| `Hardening` | a protection step failed: locked memory, randomness, process hardening | the environment, never your data |

None of them carry key material or plaintext. You can log them as they are.

*In Python: [Errors you can get](Python.md#errors-you-can-get).*

---

## Changelog

| Version | What arrived |
|---|---|
| **0.9.0** | **Store file format v2** (`spec/SPEC-secretstore.md`): the whole file is authenticated (`container_mac`), the master key is checked at `open` (`key_check`), and a write counter enables rollback detection (`open_with_min_counter`, `Error::Rollback`) · new stores are v2, an opened file keeps its version · `upgrade()` (v1 → v2, one-way), `open_with_version`, `version()`, `counter()` · `rotate` keeps the version and resets the counter on v2 · a blob cut short of its 54-byte header past the `FAFN` magic now gives `Auth`, not `Format` · `SecretStore::put` checks the 16 MiB cap on the prospective file size before sealing |
| **0.8.1** | No functional change: the documentation is corrected where it said more than the code does, a test file no longer names the machine it was made on, and the Python packages carry no paths from the machine that built them |
| **0.8.0** | **Python: `krypto-py`.** The same API from Python, built from the same code: what one seals, the other opens; one API reference, with the guarantees that differ set apart · `MasterKey::key_id` in the library, the value `krypto-cli` has always used · the repository is a workspace of `krypto` and `krypto-py` · `krypto-cli` is a small helper with nine commands |
| **0.7.3** | `drop_filesystem` changes the root only as its last step, on the directory it checked; when it fails, the root is as it was, and so is the working directory unless stepping back fails too · every change to a blob past its `FAFN` magic gives `Auth` (`krypto-cli` exit 3, though `krypto-cli open` gives 4 for a changed key id), and `SecretStore::get` gives `Auth` for a key id that does not match · an empty `info` for `derive` is `Format` · random bytes are capped at 1 MiB per call, with your own cap as an option |
| **0.7.2** | **Secret memory and the current RustCrypto line.** The dependencies moved to the current RustCrypto line (RUSTSEC-2026-0387), and Rust 1.89 is the minimum · each secret has memory pages of its own: kept out of core dumps, still locked when another secret is dropped, with a guard page on each side (note: each live secret uses at least one page of the locked-memory limit) · the password functions and `derive` wipe what argon2 and HKDF leave on the stack, and derived keys are written straight into locked memory · the per-key limit of AES-256-GCM is documented |
| **0.7.1** | No functional change: the install snippets point at crates.io, and the published crate no longer carries the CI configuration |
| **0.7.0** | **First release on crates.io.** `SecretBuf::from_vec` wipes its source even when locking fails · `info` and `salt` for `derive` are capped (`MAX_DERIVE_INPUT_BYTES`), and `MasterKey::from_bytes` caps the key like the file route · the store checks names when it reads a file too (see below) |
| **0.6.2** | **Hardening step 2:** `no_new_privs`, `close_inherited_fds` and `drop_filesystem` — separate, optional, fail-closed calls |
| **0.6.1** | Documentation and tooling: the doc guard covers the cli commands too |
| **0.6.0** | **Key rotation:** `reseal` (blob → blob under a new key generation; the algorithm is preserved) and `SecretStore::rotate` (the whole store, atomically — never half-rotated), + `krypto-cli reseal`. Both keys come from you — krypto is stateless and never owns keys · The `VERSION` constant + `krypto-cli version` (About pages at the consumers) · `krypto-cli rand` (CSPRNG for non-secrets — the Python side must not roll its own source) · `Balanced` adjusted to p=3 (note: `derive_key` with Balanced yields a different key than 0.5.x) · dependency auditing and memory verification in CI (cargo-deny, Miri, ASan) |
| **0.5.1** | Canonical base64 (the `base64` module + four `b64-*` cli commands) — for formats that ARE base64 by nature (ssh fingerprints, PEM); the canon is still hex |
| **0.5.0** | **First major revision.** The whole API in English (`utled_noekkel` → `derive_key`, `Moderate` → `High`; all error messages English) · new middle preset `Balanced` · the `WrongKey` error and exit code 4, so an old key generation no longer triggers a tampering alarm · official test vectors for all three algorithms — which **revealed and fixed** that AEGIS-256 had key and nonce swapped: AEGIS blobs from ≤ 0.4.4 must be re-encrypted · version guard test · **new modules:** `sign` (Ed25519 + ECDSA P-256, ring-compatible), `exchange` (X25519), `hex` (canonical), plus `sha256`/`ct_eq`/`random_bytes` — so no consumer rolls its own layer |
| **0.4.4** | The master key can be built from bytes in memory, not only from a file — for keys that never touch disk |
| **0.4.3** | Key derivation from a password (job #2 under "Passwords") · reading a blob's key generation without opening it · store names validated on character set, not only length · an empty context string is rejected instead of yielding a key |
| **0.4.2** | Caps on how much is read from files and input — a corrupt or hostile file cannot eat the memory |
| **0.4.1** | Robustness round without API changes: the store now distinguishes "does not exist" from "cannot read" (a permission error could previously cause silent data loss), writes roll back if they fail halfway, temporary files are private from the first moment, and the password check says `Format` instead of calling an invalid hash a "wrong password" |
| **0.4.0** | AES-256-GCM as the third algorithm · keyed seals · the command-line tool |
| **0.3.0** | The encrypted store on disk · password hashing |
| **0.2.0** | Encryption, the blob format, master key and key derivation |
| **0.1.0** | The two secret types · process hardening |

One older exception is worth knowing: **0.4.3 tightened which names the store accepts** (see the
rules above). If your code writes names with e.g. `æøå`, or names longer than 512 bytes, `put`
will start failing. Since 0.7.0 the same rules are checked when a store file is read, so a file
that still holds such a name no longer opens: `SecretStore::open` returns `Format`. Move those
entries to valid names (`get`, `put`, `delete`) with a release before 0.7.0 before you upgrade.
