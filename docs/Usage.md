# How to use krypto

**In short:** this is the how-to. **[Home](Home.md)** tells you what krypto is and what you can
use it for; this page shows **how** you actually do it, with examples. If you need to look up a
specific type or function, **[API](API.md)** is the reference.

---

## Getting started

```toml
[dependencies]
krypto = "0.6"
```

And first of all in `main`, before anything else:

```rust
krypto::harden_process()?;
```

It disables core dumps and stops other processes from reading your memory. Call it once, early.
It is safe to call again, but there is no reason to.

If you want to tighten further, there are three more optional steps — each one call, each
failing hard if it cannot deliver:

```rust
krypto::no_new_privs()?;          // never gain privileges — safe for everyone, call it early
krypto::close_inherited_fds()?;   // close everything inherited above stderr — BEFORE opening your own files
// … read your key material …
krypto::drop_filesystem("/var/empty")?; // chroot: the disk "disappears" — AFTER key reading
```

`drop_filesystem` is irreversible, needs privileges, and the directory must be empty. After it
krypto needs no filesystem — randomness comes straight from the operating system, not from
`/dev`. And `close_inherited_fds` also closes sockets you inherited *on purpose* (e.g. socket
activation) — which is why it is its own choice and not part of `harden_process`.

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

The key file must be at least 32 bytes, and is never read past `MAX_MASTER_KEY_BYTES` (4 KiB) — a
symlink to `/dev/zero` or a bloated file cannot eat the memory.

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
- `Aes256Gcm` — to talk to systems that require exactly that one.

The blob says for itself which one was used, so the reader does not need to know in advance.

### The important part about tampering

The whole blob header — magic, version, algorithm, key id and nonce — is **authenticated**. If
anyone changes a single byte, you get `Error::Auth`. You **never** get wrong plaintext back
instead.

That includes someone swapping the key id to trick you into the wrong key. That case has its own
test in the crate.

---

## A small encrypted store on disk

If you need to keep a handful of secrets under names:

```rust
use krypto::SecretStore;

let mut store = SecretStore::open("/data/secrets", &master)?;

store.put("api-token", &token)?;
let token = store.get("api-token")?;

store.contains("api-token");        // does it exist?
store.list("api-");                 // all names with this prefix
store.delete("api-token")?;
```

The store file is never read past `MAX_STORE_BYTES` (16 MiB) — the same guard against bloated
files. Each value is encrypted with **its own key derived from its name**. If someone moves a value to
another name in the file, `get` fails with `Auth`. Writes are atomic — either the old file is
there, or the new one, never half of one. The file gets mode 0600.

**Rules for names:** non-empty, at most 512 bytes, printable ASCII only (`[\x20-\x7e]`). Names are
not secret — they are listed by `list()` and may end up in the caller's log. A name with a newline
could have shifted lines in someone else's log, and an empty name is nothing you can look up
again. Break the rules and you get `Format`.

**When not to use the store:** if your secrets live in a database rather than in a file, build
directly on `derive` + `seal`/`open` instead. The store solves the file problem; it is not a
general layer.

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

You get `Error::Auth` **only** when the password is actually wrong. If the stored string is
corrupt or from another system, you get `Error::Format` — so you can tell "wrong password" from
"something is wrong with my data".

### Give me the key this password unlocks (encryption at rest)

```rust
let key = password::derive_key(&password, &salt, Preset::High)?;
let master = MasterKey::from_bytes(key)?;
```

*(Named `utled_noekkel` before 0.5.0 — same behavior, English name.)*

The salt must be **at least 16 bytes** and is stored in plaintext next to the data. It is not a
secret — its job is to make precomputed tables useless, and it does that just as well in the open.

> **Never store a hash next to the ciphertext here.** If the password is wrong, decryption fails
> by itself. Put a hash there too and you hand an attacker with the disk **something separate to
> guess against** — next to the data he had to crack anyway. You made his job easier, not harder.

### About the presets

You pick a **profile**, not numbers. The numbers live in krypto and must not be repeated in your
code or your documentation — that makes two places to keep in sync, and sooner or later one lies.

- `Interactive` — for login, where someone is waiting for an answer.
- `Balanced` — the middle ground: worth more than a login, not worth 256 MiB per concurrent call.
- `High` — for what is worth the most, or sits on a disk someone can walk away with.
  *(Named `Moderate` before 0.5.0 — same numbers, honest name: it was never a middle option.)*

**Store the profile's name** with the data where it is not self-evident. Then profiles can be
tuned later without old data becoming unreadable. For password hashing you do not need to think
about it — the parameters live in the stored string, and `verify` reads them from there.

---

## Putting a seal on something

If you want to prove a log line was not changed afterwards:

```rust
let seal = krypto::hmac_sha256(&log_key, line.as_bytes())?;
```

Without the key nobody can produce a valid seal, and therefore nobody can change the line
unnoticed. The usual pattern is to include the previous line's seal in the next computation — then
the whole log hangs together as a chain.

---

## Signing and verifying

If your service needs to prove a message came from it — or check someone else's proof — the
signature layer lives here, so you do not pull in a separate crypto library:

```rust
use krypto::sign;

// Ed25519 — raw 32-byte keys, the form the services distribute
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

## Agreeing on a key with a peer (X25519)

```rust
use krypto::exchange;

let (my_priv, my_pub) = exchange::x25519_keypair()?;
// ... exchange public keys ...
let material = exchange::x25519_shared(&my_priv, &peer_pub)?;
let master = krypto::MasterKey::from_bytes(material)?;
let key = master.derive(b"my-app/envelope/v1", salt)?;   // HKDF before use — always
```

The result is keying *material*, not a key — always run it through `derive`. A malicious peer
point that would force a predictable secret is rejected with `Auth`.

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

---

## From languages other than Rust

The crate ships a command-line tool. The point is that you do **not roll your own crypto** in the
other language — two implementations that must agree eventually disagree.

```bash
krypto-cli version                                                               # the crate version (new in 0.6.0)
krypto-cli rand --n 16                                                           # 16 CSPRNG bytes as hex — salts/ids, NOT secrets (new in 0.6.0)

# Encryption and seals (as before)
krypto-cli seal  --key-file <file> --context <str> --salt <str> [--alg <name>]  # plaintext in → blob out
krypto-cli open  --key-file <file> --context <str> --salt <str>                 # blob in → plaintext out
krypto-cli mac   --key-file <file> --context <str> --salt <str>                 # data in → seal out
krypto-cli keyid --key-file <file>                                              # which key generation
krypto-cli reseal --key-file <old> --new-key-file <new> --context <s> --salt <s>     # key rotation (0.6.0)

# Signatures and key agreement (new in 0.5.0 — the same surface as the Rust API)
krypto-cli keygen --alg ed25519 --out private.key                               # → public (hex); private key to file
krypto-cli sign   --alg ed25519 --key-file private.key < message                # → signature (hex)
krypto-cli verify --alg ed25519 --public <hex> --signature <hex> < message      # exit 0 = holds, 3 = does not
krypto-cli shared --key-file mine.key --peer <peer-public-hex> --out shared.key # shared key → file

# Passwords (new in 0.5.0; password on stdin — one trailing newline stripped)
krypto-cli derive-key --salt <hex> --preset high --out lock.key                 # password → 32-byte key file
krypto-cli password-hash --preset interactive                                   # password → PHC string
krypto-cli password-verify --phc '<string>'                                     # exit 0 = right, 3 = wrong

krypto-cli sha256 < file                                                         # → hex fingerprint
krypto-cli b64-encode < file                                                     # bytes → base64 (0.5.1; -nopad for the ssh form)
krypto-cli b64-decode                                                            # base64 on stdin → hex (0.5.1; -nopad variant exists)
krypto-cli blob-key-id < blob                                                    # which key generation? (after exit 4)
```

Data goes in on stdin and out on stdout. `--context` and `--salt` (seal/open/mac) are the same
values you would give `derive`. `--alg` for seal is `aegis256` (default), `xchacha20` or
`aes256gcm`; for keygen/public/sign/verify it is the key type.

**Private key material never leaves the tool** — it never enters the calling process.
`keygen`/`shared`/`derive-key` write to files (mode 0600, and **never** over an existing file);
the file from `shared`/`derive-key` is 32 bytes and usable directly as `--key-file` for
seal/open/mac. Only public keys, signatures, hashes, blobs and requested plaintext go to stdout.
Hex arguments must be canonical (lowercase).

Check the exit code; it is split on purpose:

| Code | Means | What to do |
|---|---|---|
| `1` | I/O or internal error | log and retry |
| `2` | you called it wrong | fix the call |
| **`3`** | **authentication failure** | **someone tampered with the data, or the key is wrong — this should be alerted on** |
| `4` | the blob belongs to another key generation | find the right key (see `keyid`) — routing, not tampering *(new in 0.5.0)* |

Error messages go to stderr and never contain key material.

---

## Errors you can get

Six kinds, and they mean different things:

| Error | When | What it means for you |
|---|---|---|
| `Auth` | tampering, wrong key, wrong password | **the only one to alert on** |
| `WrongKey` | the blob belongs to another key generation | find the right key — routing, not tampering *(new in 0.5.0)* |
| `Format` | unrecognizable or corrupt input | the data is wrong, not the key |
| `KeyNotFound` | the name does not exist in the store | normal, not an error condition |
| `Io` | file/disk trouble | the environment, not the crypto |
| `Hardening` | hardening failed | the environment lacks privileges |

None of them carry key material or plaintext. You can log them as they are.

---

## Changelog

| Version | What arrived |
|---|---|
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

**Upgrading to 0.5.0:** two names changed (`utled_noekkel` → `derive_key`, `Preset::Moderate` →
`Preset::High`) — the compiler shows you every call site. Error messages are English; if your code
matches on Norwegian substrings, adjust it. And **AEGIS blobs made before 0.5.0 must be
re-encrypted** (open with 0.4.x, reseal with 0.5.0); XChaCha and AES-GCM blobs are unaffected. The
blob format itself has been stable since 0.2. The full Norwegian ⇄ English table is in the
repository changelog.

One older exception is worth knowing: **0.4.3 tightened which names the store accepts** (see the
rules above). If your code writes names with e.g. `æøå`, or names longer than 512 bytes, `put`
will start failing. Existing data is unaffected — validation happens only on writes, so old names
can still be read, listed and deleted.

---

## What does not exist yet

- **Key rotation.** The format is prepared — every blob carries its key generation — but actually
  switching keys and re-encrypting is not built.
- **A direct Python binding.** Today that path goes through the command-line tool.
