# How to use krypto from Python

**In short:** `krypto-py` is krypto in Python *(0.8.0)*. It has the same functions, types,
constants and modules as the Rust crate, with the same names, and the same Rust code runs inside
it. What you seal in Rust, you open in Python, and the other way round.

This page shows the Python code. The *why* behind each part is the same in both languages and
lives in **[How to use krypto](Usage.md)**, the Rust how-to; each section here links to its
counterpart there. **[API](API.md)** is the reference for both, and its section on
[what differs](API.md#what-is-guaranteed-and-where-python-differs) says exactly what Python cannot
guarantee.

---

## Getting started

```sh
pip install krypto-py
```

It needs Python 3.11 or newer, and is tested with 3.11 and 3.12. *(0.8.2)* The module declares that
it needs the GIL (`gil_used = true`), because krypto-py is built and tested only with Python that
has the GIL; it is not tested on a free-threaded Python.

```python
import krypto_py as krypto

krypto.harden_process()   # first thing, as in Rust's main
```

Hardening works on the whole Python process. The optional steps are the same as in Rust:

```python
krypto.no_new_privs()
krypto.close_inherited_fds()            # the interpreter's own descriptors too: call it before anything is opened
# … read your key material …
krypto.drop_filesystem("/var/empty")    # irreversible; needs privileges
```

`close_inherited_fds` also closes the lock of a `SecretStore` that is already open, after which a
second `open` of that file succeeds: call it before opening a store.

Why, and in what order: [Getting started](Usage.md#getting-started).

---

## Secrets in memory

```python
password = krypto.SecretString.from_string("correct horse battery staple")
key = krypto.SecretBuf.random(32)
token = krypto.SecretBuf.from_vec(bytearray(b"api-token"))   # the bytearray is zeroed after the copy

length = password.expose_str(len)    # the function gets the text and its result comes back
```

The secret itself lives in Rust's locked memory, as in Rust. Two things are Python's own:

- What you pass in stays as Python keeps it. A `str` or `bytes` cannot be wiped; a `bytearray`
  given to `SecretBuf.from_vec` is zeroed, also when the call fails, so prefer that.
- `expose` and `expose_str` hand the function a Python copy, which is neither locked nor wiped.
  Expose only where you must, and do not keep what you get.

Printing gives `SecretBuf([REDACTED], len=32)`. The locked-memory limit counts in the Python
process: [Secrets in memory](Usage.md#secrets-in-memory).

---

## The master key

```python
master = krypto.MasterKey.from_secret_file("/run/secrets/master_key")

key = krypto.SecretBuf.random(32)
master = krypto.MasterKey.from_bytes(key)   # consumes `key`, also when it fails: using it afterwards is a ValueError
```

### Derive one key per purpose

```python
salt = b"per-store-salt"
log_key = master.derive(b"my-app/log/v1", salt)
store_key = master.derive(b"my-app/store/v1", salt)
key_id = master.key_id()   # 16 bytes: which key generation this is
```

The context and the salt are `bytes`, as in Rust. Why one key per purpose:
[Derive one key per purpose](Usage.md#derive-one-key-per-purpose).

---

## Encrypt and decrypt

```python
secret = krypto.SecretBuf.from_vec(bytearray(b"api-token"))
blob = krypto.seal(log_key, key_id, secret, krypto.Alg.Aegis256)   # bytes: store it wherever you like

back = krypto.open(log_key, blob)   # a SecretBuf: the plaintext stays locked until exposed
assert krypto.blob_key_id(blob) == key_id
```

*(0.9.0)* To bind a blob to a context without putting it in the plaintext, pass AAD — it is not
stored in the blob, so supply the same value when opening (a wrong one raises `AuthError`):

```python
aad_blob = krypto.seal_with_aad(log_key, key_id, secret, krypto.Alg.Aegis256, b"record/42")
back = krypto.open_with_aad(log_key, aad_blob, b"record/42")
```

The AAD is at most `krypto.MAX_AAD_BYTES` (1024) bytes; a longer one raises `FormatError`. It is
public data to krypto — held in ordinary memory, not locked and not wiped — so nothing secret
belongs in it.

A changed blob, or the wrong key, raises `AuthError`:

```python
tampered = blob[:-1] + bytes([blob[-1] ^ 1])
try:
    krypto.open(log_key, tampered)
except krypto.AuthError:
    pass   # tampering or the wrong key: alarm
```

*(0.9.0)* A blob that starts with `FAFN` but is cut short of its 54-byte header raises
`AuthError` too, not `FormatError` — the alarm class is no longer the tamperer's choice. Only data
that cannot carry the magic (shorter than 4 bytes, or not starting with `FAFN`) is `FormatError`.

The algorithms and the tampering rules: [Encrypt and decrypt](Usage.md#encrypt-and-decrypt).

---

## A small encrypted store on disk

```python
store = krypto.SecretStore.open("/data/secrets", master)   # reads v1 and v2; a new store is v2

store.put("api-token", krypto.SecretBuf.from_vec(bytearray(b"token")))
token = store.get("api-token")

store.contains("api-token")   # does it exist?
store.list("api-")            # all names with this prefix
store.delete("api-token")
store.key_id()                # the store's key_id, 16 bytes, not secret
```

In Rust the store borrows the master key; here it keeps the `MasterKey` object alive for as long as
it lives. One handle per file holds as in Rust, with the same limits: a second `open` of the same
file through the same path fails with `IoError` while the first lives, and the lock goes when the
handle does (`del store`). The lock does not protect against two things, and neither gives an
error. `close_inherited_fds` closes it, after which a second `open` succeeds; call it before
opening a store. After `os.fork()`, also in `multiprocessing` with the fork start method, parent
and child share the lock, and it is held until both copies of the handle are gone. Both can write
through their copies, and the last to write overwrites what the other wrote. Open the store after
the fork, or use it in one process only.

`rotate` returns the new handle and consumes the old one:

```python
new_master = krypto.MasterKey.from_bytes(krypto.SecretBuf.random(32))
store = store.rotate(new_master)
```

When the rotation itself fails, the old handle is consumed all the same: using it is a `ValueError`.
Open the file again; it is unchanged, still under the old master key, except in one case
*(0.8.2)*: if only the sync of the directory after the rename failed, the `IoError` says the file
is under the new master key; reopen it with that key. *(0.9.0)* `rotate` keeps the file's version,
and on a v2 file resets the write counter to 0 with a fresh salt and key id.

*(0.9.0)* **Store file version 2.** The store file has a format version, 1 or 2. `open` reads both
and creates a **v2** store when the file is new. On a v2 file the whole file is sealed (a
container MAC over the header and all entries) and the master key is checked at `open`, so a
master key that does not fit raises `WrongKeyError` from `open` itself, and a file that is not
what was written, such as one with a removed, swapped or injected entry, raises `AuthError`. A
changed salt or key check raises `WrongKeyError` too, so if you know your key is the right one,
treat it as a changed file. On a v1 file the old rule stands: `open` checks nothing, and a wrong
key raises `AuthError` from `get`.

```python
store.version()    # 1 or 2 — the file's format version
store.counter()    # the write counter (v2); 0 on a v1 store

store = krypto.SecretStore.open_with_version("/data/secrets", master, 1)        # v1 only, created as v1 when new; a v2 file is FormatError
store = krypto.SecretStore.open_with_min_counter("/data/secrets", master, seen)  # v2 only; RollbackError if the file is older
store = store.upgrade()                                                          # v1 → v2, one-way; consumes the handle
krypto.SecretStore.key_id_from_file("/data/secrets")                             # the key_id the file says it has, not authenticated
```

Writes keep the file's version. An open that names a version accepts only a file of that version;
`open` cannot tell a v1 file from a v2 file that has been made into one, so if you rely on what v2
adds, name version 2. `upgrade` verifies every entry first (any failure leaves the file untouched,
and the handle is consumed all the same) and rewrites the file as v2 in one atomic write — the
values are re-wrapped, not re-encrypted. For rollback detection, keep the store's `key_id()` and
`counter()` outside the file after each write; when you open it, pass that counter to
`open_with_min_counter` and check that `key_id()` is the one you kept. `RollbackError` means an
older copy of the file may have been put back. A rotation or an upgrade starts the counter at 0;
start your anchor again from there. With an anchor above 0, a missing file raises `IoError` and
nothing is created. Without an anchor, no freshness check runs — the key check and the MAC always
do on a v2 file. At its maximum the counter does not wrap: `put` and `delete` raise
`HardeningError` and write nothing, and the store must be rotated. `key_id_from_file` reads the
header only, without the master key: `IoError` if the file cannot be opened, `FormatError` if it is
not a store file.

As in Rust, the store protects its contents, not the file, and `open` does not check the master
key on a v1 file: a wrong one raises `AuthError` from `get`.

The rest of the rules: [A small encrypted store on disk](Usage.md#a-small-encrypted-store-on-disk).

---

## Passwords

```python
from krypto_py import password
from krypto_py.password import Preset

attempt = krypto.SecretString.from_string("correct horse battery staple")
stored = password.hash(attempt, Preset.Interactive)    # this is what you store
password.verify(attempt, stored)                       # AuthError if the password is wrong

salt = krypto.random_bytes(16)
key = password.derive_key(attempt, salt, Preset.High)
master = krypto.MasterKey.from_bytes(key)
```

The three functions let other Python threads run while Argon2 works. The two jobs, and the presets:
[Passwords](Usage.md#passwords).

*(0.8.2)* `password.verify` accepts only what krypto makes or can make: Argon2id, version 19, with
parameters within the range in [Passwords](Usage.md#passwords), and associated data if the string
carries it. Any other stored string, such as an Argon2i hash from another tool or one made with a
secret key (`keyid=`), raises `FormatError`, before Argon2 runs.

`password.derive_key` takes a salt of at least 16 bytes and, *(0.8.2)*, at most 1024; outside that
it raises `FormatError`.

---

## Putting a seal on something

```python
seal = krypto.hmac_sha256(log_key, b"a log line")
```

How a chain of seals works: [Putting a seal on something](Usage.md#putting-a-seal-on-something).

---

## Signing and verifying

```python
from krypto_py import sign

seed, public = sign.ed25519_keypair()
sig = sign.ed25519_sign(seed, b"message")
sign.ed25519_verify(public, b"message", sig)       # AuthError if it does not hold

pkcs8, sec1_public = sign.ecdsa_p256_keypair()
der = sign.ecdsa_p256_sign(pkcs8, b"message")
sign.ecdsa_p256_verify(sec1_public, b"message", der)
```

*(0.8.2)* `sign.ed25519_verify` is strict: a weak (small-order) public key, for which anyone can
make signatures, is an `AuthError`, and a public key that is not canonically encoded is a
`FormatError`. `sign.ed25519_verify_relaxed` takes the same arguments and only checks that the
signature equation holds, so it accepts weak keys; use it only when you must accept such keys,
never to check who signed with a public key you got from someone else.

The key forms, and which verifier to use: [Signing and verifying](Usage.md#signing-and-verifying).

---

## Agreeing on a key with a peer (X25519)

```python
from krypto_py import exchange

my_priv, my_pub = exchange.x25519_keypair()
peer_priv, peer_pub = exchange.x25519_keypair()   # in real use, peer_pub comes from the peer

material = exchange.x25519_shared(my_priv, peer_pub)
master = krypto.MasterKey.from_bytes(material)
salt = b"my-app-salt"                              # the same on both sides
key = master.derive(b"my-app/envelope/v1", salt)   # always derive before use
```

Why the material is not a key: [Agreeing on a key with a peer](Usage.md#agreeing-on-a-key-with-a-peer-x25519).

---

## The small utilities

```python
fp = krypto.sha256(b"certificate bytes")    # fingerprint
equal = krypto.ct_eq(fp, fp)                # constant-time comparison
hexs = krypto.hex.encode(fp)                # lowercase, one canonical form
raw = krypto.hex.decode(hexs)               # rejects uppercase
salt = krypto.random_bytes(16)              # for values that are NOT secrets
```

The caps on random bytes, and your own cap: [The small utilities](Usage.md#the-small-utilities).

---

## Errors you can get

Each kind is an exception, all under `krypto.Error`:

| Rust | Python | What it means for you |
|---|---|---|
| `Error::Auth` | `AuthError` | tampering, wrong key, wrong password; at the open of a v2 store, a file that is not what was written — **alert on it** |
| `Error::WrongKey` | `WrongKeyError` | the key does not fit: for a blob, another key generation, so find the right key; at the open of a v2 store, a master key that does not fit the file |
| `Error::Format` | `FormatError` | the input has the wrong shape, such as a file that is not a store file or a store of another version than the open names |
| `Error::KeyNotFound` | `KeyNotFoundError` | the name does not exist in the store |
| `Error::Rollback` *(0.9.0)* | `RollbackError` | `SecretStore.open_with_min_counter`: the file's counter is below your minimum — an older copy may be back; the attributes `file_counter` and `min_counter` hold both |
| `Error::Io` | `IoError` | file or disk trouble; a missing store file for `open_with_min_counter` above 0 |
| `Error::Hardening` | `HardeningError` | a protection step or the environment failed; or a store whose counter is at its maximum, which must be rotated |

```python
try:
    krypto.open(log_key, blob)
except krypto.AuthError:
    ...   # alarm
except krypto.Error:
    ...   # everything else krypto raises
```

Besides these, using a consumed object (after `MasterKey.from_bytes`, `rotate` or `upgrade`, also
when the operation itself failed) is a `ValueError`; an argument of the wrong type is rejected with
`TypeError` before anything is consumed. None of the messages carry key material or plaintext.

A panic in the Rust code surfaces as `pyo3_runtime.PanicException`. It derives from
`BaseException`, not `Exception`, so neither `except krypto.Error` nor `except Exception` catches it.

---

## Further

- **[How to use krypto](Usage.md)** — the how-to, with the reasons, in Rust
- **[API](API.md)** — the reference for both, and what Python cannot guarantee
- **[Home](Home.md)** — what krypto is
