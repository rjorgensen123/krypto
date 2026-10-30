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

It needs Python 3.11 or newer.

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
  given to `SecretBuf.from_vec` is zeroed, so prefer that.
- `expose` and `expose_str` hand the function a Python copy, which is neither locked nor wiped.
  Expose only where you must, and do not keep what you get.

Printing gives `SecretBuf([REDACTED], len=32)`. The locked-memory limit counts in the Python
process: [Secrets in memory](Usage.md#secrets-in-memory).

---

## The master key

```python
master = krypto.MasterKey.from_secret_file("/run/secrets/master_key")

key = krypto.SecretBuf.random(32)
master = krypto.MasterKey.from_bytes(key)   # consumes `key`: using it afterwards is a ValueError
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

A changed blob, or the wrong key, raises `AuthError`:

```python
tampered = blob[:-1] + bytes([blob[-1] ^ 1])
try:
    krypto.open(log_key, tampered)
except krypto.AuthError:
    pass   # tampering or the wrong key: alarm
```

The algorithms and the tampering rules: [Encrypt and decrypt](Usage.md#encrypt-and-decrypt).

---

## A small encrypted store on disk

```python
store = krypto.SecretStore.open("/data/secrets", master)

store.put("api-token", krypto.SecretBuf.from_vec(bytearray(b"token")))
token = store.get("api-token")

store.contains("api-token")   # does it exist?
store.list("api-")            # all names with this prefix
store.delete("api-token")
```

In Rust the store borrows the master key; here it keeps the `MasterKey` object alive for as long as
it lives. One handle per file holds as in Rust: a second `open` of the same file fails with
`IoError` while the first lives, and the lock goes when the handle does (`del store`). `rotate`
returns the new handle and consumes the old one:

```python
new_master = krypto.MasterKey.from_bytes(krypto.SecretBuf.random(32))
store = store.rotate(new_master)
```

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

The key forms: [Signing and verifying](Usage.md#signing-and-verifying).

---

## Agreeing on a key with a peer (X25519)

```python
from krypto_py import exchange

my_priv, my_pub = exchange.x25519_keypair()
peer_priv, peer_pub = exchange.x25519_keypair()   # in real use, peer_pub comes from the peer

material = exchange.x25519_shared(my_priv, peer_pub)
master = krypto.MasterKey.from_bytes(material)
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
| `Error::Auth` | `AuthError` | tampering, wrong key, wrong password — **the only one to alert on** |
| `Error::WrongKey` | `WrongKeyError` | another key generation: find the right key |
| `Error::Format` | `FormatError` | the input has the wrong shape |
| `Error::KeyNotFound` | `KeyNotFoundError` | the name does not exist in the store |
| `Error::Io` | `IoError` | file or disk trouble |
| `Error::Hardening` | `HardeningError` | a protection step or the environment failed |

```python
try:
    krypto.open(log_key, blob)
except krypto.AuthError:
    ...   # alarm
except krypto.Error:
    ...   # everything else krypto raises
```

Besides these, using a consumed object (after `MasterKey.from_bytes` or `rotate`) is a `ValueError`.
None of the messages carry key material or plaintext.

---

## Further

- **[How to use krypto](Usage.md)** — the how-to, with the reasons, in Rust
- **[API](API.md)** — the reference for both, and what Python cannot guarantee
- **[Home](Home.md)** — what krypto is
