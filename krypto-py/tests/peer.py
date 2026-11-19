# SPDX-License-Identifier: MIT OR Apache-2.0
"""The Python side of `interop.rs`: krypto_py on what Rust wrote (0.8.0).

    python -I peer.py <mode> <dir>

It opens and checks what Rust wrote to `<dir>/rust/`, and writes what Python
makes, and its answers to the same inputs, to `<dir>/python/` for Rust to
check. The stores lie in `<dir>` itself; a mode ending in `-back` checks what
Rust did with what Python made. A failed check is an exception, and a non-zero
exit.
"""

import sys
from pathlib import Path

import krypto_py as k
from krypto_py import base64, exchange, hex, password, sign

CONTEXT = b"interop/v1"
SALT = b"interop-salt"
AAD = b"record/42"
OTHER_AAD = b"record/43"
NEW_AAD = b"record/44"
PASSWORD = "correct horse battery staple"
ALGS = {"aegis256": k.Alg.Aegis256, "xchacha20": k.Alg.XChaCha20Poly1305, "aes256gcm": k.Alg.Aes256Gcm}


def seal(d):
    rust, out = d / "rust", d / "python"
    master = k.MasterKey.from_secret_file(str(d / "master.key"))
    master2 = k.MasterKey.from_secret_file(str(d / "master2.key"))
    message = (d / "message").read_bytes()
    key, key2 = master.derive(CONTEXT, SALT), master2.derive(CONTEXT, SALT)

    for name in ALGS:
        assert k.open(key, (rust / f"blob-{name}").read_bytes()).expose(bytes) == message, name
    assert k.open(key2, (rust / "resealed").read_bytes()).expose(bytes) == message, "resealed"
    store = k.SecretStore.open(str(d / "shared.store"), master)
    assert store.get("from-rust").expose(bytes) == message, "store"
    store.put("from-python", k.SecretBuf.from_vec(message))
    del store

    for name, alg in ALGS.items():
        (out / f"blob-{name}").write_bytes(k.seal(key, master.key_id(), k.SecretBuf.from_vec(message), alg))
    (out / "resealed").write_bytes(k.reseal(key, key2, master2.key_id(), (out / "blob-aegis256").read_bytes()))
    (out / "key-id").write_bytes(master.key_id())
    (out / "hmac").write_bytes(k.hmac_sha256(key, message))


def keys(d):
    rust, out = d / "rust", d / "python"
    message = (d / "message").read_bytes()
    pw = k.SecretString.from_string(PASSWORD)

    password.verify(pw, (rust / "phc").read_text())
    (out / "phc").write_text(password.hash(pw, password.Preset.Interactive))
    derived = password.derive_key(pw, (d / "pw-salt").read_bytes(), password.Preset.Interactive)
    (out / "derived-key").write_bytes(derived.expose(bytes))

    seed = k.SecretBuf.from_vec((rust / "ed25519.seed").read_bytes())
    sign.ed25519_verify((rust / "ed25519.public").read_bytes(), message, (rust / "ed25519.sig").read_bytes())
    (out / "ed25519.public-of-rust").write_bytes(sign.ed25519_public(seed))
    (out / "ed25519.sig-of-rust").write_bytes(sign.ed25519_sign(seed, message))
    own_seed, own_public = sign.ed25519_keypair()
    (out / "ed25519.public").write_bytes(own_public)
    (out / "ed25519.sig").write_bytes(sign.ed25519_sign(own_seed, message))

    pkcs8 = k.SecretBuf.from_vec((rust / "p256.pkcs8").read_bytes())
    sign.ecdsa_p256_verify((rust / "p256.public").read_bytes(), message, (rust / "p256.sig").read_bytes())
    (out / "p256.public-of-rust").write_bytes(sign.ecdsa_p256_public(pkcs8))
    own_pkcs8, own_p256_public = sign.ecdsa_p256_keypair()
    (out / "p256.public").write_bytes(own_p256_public)
    (out / "p256.sig").write_bytes(sign.ecdsa_p256_sign(own_pkcs8, message))

    x_secret, x_public = exchange.x25519_keypair()
    (out / "x25519.public").write_bytes(x_public)
    shared = exchange.x25519_shared(x_secret, (rust / "x25519.public").read_bytes())
    (out / "x25519.shared").write_bytes(shared.expose(bytes))

    (out / "sha256").write_bytes(k.sha256(message))
    (out / "hex").write_text(hex.encode(message))
    (out / "base64").write_text(base64.encode(message))


def raises(error, call, *args):
    """The exception `call(*args)` raises, which must be `error`."""
    try:
        call(*args)
    except error as e:
        return e
    raise AssertionError(f"{call.__name__} did not raise {error.__name__}")


def bound_to_aad(key, blob, aad, other_aad, message, what):
    """`blob` opens under `key` with `aad`, and is `AuthError` with
    `other_aad`, with an empty AAD and through `open`, which takes none."""
    assert k.open_with_aad(key, blob, aad).expose(bytes) == message, what
    for wrong in (other_aad, b""):
        raises(k.AuthError, k.open_with_aad, key, blob, wrong)
    raises(k.AuthError, k.open, key, blob)


def aad(d):
    rust, out = d / "rust", d / "python"
    master = k.MasterKey.from_secret_file(str(d / "master.key"))
    master2 = k.MasterKey.from_secret_file(str(d / "master2.key"))
    message = (d / "message").read_bytes()
    key, key2 = master.derive(CONTEXT, SALT), master2.derive(CONTEXT, SALT)

    for name in ALGS:
        bound_to_aad(key, (rust / f"aad-blob-{name}").read_bytes(), AAD, OTHER_AAD, message, name)
    bound_to_aad(key2, (rust / "aad-resealed").read_bytes(), NEW_AAD, AAD, message, "resealed")

    for name, alg in ALGS.items():
        blob = k.seal_with_aad(key, master.key_id(), k.SecretBuf.from_vec(message), alg, AAD)
        (out / f"aad-blob-{name}").write_bytes(blob)
    rust_blob = (rust / "aad-blob-aegis256").read_bytes()
    (out / "aad-resealed").write_bytes(k.reseal_with_aad(key, key2, master2.key_id(), rust_blob, AAD, NEW_AAD))


def aad_back(d):
    master2 = k.MasterKey.from_secret_file(str(d / "master2.key"))
    message = (d / "message").read_bytes()
    key2 = master2.derive(CONTEXT, SALT)
    resealed = (d / "rust" / "aad-resealed-of-python").read_bytes()
    bound_to_aad(key2, resealed, NEW_AAD, AAD, message, "resealed by Rust")


def store_v2(d):
    master = k.MasterKey.from_secret_file(str(d / "master.key"))
    message = (d / "message").read_bytes()

    # Rust's store, made and written once there.
    path = str(d / "rust.store")
    e = raises(k.RollbackError, k.SecretStore.open_with_min_counter, path, master, 2)
    assert (e.file_counter, e.min_counter) == (1, 2), "rollback"
    store = k.SecretStore.open_with_min_counter(path, master, 1)
    assert (store.version(), store.counter()) == (2, 1), "rust.store"
    assert store.get("from-rust").expose(bytes) == message, "rust.store"
    store.put("from-python", k.SecretBuf.from_vec(message))
    assert store.counter() == 2, "rust.store after a write"
    del store

    store = k.SecretStore.open(str(d / "python.store"), master)
    assert (store.version(), store.counter()) == (2, 0), "a new store"
    store.put("from-python", k.SecretBuf.from_vec(message))
    assert store.counter() == 1, "after one write"


def store_v2_back(d):
    master = k.MasterKey.from_secret_file(str(d / "master.key"))
    message = (d / "message").read_bytes()
    store = k.SecretStore.open_with_version(str(d / "python.store"), master, 2)
    assert store.counter() == 2, "python.store after Rust's write"
    assert store.list("") == ["from-python", "from-rust"], "python.store"
    assert store.get("from-rust").expose(bytes) == message, "python.store"


def upgrade_rotate(d):
    master = k.MasterKey.from_secret_file(str(d / "master.key"))
    master2 = k.MasterKey.from_secret_file(str(d / "master2.key"))
    message = (d / "message").read_bytes()

    store = k.SecretStore.open_with_version(str(d / "rust-v1.store"), master, 1)
    assert (store.version(), store.counter()) == (1, 0), "rust-v1.store"
    store = store.upgrade()
    assert (store.version(), store.counter()) == (2, 0), "rust-v1.store after upgrade"
    del store

    path = str(d / "rust-rotated.store")
    raises(k.WrongKeyError, k.SecretStore.open, path, master)
    store = k.SecretStore.open(path, master2)
    assert (store.version(), store.counter()) == (2, 0), "rust-rotated.store"
    assert store.get("from-rust").expose(bytes) == message, "rust-rotated.store"
    del store

    store = k.SecretStore.open_with_version(str(d / "python-v1.store"), master, 1)
    store.put("from-python", k.SecretBuf.from_vec(message))
    assert (store.version(), store.counter()) == (1, 0), "a v1 store"
    del store

    store = k.SecretStore.open(str(d / "python-rotated.store"), master)
    store.put("from-python", k.SecretBuf.from_vec(message))
    store = store.rotate(master2)
    assert (store.version(), store.counter()) == (2, 0), "after rotate"


def upgrade_rotate_back(d):
    master = k.MasterKey.from_secret_file(str(d / "master.key"))
    message = (d / "message").read_bytes()
    store = k.SecretStore.open_with_version(str(d / "python-v1.store"), master, 2)
    assert store.counter() == 0, "python-v1.store after Rust's upgrade"
    assert store.get("from-python").expose(bytes) == message, "python-v1.store"


if __name__ == "__main__":
    {
        "seal": seal,
        "keys": keys,
        "aad": aad,
        "aad-back": aad_back,
        "store-v2": store_v2,
        "store-v2-back": store_v2_back,
        "upgrade-rotate": upgrade_rotate,
        "upgrade-rotate-back": upgrade_rotate_back,
    }[sys.argv[1]](Path(sys.argv[2]))
