# SPDX-License-Identifier: MIT OR Apache-2.0
"""The Python side of `interop.rs`: krypto_py on what Rust wrote (0.8.0).

    python -I peer.py seal|keys <dir>

It opens and checks what Rust wrote to `<dir>/rust/`, and writes what Python
makes, and its answers to the same inputs, to `<dir>/python/` for Rust to
check. A failed check is an exception, and a non-zero exit.
"""

import sys
from pathlib import Path

import krypto_py as k
from krypto_py import base64, exchange, hex, password, sign

CONTEXT = b"interop/v1"
SALT = b"interop-salt"
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


if __name__ == "__main__":
    {"seal": seal, "keys": keys}[sys.argv[1]](Path(sys.argv[2]))
