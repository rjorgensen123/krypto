# SPDX-License-Identifier: MIT OR Apache-2.0
"""krypto-py from Python: the crate's API, and what Python adds (0.8.0).

These tests check the binding itself: the exceptions, and the rules Python adds
on top of Rust's, such as consumed objects, zeroed bytearrays and the store's
lock. That the names are the crate's is checked in `surface.rs`, and what
crosses between Rust and Python in `interop.rs`, both against the crate.
"""

from importlib.metadata import version

import pytest

import krypto_py as k
from krypto_py import base64, exchange, hex, password, sign

ALGS = {"aegis256": k.Alg.Aegis256, "xchacha20": k.Alg.XChaCha20Poly1305, "aes256gcm": k.Alg.Aes256Gcm}


def master(seed=0):
    return k.MasterKey.from_bytes(k.SecretBuf.from_vec(bytes(range(seed, seed + 32))))


def plain(buf):
    return buf.expose(bytes)


# --------------------------------------------------------------------------- #
# One version, one error tree (that the names are the crate's: `surface.rs`)
# --------------------------------------------------------------------------- #

def test_one_version_and_one_error_tree():
    assert k.VERSION == k.__version__ == version("krypto-py"), "the module and the package have one version"
    for e in [k.IoError, k.HardeningError, k.FormatError, k.AuthError, k.KeyNotFoundError, k.WrongKeyError]:
        assert issubclass(e, k.Error)
    assert k.error.AuthError is k.AuthError


# --------------------------------------------------------------------------- #
# SecretBuf, SecretString
# --------------------------------------------------------------------------- #

def test_secrets_zero_a_bytearray_and_redact():
    source = bytearray(b"secret")
    buf = k.SecretBuf.from_vec(source)
    assert source == bytearray(6), "from_vec zeroes a bytearray, as Rust zeroizes the source"
    assert plain(buf) == b"secret" and buf.len() == 6 and len(buf) == 6 and not buf.is_empty()
    assert "secret" not in repr(buf) and "REDACTED" in repr(buf)
    s = k.SecretString.from_string("hunter2")
    assert s.len() == 7 and s.expose_str(lambda t: t) == "hunter2" and "hunter2" not in repr(s)


def test_random_is_capped_per_call():
    assert len(k.SecretBuf.random(32)) == 32
    assert len(k.random_bytes(k.MAX_RANDOM_BYTES)) == k.MAX_RANDOM_BYTES
    with pytest.raises(k.FormatError):
        k.random_bytes(k.MAX_RANDOM_BYTES + 1)
    with pytest.raises(k.FormatError):
        k.SecretBuf.random(k.MAX_RANDOM_BYTES + 1)
    assert len(k.random_bytes_with_limit(k.MAX_RANDOM_BYTES + 1, k.MAX_RANDOM_BYTES + 1)) == k.MAX_RANDOM_BYTES + 1
    with pytest.raises(k.HardeningError):
        k.random_bytes_with_limit(2**64 - 1, 2**64 - 1)


# --------------------------------------------------------------------------- #
# Keys, AEAD
# --------------------------------------------------------------------------- #

def test_master_key(tmp_path):
    buf = k.SecretBuf.from_vec(bytes(range(32)))
    m = k.MasterKey.from_bytes(buf)
    with pytest.raises(ValueError):
        buf.len()  # from_bytes consumed it, as Rust moves it
    assert m.key_id().hex() == "e5b56819c0e7cf09e3fc10357542f41c", "the frozen key id"
    p = tmp_path / "master.key"
    p.write_bytes(bytes(range(32)))
    assert k.MasterKey.from_secret_file(str(p)).key_id() == m.key_id()
    with pytest.raises(k.FormatError):
        k.MasterKey.from_bytes(k.SecretBuf.from_vec(bytes(16)))
    with pytest.raises(k.FormatError):
        m.derive(b"", b"s")


@pytest.mark.parametrize("alg", list(ALGS.values()))
def test_seal_open_tamper(alg):
    m = master()
    dk = m.derive(b"ctx/v1", b"s")
    blob = k.seal(dk, m.key_id(), k.SecretBuf.from_vec(b"data"), alg)
    opened = k.open(dk, blob)
    assert isinstance(opened, k.SecretBuf) and plain(opened) == b"data"
    assert k.blob_key_id(blob) == m.key_id()
    for i in [4, 5, 10, 30, len(blob) - 1]:
        bad = bytearray(blob)
        bad[i] ^= 1
        with pytest.raises(k.AuthError):
            k.open(dk, bytes(bad))
    with pytest.raises(k.AuthError):
        k.open(master(32).derive(b"ctx/v1", b"s"), blob)
    with pytest.raises(k.FormatError):
        k.open(dk, b"not a blob")


def test_reseal_and_hmac():
    a, b = master(), master(32)
    blob = k.seal(a.derive(b"c", b"s"), a.key_id(), k.SecretBuf.from_vec(b"x"), k.Alg.Aes256Gcm)
    moved = k.reseal(a.derive(b"c", b"s"), b.derive(b"c", b"s"), b.key_id(), blob)
    assert plain(k.open(b.derive(b"c", b"s"), moved)) == b"x" and k.blob_key_id(moved) == b.key_id()
    mac = k.hmac_sha256(a.derive(b"c", b"s"), b"data")
    assert len(mac) == 32 and mac == k.hmac_sha256(a.derive(b"c", b"s"), b"data")


def test_secretstore(tmp_path):
    path = str(tmp_path / "s.store")
    s = k.SecretStore.open(path, master())
    s.put("a/b", k.SecretBuf.from_vec(b"v"))
    assert s.contains("a/b") and s.list("a/") == ["a/b"] and plain(s.get("a/b")) == b"v"
    with pytest.raises(k.KeyNotFoundError):
        s.get("nope")
    s.delete("a/b")
    assert not s.contains("a/b")
    with pytest.raises(k.IoError):
        k.SecretStore.open(path, master())  # one handle per file, as in Rust
    s.put("x", k.SecretBuf.from_vec(b"y"))
    new = s.rotate(master(32))
    with pytest.raises(ValueError):
        s.get("x")  # rotate consumed the old handle
    del new  # the lock goes with the handle
    assert plain(k.SecretStore.open(path, master(32)).get("x")) == b"y"


# --------------------------------------------------------------------------- #
# password, sign, exchange, hex, base64, utilities
# --------------------------------------------------------------------------- #

def test_password():
    pw = k.SecretString.from_string("correct horse")
    phc = password.hash(pw, password.Preset.Interactive)
    password.verify(pw, phc)
    with pytest.raises(k.AuthError):
        password.verify(k.SecretString.from_string("wrong"), phc)
    with pytest.raises(k.FormatError):
        password.verify(pw, "not-a-phc")
    one = password.derive_key(pw, bytes(16), password.Preset.Interactive)
    two = password.derive_key(pw, bytes(16), password.Preset.Interactive)
    assert plain(one) == plain(two) and len(one) == 32


def test_sign_and_exchange():
    seed = k.SecretBuf.from_vec(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970"
                              "1cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert sign.ed25519_public(seed) == public
    assert sign.ed25519_sign(seed, b"") == signature
    sign.ed25519_verify(public, b"", signature)
    with pytest.raises(k.AuthError):
        sign.ed25519_verify(public, b"x", signature)
    key, public = sign.ecdsa_p256_keypair()
    assert sign.ecdsa_p256_public(key) == public
    sig = sign.ecdsa_p256_sign(key, b"m")
    sign.ecdsa_p256_verify(public, b"m", sig)
    with pytest.raises(k.AuthError):
        sign.ecdsa_p256_verify(public, b"n", sig)
    a, pa = exchange.x25519_keypair()
    b, pb = exchange.x25519_keypair()
    assert exchange.x25519_public(a) == pa
    assert plain(exchange.x25519_shared(a, pb)) == plain(exchange.x25519_shared(b, pa))


def test_encodings_and_utilities():
    assert k.sha256(b"abc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert hex.encode(b"\x01\xab") == "01ab" and hex.decode("01ab") == b"\x01\xab"
    with pytest.raises(k.FormatError):
        hex.decode("01AB")
    assert base64.encode(b"foob") == "Zm9vYg==" and base64.encode_nopad(b"foob") == "Zm9vYg"
    assert base64.decode("Zm9vYg==") == b"foob" and base64.decode_nopad("Zm9vYg") == b"foob"
    with pytest.raises(k.FormatError):
        base64.decode("Zm9vYg")
    assert k.ct_eq(b"a", b"a") and not k.ct_eq(b"a", b"b") and not k.ct_eq(b"a", b"ab")
