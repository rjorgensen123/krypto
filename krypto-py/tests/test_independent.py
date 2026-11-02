# SPDX-License-Identifier: MIT OR Apache-2.0
"""krypto against code it did not write (0.8.0).

Every test checks what krypto composed itself, the blob format, HKDF, the key
id, the presets and the key forms, against an INDEPENDENT implementation:
`cryptography`, `argon2-cffi`, `hashlib`, `base64`. In both directions where a
direction exists. The binding and the crate run the same code, so `interop.rs`
shows that they agree; this shows that what they agree on is right. The
versions of the independent libraries are locked in `requirements-ci.txt`.
"""

import base64 as py_b64
import hashlib
import hmac as py_hmac
import secrets

import pytest
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import krypto_py as k
from krypto_py import base64, exchange, password, sign

KEY_ID_CONTEXT = b"krypto/key-id/v1"
FAFN_MAGIC = b"FAFN"
FORMAT_VER = 1
ALG_AES256GCM = 3
HEADER_LEN = 4 + 1 + 1 + 16 + 32  # 54

# The preset numbers are the crate's public contract (docs/API.md).
PRESETS = [
    (password.Preset.Interactive, dict(memory_cost=65_536, iterations=3, lanes=2)),
    (password.Preset.Balanced, dict(memory_cost=131_072, iterations=3, lanes=3)),
    (password.Preset.High, dict(memory_cost=262_144, iterations=4, lanes=4)),
]


def hkdf_derive(master: bytes, info: bytes, salt: bytes) -> bytes:
    """MasterKey.derive, written again: HKDF-SHA256, 32 bytes."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(master)


def key_id(master: bytes) -> bytes:
    """MasterKey.key_id, written again."""
    return py_hmac.new(hkdf_derive(master, KEY_ID_CONTEXT, b""), b"key-id", hashlib.sha256).digest()[:16]


@pytest.fixture()
def master():
    raw = secrets.token_bytes(32)
    return raw, k.MasterKey.from_bytes(k.SecretBuf.from_vec(raw))


def plain(buf):
    return buf.expose(bytes)


# Hash, MAC, key id

def test_sha256_matches_hashlib():
    data = b"the quick brown fox"
    assert k.sha256(data) == hashlib.sha256(data).digest()


def test_mac_matches_hkdf_and_hmac(master):
    raw, m = master
    data = b"audit chain payload"
    dk = hkdf_derive(raw, b"example/audit/v1", b"s1")
    assert k.hmac_sha256(m.derive(b"example/audit/v1", b"s1"), data) == py_hmac.new(dk, data, hashlib.sha256).digest()


def test_key_id_matches_the_recipe(master):
    raw, m = master
    assert m.key_id() == key_id(raw)


# AEAD (AES-256-GCM, the algorithm both sides implement)

def test_krypto_seals_python_decrypts(master):
    raw, m = master
    plaintext = b"cross-language payload"
    blob = k.seal(m.derive(b"ctx/v1", b"s"), m.key_id(), k.SecretBuf.from_vec(plaintext), k.Alg.Aes256Gcm)
    header, body = blob[:HEADER_LEN], blob[HEADER_LEN:]
    assert header[:4] == FAFN_MAGIC and header[4] == FORMAT_VER and header[5] == ALG_AES256GCM
    assert header[6:22] == key_id(raw)
    assert header[34:54] == bytes(20), "the unused nonce tail must be zero"
    assert AESGCM(hkdf_derive(raw, b"ctx/v1", b"s")).decrypt(header[22:34], body, header) == plaintext


def test_python_seals_krypto_opens(master):
    raw, m = master
    plaintext = b"built by python"
    nonce = secrets.token_bytes(12)
    header = FAFN_MAGIC + bytes([FORMAT_VER, ALG_AES256GCM]) + key_id(raw) + nonce + bytes(20)
    body = AESGCM(hkdf_derive(raw, b"ctx/v1", b"s")).encrypt(nonce, plaintext, header)
    assert plain(k.open(m.derive(b"ctx/v1", b"s"), header + body)) == plaintext


def test_blob_key_id_is_the_header_field(master):
    raw, m = master
    blob = k.seal(m.derive(b"c", b"s"), m.key_id(), k.SecretBuf.from_vec(b"x"), k.Alg.Aegis256)
    assert k.blob_key_id(blob) == blob[6:22] == key_id(raw)


# Ed25519

def raw_public(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def test_ed25519_krypto_signs_python_verifies():
    seed, public = sign.ed25519_keypair()
    msg = b"order body"
    ed25519.Ed25519PublicKey.from_public_bytes(public).verify(sign.ed25519_sign(seed, msg), msg)


def test_ed25519_python_signs_krypto_verifies():
    key = ed25519.Ed25519PrivateKey.generate()
    public, msg = raw_public(key.public_key()), b"reply body"
    sig = key.sign(msg)
    sign.ed25519_verify(public, msg, sig)
    with pytest.raises(k.AuthError):
        sign.ed25519_verify(public, msg + b"!", sig)


def test_ed25519_python_seed_is_krypto_seed():
    key = ed25519.Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    assert sign.ed25519_public(k.SecretBuf.from_vec(seed)) == raw_public(key.public_key())


# ECDSA P-256

def sec1(public_key):
    return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def test_p256_krypto_signs_python_verifies():
    pkcs8, public = sign.ecdsa_p256_keypair()
    msg = b"config diff"
    py_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
    py_public.verify(sign.ecdsa_p256_sign(pkcs8, msg), msg, ec.ECDSA(hashes.SHA256()))
    loaded = serialization.load_der_private_key(plain(pkcs8), password=None)
    assert isinstance(loaded, ec.EllipticCurvePrivateKey) and sec1(loaded.public_key()) == public


def test_p256_python_signs_krypto_verifies():
    key = ec.generate_private_key(ec.SECP256R1())
    msg = b"approval"
    sign.ecdsa_p256_verify(sec1(key.public_key()), msg, key.sign(msg, ec.ECDSA(hashes.SHA256())))
    pkcs8 = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
    assert sign.ecdsa_p256_public(k.SecretBuf.from_vec(pkcs8)) == sec1(key.public_key())


# X25519

def test_x25519_shared_matches_python():
    secret, public = exchange.x25519_keypair()
    py_key = x25519.X25519PrivateKey.generate()
    shared = exchange.x25519_shared(secret, raw_public(py_key.public_key()))
    assert plain(shared) == py_key.exchange(x25519.X25519PublicKey.from_public_bytes(public))


# Passwords (Argon2id)

@pytest.mark.parametrize("preset,p", PRESETS[:2])
def test_derive_key_matches_argon2id(preset, p):
    # High is left out only for time (256 MiB per hash); the PHC test checks its numbers.
    salt = secrets.token_bytes(16)
    expected = Argon2id(salt=salt, length=32, iterations=p["iterations"], lanes=p["lanes"],
                        memory_cost=p["memory_cost"]).derive(b"correct horse")
    assert plain(password.derive_key(k.SecretString.from_string("correct horse"), salt, preset)) == expected


@pytest.mark.parametrize("preset,p", PRESETS)
def test_phc_carries_the_preset_and_verifies_in_argon2_cffi(preset, p):
    phc = password.hash(k.SecretString.from_string("hunter2"), preset)
    assert f"m={p['memory_cost']},t={p['iterations']},p={p['lanes']}" in phc, phc
    PasswordHasher().verify(phc, "hunter2")
    with pytest.raises(VerifyMismatchError):
        PasswordHasher().verify(phc, "hunter3")


def test_argon2_cffi_phc_verifies_in_krypto():
    phc = PasswordHasher(time_cost=3, memory_cost=65_536, parallelism=2).hash("hunter2")
    password.verify(k.SecretString.from_string("hunter2"), phc)
    with pytest.raises(k.AuthError):
        password.verify(k.SecretString.from_string("hunter3"), phc)


# Base64

def test_base64_matches_the_stdlib():
    for size in (0, 1, 2, 3, 4, 5, 6, 31, 32, 33, 64):
        data = secrets.token_bytes(size)
        padded = py_b64.b64encode(data).decode()
        assert base64.encode(data) == padded and base64.encode_nopad(data) == padded.rstrip("=")
        assert base64.decode(padded) == data and base64.decode_nopad(padded.rstrip("=")) == data
