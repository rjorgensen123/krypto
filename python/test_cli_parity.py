# SPDX-License-Identifier: MIT OR Apache-2.0
"""Rust ↔ Python parity for krypto-cli.

Every test drives the REAL binary (subprocess, exactly like a non-Rust
caller does) and
checks the answer against an INDEPENDENT Python implementation (`cryptography`
/ `argon2-cffi` / `hashlib`) — in both directions where a direction exists.
That is the guarantee worth having: two implementations that must agree,
tested against each other, not each against itself.

Requires the binary to be built first:  cargo build --bin krypto-cli
Run with the pinned venv:               .venv/bin/pytest -q
"""

import hashlib
import hmac as py_hmac
import os
import secrets
import subprocess
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CLI = Path(os.environ.get(
    "KRYPTO_CLI",
    Path(__file__).resolve().parent.parent / "target" / "debug" / "krypto-cli",
))

KEY_ID_CONTEXT = b"krypto/key-id/v1"
FAFN_MAGIC = b"FAFN"
FORMAT_VER = 1
ALG_AES256GCM = 3
HEADER_LEN = 4 + 1 + 1 + 16 + 32  # 54


def run(args, stdin=b""):
    """Run the CLI, return (exit code, stdout bytes)."""
    p = subprocess.run(
        [str(CLI), *args], input=stdin, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, check=False,
    )
    return p.returncode, p.stdout


def run_ok(args, stdin=b""):
    code, out = run(args, stdin)
    assert code == 0, f"krypto-cli {args[0]} failed with exit {code}"
    return out


def hkdf_derive(master: bytes, info: bytes, salt: bytes) -> bytes:
    """The Python replication of MasterKey::derive (HKDF-SHA256, 32 bytes)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(master)


def key_id(master: bytes) -> bytes:
    """The Python replication of the CLI's deterministic key id."""
    dk = hkdf_derive(master, KEY_ID_CONTEXT, b"")
    return py_hmac.new(dk, b"key-id", hashlib.sha256).digest()[:16]


@pytest.fixture()
def master_file(tmp_path):
    master = secrets.token_bytes(32)
    path = tmp_path / "master.key"
    path.write_bytes(master)
    return path, master


# --------------------------------------------------------------------------- #
# Hash + MAC + key id
# --------------------------------------------------------------------------- #

def test_sha256_matches_hashlib():
    data = b"the quick brown fox"
    out = run_ok(["sha256"], data).decode().strip()
    assert out == hashlib.sha256(data).hexdigest()


def test_mac_matches_python_hkdf_hmac(master_file):
    path, master = master_file
    data = b"audit chain payload"
    out = run_ok(
        ["mac", "--key-file", str(path), "--context", "l2/audit/v1", "--salt", "s1"],
        data,
    ).decode().strip()
    dk = hkdf_derive(master, b"l2/audit/v1", b"s1")
    assert out == py_hmac.new(dk, data, hashlib.sha256).hexdigest()


def test_keyid_matches_python_replication(master_file):
    path, master = master_file
    out = run_ok(["keyid", "--key-file", str(path)]).decode().strip()
    assert out == key_id(master).hex()


# --------------------------------------------------------------------------- #
# AEAD interop (AES-256-GCM — the algorithm both sides implement)
# --------------------------------------------------------------------------- #

def test_cli_seals_python_decrypts(master_file):
    path, master = master_file
    plaintext = b"cross-language payload"
    blob = run_ok(
        ["seal", "--key-file", str(path), "--context", "ctx/v1", "--salt", "s",
         "--alg", "aes256gcm"],
        plaintext,
    )
    header, body = blob[:HEADER_LEN], blob[HEADER_LEN:]
    assert header[:4] == FAFN_MAGIC and header[4] == FORMAT_VER
    assert header[5] == ALG_AES256GCM
    assert header[6:22] == key_id(master)
    nonce = header[22:34]  # AES-GCM uses the first 12 of the 32-byte field
    assert header[34:54] == bytes(20), "the unused nonce tail must be zero"

    dk = hkdf_derive(master, b"ctx/v1", b"s")
    # cryptography's AESGCM takes ct||tag and the full header as AAD.
    assert AESGCM(dk).decrypt(nonce, body, header) == plaintext


def test_python_seals_cli_opens(master_file):
    path, master = master_file
    plaintext = b"built by python"
    dk = hkdf_derive(master, b"ctx/v1", b"s")

    nonce12 = secrets.token_bytes(12)
    header = (
        FAFN_MAGIC + bytes([FORMAT_VER, ALG_AES256GCM]) + key_id(master)
        + nonce12 + bytes(20)
    )
    assert len(header) == HEADER_LEN
    body = AESGCM(dk).encrypt(nonce12, plaintext, header)

    out = run_ok(
        ["open", "--key-file", str(path), "--context", "ctx/v1", "--salt", "s"],
        header + body,
    )
    assert out == plaintext


def test_python_tamper_gives_exit_3_and_wrong_generation_exit_4(master_file, tmp_path):
    path, _master = master_file
    blob = bytearray(run_ok(
        ["seal", "--key-file", str(path), "--context", "c", "--salt", "s"], b"x"))
    blob[-1] ^= 1
    code, _ = run(["open", "--key-file", str(path), "--context", "c", "--salt", "s"],
                  bytes(blob))
    assert code == 3, "tampering must be exit 3 (alarm)"

    other = tmp_path / "other.key"
    other.write_bytes(secrets.token_bytes(32))
    blob2 = run_ok(["seal", "--key-file", str(path), "--context", "c", "--salt", "s"], b"x")
    code, _ = run(["open", "--key-file", str(other), "--context", "c", "--salt", "s"], blob2)
    assert code == 4, "another key generation must be exit 4 (routing), not an alarm"


# --------------------------------------------------------------------------- #
# Ed25519 — both directions, including Python-made seeds
# --------------------------------------------------------------------------- #

def test_ed25519_cli_signs_python_verifies(tmp_path):
    key = tmp_path / "ed.key"
    public_hex = run_ok(["keygen", "--alg", "ed25519", "--out", str(key)]).decode().strip()
    msg = b"order body"
    sig = bytes.fromhex(run_ok(
        ["sign", "--alg", "ed25519", "--key-file", str(key)], msg).decode().strip())
    pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
    pub.verify(sig, msg)  # raises on mismatch


def test_ed25519_python_signs_cli_verifies(tmp_path):
    priv = ed25519.Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    msg = b"reply body"
    sig_hex = priv.sign(msg).hex()
    code, _ = run(["verify", "--alg", "ed25519", "--public", pub_hex,
                   "--signature", sig_hex], msg)
    assert code == 0
    code, _ = run(["verify", "--alg", "ed25519", "--public", pub_hex,
                   "--signature", sig_hex], msg + b"!")
    assert code == 3


def test_ed25519_python_seed_is_usable_by_cli(tmp_path):
    """A raw seed written by Python must be the exact key format the CLI reads."""
    priv = ed25519.Ed25519PrivateKey.generate()
    seed = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())
    key = tmp_path / "py-seed.key"
    key.write_bytes(seed)
    public_hex = run_ok(
        ["public", "--alg", "ed25519", "--key-file", str(key)]).decode().strip()
    expected = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    assert public_hex == expected


# --------------------------------------------------------------------------- #
# ECDSA P-256 — both directions, including PKCS#8 interchange
# --------------------------------------------------------------------------- #

def test_p256_cli_signs_python_verifies(tmp_path):
    key = tmp_path / "p256.key"
    public_hex = run_ok(["keygen", "--alg", "p256", "--out", str(key)]).decode().strip()
    msg = b"config diff"
    sig = bytes.fromhex(run_ok(
        ["sign", "--alg", "p256", "--key-file", str(key)], msg).decode().strip())
    pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), bytes.fromhex(public_hex))
    pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))  # raises on mismatch

    # And Python must be able to read the CLI's PKCS#8 private key directly.
    loaded = serialization.load_der_private_key(key.read_bytes(), password=None)
    assert isinstance(loaded, ec.EllipticCurvePrivateKey)


def test_p256_python_signs_cli_verifies(tmp_path):
    priv = ec.generate_private_key(ec.SECP256R1())
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint).hex()
    msg = b"approval"
    sig_hex = priv.sign(msg, ec.ECDSA(hashes.SHA256())).hex()
    code, _ = run(["verify", "--alg", "p256", "--public", pub_hex,
                   "--signature", sig_hex], msg)
    assert code == 0

    # A Python-written PKCS#8 file must be usable as the CLI's --key-file.
    key = tmp_path / "py-p256.key"
    key.write_bytes(priv.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    cli_pub = run_ok(["public", "--alg", "p256", "--key-file", str(key)]).decode().strip()
    assert cli_pub == pub_hex


# --------------------------------------------------------------------------- #
# X25519 — the shared secret must be identical on both sides
# --------------------------------------------------------------------------- #

def test_x25519_shared_matches_python(tmp_path):
    cli_key = tmp_path / "x-cli.key"
    cli_pub = bytes.fromhex(run_ok(
        ["keygen", "--alg", "x25519", "--out", str(cli_key)]).decode().strip())

    py_priv = x25519.X25519PrivateKey.generate()
    py_pub = py_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    out = tmp_path / "shared.key"
    run_ok(["shared", "--key-file", str(cli_key), "--peer", py_pub.hex(),
            "--out", str(out)])
    cli_shared = out.read_bytes()

    py_shared = py_priv.exchange(x25519.X25519PublicKey.from_public_bytes(cli_pub))
    assert cli_shared == py_shared, "both sides must derive the identical shared secret"
    assert len(cli_shared) == 32


# --------------------------------------------------------------------------- #
# Passwords — argon2id parity (derivation AND PHC hashing)
# --------------------------------------------------------------------------- #

# The preset numbers are the crate's public contract (API-krypto-v0.6.md).
PRESETS = {
    "interactive": dict(memory_cost=65_536, iterations=3, lanes=2),
    "balanced": dict(memory_cost=131_072, iterations=3, lanes=3),
    "high": dict(memory_cost=262_144, iterations=4, lanes=4),
}


@pytest.mark.parametrize("preset", ["interactive", "balanced"])
def test_derive_key_matches_python_argon2id(tmp_path, preset):
    # `high` is excluded only for test time (256 MiB per hash); the parameter
    # table itself is verified for all three by the PHC test below.
    salt = secrets.token_bytes(16)
    out = tmp_path / f"dk-{preset}.key"
    run_ok(["derive-key", "--salt", salt.hex(), "--preset", preset,
            "--out", str(out)], b"correct horse\n")
    cli_key = out.read_bytes()

    p = PRESETS[preset]
    py_key = Argon2id(salt=salt, length=32, iterations=p["iterations"],
                      lanes=p["lanes"], memory_cost=p["memory_cost"]).derive(
        b"correct horse")
    assert cli_key == py_key, f"preset {preset}: CLI and Python argon2id disagree"


@pytest.mark.parametrize("preset", ["interactive", "balanced", "high"])
def test_password_hash_phc_verifies_in_python_with_expected_params(preset):
    phc = run_ok(["password-hash", "--preset", preset], b"hunter2\n").decode().strip()
    p = PRESETS[preset]
    assert f"m={p['memory_cost']},t={p['iterations']},p={p['lanes']}" in phc, phc
    PasswordHasher().verify(phc, "hunter2")  # raises on mismatch
    with pytest.raises(VerifyMismatchError):
        PasswordHasher().verify(phc, "hunter3")


def test_python_phc_verifies_in_cli():
    phc = PasswordHasher(time_cost=3, memory_cost=65_536, parallelism=2).hash("hunter2")
    code, _ = run(["password-verify", "--phc", phc], b"hunter2\n")
    assert code == 0
    code, _ = run(["password-verify", "--phc", phc], b"hunter3\n")
    assert code == 3, "a wrong password must be exit 3"


def test_blob_key_id_matches_python_header_parse(master_file):
    path, master = master_file
    blob = run_ok(["seal", "--key-file", str(path), "--context", "c", "--salt", "s"], b"x")
    out = run_ok(["blob-key-id"], blob).decode().strip()
    assert out == blob[6:22].hex()          # the public header field…
    assert out == key_id(master).hex()      # …which is the master key's generation


def test_base64_matches_python_stdlib():
    """krypto::base64 (STANDARD, padded + nopad) against Python's base64
    stdlib — both directions, over lengths covering every padding case."""
    import base64 as py_b64

    for size in (0, 1, 2, 3, 4, 5, 6, 31, 32, 33, 64):
        data = secrets.token_bytes(size)
        expect_padded = py_b64.b64encode(data).decode()
        expect_nopad = expect_padded.rstrip("=")

        assert run_ok(["b64-encode"], data).decode().strip() == expect_padded
        assert run_ok(["b64-encode-nopad"], data).decode().strip() == expect_nopad
        assert run_ok(["b64-decode"], expect_padded.encode()).decode().strip() == data.hex()
        assert (
            run_ok(["b64-decode-nopad"], expect_nopad.encode()).decode().strip()
            == data.hex()
        )


def test_base64_decode_is_fail_closed():
    """Whitespace, wrong padding and non-canonical trailing bits must be refused."""
    for bad in (b"Zm9v YmFy", b"Zm9vYmE", b"Zm9vYmF="):
        p = subprocess.run(
            [str(CLI), "b64-decode"], input=bad, capture_output=True
        )
        assert p.returncode != 0, bad
