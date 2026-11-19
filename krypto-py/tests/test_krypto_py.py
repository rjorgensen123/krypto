# SPDX-License-Identifier: MIT OR Apache-2.0
"""krypto-py from Python: the crate's API, and what Python adds (0.8.0).

These tests check the binding itself: the exceptions, and the rules Python adds
on top of Rust's, such as consumed objects, zeroed bytearrays and the store's
lock. That the names are the crate's is checked in `surface.rs`, what crosses
between Rust and Python in `interop.rs`, both against the crate, and krypto
against code it did not write in `test_independent.py`.
"""

import os
import subprocess
import sys
import threading
import time
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
    for e in [k.IoError, k.HardeningError, k.FormatError, k.AuthError, k.KeyNotFoundError, k.WrongKeyError, k.RollbackError]:
        assert issubclass(e, k.Error)
    assert k.error.AuthError is k.AuthError and k.error.RollbackError is k.RollbackError
    # The message is the Rust one, so both languages say the same.
    m = master()
    blob = k.seal(m.derive(b"c", b"s"), m.key_id(), k.SecretBuf.from_vec(b"x"), k.Alg.Aegis256)
    with pytest.raises(k.AuthError) as e:
        k.open(master(32).derive(b"c", b"s"), blob)
    assert str(e.value) == "authentication failure (tampering or wrong key)"


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


def test_the_guarantees_hold_from_python():
    """A secret made from Python is in krypto's memory, locked (`lo`) and kept
    out of core dumps (`dd`); and harden_process has the same effect as in Rust."""
    def protected():
        with open("/proc/self/smaps") as f:
            return sum(1 for line in f if line.startswith("VmFlags:") and {"lo", "dd"} <= set(line.split()[1:]))
    before = protected()
    buf = k.SecretBuf.random(32)
    assert protected() == before + 1
    del buf
    assert protected() == before
    # In a child, so pytest itself stays as it is.
    code = ("import ctypes, resource, krypto_py\n"
            "krypto_py.harden_process()\n"
            "assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)\n"
            "assert ctypes.CDLL(None).prctl(3, 0, 0, 0, 0) == 0  # PR_GET_DUMPABLE\n")
    subprocess.run([sys.executable, "-I", "-c", code], check=True)


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


def test_seal_open_reseal_with_aad():
    a, b = master(), master(32)
    dk, dk_b = a.derive(b"ctx/v1", b"s"), b.derive(b"ctx/v1", b"s")
    pt = k.SecretBuf.from_vec(b"data")
    blob = k.seal_with_aad(dk, a.key_id(), pt, k.Alg.Aegis256, b"record/42")
    assert plain(k.open_with_aad(dk, blob, b"record/42")) == b"data"
    with pytest.raises(k.AuthError):
        k.open_with_aad(dk, blob, b"record/43")  # wrong AAD
    with pytest.raises(k.AuthError):
        k.open(dk, blob)  # no AAD given
    # Empty AAD is exactly the plain seal/open contract.
    blob0 = k.seal_with_aad(dk, a.key_id(), pt, k.Alg.Aegis256, b"")
    assert plain(k.open(dk, blob0)) == b"data"
    assert plain(k.open_with_aad(dk, k.seal(dk, a.key_id(), pt, k.Alg.Aegis256), b"")) == b"data"
    # Rotation carries the binding: the new blob takes the NEW AAD only.
    moved = k.reseal_with_aad(dk, dk_b, b.key_id(), blob, b"record/42", b"record/43")
    assert plain(k.open_with_aad(dk_b, moved, b"record/43")) == b"data"
    with pytest.raises(k.AuthError):
        k.open_with_aad(dk_b, moved, b"record/42")
    with pytest.raises(k.AuthError):
        k.reseal_with_aad(dk, dk_b, b.key_id(), blob, b"wrong", b"record/43")


def test_aad_is_capped():
    assert k.MAX_AAD_BYTES == 1024
    m = master()
    dk = m.derive(b"ctx/v1", b"s")
    with pytest.raises(k.FormatError):
        k.seal_with_aad(dk, m.key_id(), k.SecretBuf.from_vec(b"data"), k.Alg.Aegis256, bytes(k.MAX_AAD_BYTES + 1))


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
    s = k.SecretStore.open(path, master(32))
    assert plain(s.get("x")) == b"y"
    # Several Python threads on the same store: nothing is lost.
    def writer(i):
        for j in range(10):
            s.put(f"t{i}/{j}", k.SecretBuf.from_vec(bytes([i, j])))

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(s.list("t")) == 40 and plain(s.get("t3/9")) == bytes([3, 9])


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write in a read-only directory")
def test_failed_rotate_consumes_the_handle_and_keeps_the_file(tmp_path):
    """A `rotate` that fails before anything is written consumes the old
    handle all the same; the file is unchanged and opens with the old master
    key."""
    d = tmp_path / "store"
    d.mkdir()
    path = d / "s.store"
    s = k.SecretStore.open(str(path), master())
    s.put("x", k.SecretBuf.from_vec(b"y"))
    before = path.read_bytes()
    d.chmod(0o555)  # the atomic write cannot create its tmp file
    try:
        with pytest.raises(k.IoError):
            s.rotate(master(32))
    finally:
        d.chmod(0o755)
    with pytest.raises(ValueError):
        s.get("x")
    assert path.read_bytes() == before
    assert plain(k.SecretStore.open(str(path), master()).get("x")) == b"y"


def test_secretstore_version_counter_upgrade_and_rollback(tmp_path):
    """The store's format version and counter, the one-way upgrade and the
    rollback anchor (0.9.0): a new store is v2, an anchored open names v2 and
    refuses a v1 file with FormatError, and it fails with RollbackError below
    the anchor."""
    path = str(tmp_path / "s.store")
    s = k.SecretStore.open(path, master())  # a new store is v2
    assert s.version() == 2 and s.counter() == 0
    s.put("a", k.SecretBuf.from_vec(b"1"))
    assert s.version() == 2 and s.counter() == 1
    del s  # the lock goes with the handle
    # The counter anchors the file: below the caller's minimum, no handle.
    with pytest.raises(k.RollbackError) as e:
        k.SecretStore.open_with_min_counter(path, master(), 2)
    assert e.value.file_counter == 1 and e.value.min_counter == 2
    assert str(e.value).startswith("rollback detected")
    ok = k.SecretStore.open_with_min_counter(path, master(), 1)
    assert ok.version() == 2 and ok.counter() == 1
    del ok
    # An explicit v1 store is created as v1 and stays v1 (sticky).
    v1 = str(tmp_path / "v1.store")
    s1 = k.SecretStore.open_with_version(v1, master(), 1)
    assert s1.version() == 1 and s1.counter() == 0
    s1.put("x", k.SecretBuf.from_vec(b"y"))
    with pytest.raises(k.FormatError):
        k.SecretStore.open_with_version(str(tmp_path / "other.store"), master(), 3)
    # An anchored open names v2, so it refuses a v1 file, whatever the anchor.
    v1b = str(tmp_path / "v1b.store")
    sb = k.SecretStore.open_with_version(v1b, master(), 1)
    sb.put("x", k.SecretBuf.from_vec(b"y"))
    del sb
    for anchor in (1, 0):
        with pytest.raises(k.FormatError):
            k.SecretStore.open_with_min_counter(v1b, master(), anchor)
    # Upgrade is one-way: v1 -> v2, the entries readable, the old handle gone.
    s2 = s1.upgrade()
    assert s2.version() == 2 and s2.counter() == 0
    assert plain(s2.get("x")) == b"y"
    with pytest.raises(ValueError):
        s1.get("x")  # upgrade consumed the old handle
    del s2
    reopened = k.SecretStore.open(v1, master())
    assert reopened.version() == 2 and plain(reopened.get("x")) == b"y"


def test_secretstore_key_id_and_wrong_key(tmp_path):
    """The store's key_id, from the open store and from the file without the
    master key, and WrongKeyError from open when the master key does not fit
    a v2 file."""
    path = tmp_path / "s.store"
    s = k.SecretStore.open(str(path), master())
    key_id = s.key_id()
    assert len(key_id) == 16 and k.SecretStore.key_id_from_file(str(path)) == key_id
    del s  # the lock goes with the handle
    with pytest.raises(k.WrongKeyError):
        k.SecretStore.open(str(path), master(32))
    with pytest.raises(k.IoError):
        k.SecretStore.key_id_from_file(str(tmp_path / "missing.store"))
    (tmp_path / "not-a-store").write_bytes(b"important = true\n")
    with pytest.raises(k.FormatError):
        k.SecretStore.key_id_from_file(str(tmp_path / "not-a-store"))


def test_close_inherited_fds_refuses_while_a_store_is_open(tmp_path):
    """With a store open, close_inherited_fds raises HardeningError and closes
    nothing, so the store still works (0.9.0). In a child, so pytest's own
    descriptors stay open should the call ever succeed."""
    code = ("import sys, krypto_py as k\n"
            "s = k.SecretStore.open(sys.argv[1], k.MasterKey.from_bytes(k.SecretBuf.from_vec(bytes(32))))\n"
            "try:\n"
            "    k.close_inherited_fds()\n"
            "    sys.exit('close_inherited_fds did not refuse')\n"
            "except k.HardeningError as e:\n"
            "    assert 'a SecretStore is open in this process' in str(e), e\n"
            "s.put('a', k.SecretBuf.from_vec(b'value'))\n"
            "assert s.get('a').expose(bytes) == b'value'\n")
    subprocess.run([sys.executable, "-I", "-c", code, str(tmp_path / "s.store")], check=True)


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
    # Other Python threads run while Argon2 works: this one never stands still
    # for anything near as long as Argon2 takes.
    took = []

    def work():
        start = time.monotonic()
        password.derive_key(pw, bytes(16), password.Preset.Interactive)
        took.append(time.monotonic() - start)

    worker = threading.Thread(target=work)
    last, gap = time.monotonic(), 0.0
    worker.start()
    while worker.is_alive():
        now = time.monotonic()
        gap, last = max(gap, now - last), now
    worker.join()
    assert gap < took[0] / 4, f"Python stood still {gap:.3f} s of Argon2's {took[0]:.3f} s"


def test_derive_key_takes_no_mutable_salt():
    """`derive_key` refuses a `bytearray` or `memoryview` salt."""
    # The salt is borrowed while other threads run, so it must be immutable `bytes`.
    pw = k.SecretString.from_string("correct horse")
    for salt in (bytearray(16), memoryview(bytearray(16))):
        with pytest.raises(TypeError):
            password.derive_key(pw, salt, password.Preset.Interactive)


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


def test_ed25519_verify_and_verify_relaxed():
    """Both Ed25519 verifiers take a normal signature (0.8.2)."""
    assert callable(sign.ed25519_verify_relaxed)
    seed, public = sign.ed25519_keypair()
    sig = sign.ed25519_sign(seed, b"message")
    sign.ed25519_verify(public, b"message", sig)
    sign.ed25519_verify_relaxed(public, b"message", sig)
    with pytest.raises(k.AuthError):
        sign.ed25519_verify_relaxed(public, b"other message", sig)
    # The identity point as key, R = identity, S = 0: a forgery for every message.
    weak = bytes([1]) + bytes(31)
    forged = bytes([1]) + bytes(63)
    for message in (b"msg1", b"msg2"):
        with pytest.raises(k.AuthError):
            sign.ed25519_verify(weak, message, forged)
        sign.ed25519_verify_relaxed(weak, message, forged)


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


def test_the_limits_are_rusts(tmp_path):
    """The limits (0.9.0): the constants are Rust's, the encoders raise where
    Rust gives `Err`, and an input over its limit, or a store name that breaks
    the rules at lookup, raises `FormatError`."""
    assert k.MAX_DATA_BYTES == 64 * 1024 * 1024
    assert (password.MAX_PASSWORD_BYTES, password.MAX_PHC_BYTES) == (1024, 512)
    assert (sign.MAX_ECDSA_P256_PUBLIC_BYTES, sign.MAX_ECDSA_P256_SIG_BYTES,
            sign.MAX_ECDSA_P256_PKCS8_BYTES) == (65, 72, 512)
    over = bytes(k.MAX_DATA_BYTES + 1)
    for encode in (hex.encode, base64.encode, base64.encode_nopad):
        with pytest.raises(k.FormatError):
            encode(over)
    del over
    with pytest.raises(k.FormatError):
        password.hash(k.SecretString.from_string("p" * (password.MAX_PASSWORD_BYTES + 1)), password.Preset.Interactive)
    with pytest.raises(k.FormatError):
        password.verify(k.SecretString.from_string("p"), "x" * (password.MAX_PHC_BYTES + 1))
    key, public = sign.ecdsa_p256_keypair()
    with pytest.raises(k.FormatError):
        sign.ecdsa_p256_verify(public + b"\0", b"m", sign.ecdsa_p256_sign(key, b"m"))
    s = k.SecretStore.open(str(tmp_path / "s.store"), master())
    for call in (s.get, s.delete):
        with pytest.raises(k.FormatError):
            call("line\nbreak")
    assert not s.contains("line\nbreak") and s.list("\n") == []
