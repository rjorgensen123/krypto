// SPDX-License-Identifier: MIT OR Apache-2.0
//! `krypto_py` — the Python binding for krypto (0.8.0).
//!
//! It mirrors the Rust crate function for function: the same names,
//! parameters, modules and types. What differs is what can be guaranteed,
//! never what a function does. Keys and plaintext stay in krypto's locked,
//! guarded, wiped memory behind `SecretBuf`, `SecretString`, `MasterKey` and
//! `DerivedKey`; what Python itself holds — `bytes` passed in, and the copies
//! `expose` hands out — is ordinary Python memory, neither locked nor wiped.
//!
//! `Result<T, Error>` becomes a return value or an exception: `Error`, with
//! one subclass per variant (`Error::Auth` is `AuthError`, and so on).

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyModule};
use zeroize::Zeroizing;

pyo3::create_exception!(
    krypto_py,
    Error,
    PyException,
    "Every krypto error (`krypto::Error`)."
);
pyo3::create_exception!(krypto_py, IoError, Error, "`Error::Io`: file or directory.");
pyo3::create_exception!(
    krypto_py,
    HardeningError,
    Error,
    "`Error::Hardening`: a protection step or the environment failed; never a verdict on the data."
);
pyo3::create_exception!(
    krypto_py,
    FormatError,
    Error,
    "`Error::Format`: the input had the wrong shape."
);
pyo3::create_exception!(
    krypto_py,
    AuthError,
    Error,
    "`Error::Auth`: tampering, or the wrong key or password. The one to alarm on."
);
pyo3::create_exception!(
    krypto_py,
    KeyNotFoundError,
    Error,
    "`Error::KeyNotFound`: the name does not exist in the store."
);
pyo3::create_exception!(
    krypto_py,
    WrongKeyError,
    Error,
    "`Error::WrongKey`: another key generation. Routing, not tampering."
);

fn err(e: krypto::Error) -> PyErr {
    let msg = e.to_string();
    match e {
        krypto::Error::Io(_) => IoError::new_err(msg),
        krypto::Error::Hardening(_) => HardeningError::new_err(msg),
        krypto::Error::Format(_) => FormatError::new_err(msg),
        krypto::Error::Auth => AuthError::new_err(msg),
        krypto::Error::KeyNotFound => KeyNotFoundError::new_err(msg),
        krypto::Error::WrongKey => WrongKeyError::new_err(msg),
        _ => Error::new_err(msg),
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn array<const N: usize>(b: &[u8], what: &str) -> PyResult<[u8; N]> {
    b.try_into()
        .map_err(|_| FormatError::new_err(format!("{what} is {N} bytes, got {}", b.len())))
}

// --------------------------------------------------------------------------- //
// SecretBuf, SecretString
// --------------------------------------------------------------------------- //

/// `krypto::SecretBuf`: bytes in locked, guarded memory, wiped when dropped.
/// A `MasterKey.from_bytes` consumes it, as in Rust; using it afterwards is a
/// `ValueError`.
#[pyclass(frozen, module = "krypto_py", name = "SecretBuf")]
struct SecretBuf {
    inner: Mutex<Option<krypto::SecretBuf>>,
}

impl SecretBuf {
    fn wrap(buf: krypto::SecretBuf) -> Self {
        Self {
            inner: Mutex::new(Some(buf)),
        }
    }
    fn with<R>(&self, f: impl FnOnce(&krypto::SecretBuf) -> PyResult<R>) -> PyResult<R> {
        match lock(&self.inner).as_ref() {
            Some(b) => f(b),
            None => Err(PyValueError::new_err("this SecretBuf was consumed")),
        }
    }
    fn take(&self) -> PyResult<krypto::SecretBuf> {
        lock(&self.inner)
            .take()
            .ok_or_else(|| PyValueError::new_err("this SecretBuf was consumed"))
    }
}

#[pymethods]
impl SecretBuf {
    /// Copies `v` into locked memory. A `bytearray` is zeroed afterwards, as
    /// Rust zeroizes the source; a `bytes` object cannot be, so it stays as
    /// Python keeps it.
    #[staticmethod]
    fn from_vec(v: &Bound<'_, PyAny>) -> PyResult<Self> {
        let data = if let Ok(ba) = v.cast::<PyByteArray>() {
            let data = ba.to_vec();
            // SAFETY: the GIL is held and nothing else borrows the buffer
            // during this call.
            unsafe { ba.as_bytes_mut() }.fill(0);
            data
        } else if let Ok(b) = v.cast::<PyBytes>() {
            b.as_bytes().to_vec()
        } else {
            return Err(PyTypeError::new_err("from_vec takes bytes or bytearray"));
        };
        krypto::SecretBuf::from_vec(data)
            .map(Self::wrap)
            .map_err(err)
    }

    /// `len` bytes from the OS CSPRNG, at most `MAX_RANDOM_BYTES`.
    #[staticmethod]
    fn random(len: usize) -> PyResult<Self> {
        krypto::SecretBuf::random(len).map(Self::wrap).map_err(err)
    }

    /// `random` with the caller's own cap for this call.
    #[staticmethod]
    fn random_with_limit(len: usize, limit: usize) -> PyResult<Self> {
        krypto::SecretBuf::random_with_limit(len, limit)
            .map(Self::wrap)
            .map_err(err)
    }

    fn len(&self) -> PyResult<usize> {
        self.with(|b| Ok(b.len()))
    }

    fn is_empty(&self) -> PyResult<bool> {
        self.with(|b| Ok(b.is_empty()))
    }

    fn __len__(&self) -> PyResult<usize> {
        self.len()
    }

    /// Calls `f` with the bytes and returns what `f` returns. `f` gets a
    /// Python `bytes` copy, which is neither locked nor wiped.
    fn expose(&self, py: Python<'_>, f: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let copy = self.with(|b| Ok(Zeroizing::new(b.expose(|s| s.to_vec()))))?;
        Ok(f.call1((PyBytes::new(py, &copy),))?.unbind())
    }

    fn __repr__(&self) -> String {
        match lock(&self.inner).as_ref() {
            Some(b) => format!("SecretBuf([REDACTED], len={})", b.len()),
            None => "SecretBuf(<consumed>)".into(),
        }
    }
}

/// `krypto::SecretString`: a UTF-8 secret in locked memory, wiped when dropped.
#[pyclass(frozen, module = "krypto_py", name = "SecretString")]
struct SecretString {
    inner: krypto::SecretString,
}

#[pymethods]
impl SecretString {
    /// Copies `s` into locked memory. The Python `str` stays as Python keeps it.
    #[staticmethod]
    fn from_string(s: String) -> PyResult<Self> {
        krypto::SecretString::from_string(s)
            .map(|inner| Self { inner })
            .map_err(err)
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Calls `f` with the text and returns what `f` returns. `f` gets a Python
    /// `str` copy, which is neither locked nor wiped.
    fn expose_str(&self, f: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let copy = Zeroizing::new(self.inner.expose_str(|s| s.to_string()));
        Ok(f.call1((copy.as_str(),))?.unbind())
    }

    fn __repr__(&self) -> String {
        format!("SecretString([REDACTED], len={})", self.inner.len())
    }
}

// --------------------------------------------------------------------------- //
// MasterKey, DerivedKey, hmac_sha256
// --------------------------------------------------------------------------- //

/// `krypto::MasterKey`.
#[pyclass(frozen, module = "krypto_py", name = "MasterKey")]
struct MasterKey {
    inner: krypto::MasterKey,
}

#[pymethods]
impl MasterKey {
    #[staticmethod]
    fn from_secret_file(path: PathBuf) -> PyResult<Self> {
        krypto::MasterKey::from_secret_file(path)
            .map(|inner| Self { inner })
            .map_err(err)
    }

    /// Consumes `key`, as in Rust.
    #[staticmethod]
    fn from_bytes(key: &SecretBuf) -> PyResult<Self> {
        krypto::MasterKey::from_bytes(key.take()?)
            .map(|inner| Self { inner })
            .map_err(err)
    }

    fn derive(&self, info: &[u8], salt: &[u8]) -> PyResult<DerivedKey> {
        self.inner
            .derive(info, salt)
            .map(|inner| DerivedKey { inner })
            .map_err(err)
    }

    /// The key id (16 bytes), as `MasterKey::key_id` (0.8.0).
    fn key_id<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let id = self.inner.key_id().map_err(err)?;
        Ok(PyBytes::new(py, &id))
    }

    fn __repr__(&self) -> &'static str {
        "MasterKey([REDACTED])"
    }
}

/// `krypto::DerivedKey`. Made only by `MasterKey.derive`.
#[pyclass(frozen, module = "krypto_py", name = "DerivedKey")]
struct DerivedKey {
    inner: krypto::DerivedKey,
}

#[pymethods]
impl DerivedKey {
    fn __repr__(&self) -> &'static str {
        "DerivedKey([REDACTED])"
    }
}

#[pyfunction]
fn hmac_sha256<'py>(
    py: Python<'py>,
    key: &DerivedKey,
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let mac = krypto::hmac_sha256(&key.inner, data).map_err(err)?;
    Ok(PyBytes::new(py, &mac))
}

// --------------------------------------------------------------------------- //
// AEAD
// --------------------------------------------------------------------------- //

/// `krypto::Alg`.
#[pyclass(eq, eq_int, frozen, module = "krypto_py", name = "Alg")]
#[derive(Clone, Copy, PartialEq)]
enum Alg {
    Aegis256,
    XChaCha20Poly1305,
    Aes256Gcm,
}

impl From<Alg> for krypto::Alg {
    fn from(a: Alg) -> Self {
        match a {
            Alg::Aegis256 => krypto::Alg::Aegis256,
            Alg::XChaCha20Poly1305 => krypto::Alg::XChaCha20Poly1305,
            Alg::Aes256Gcm => krypto::Alg::Aes256Gcm,
        }
    }
}

#[pyfunction]
fn seal<'py>(
    py: Python<'py>,
    key: &DerivedKey,
    key_id: &[u8],
    plaintext: &SecretBuf,
    alg: &Alg,
) -> PyResult<Bound<'py, PyBytes>> {
    let kid = array::<16>(key_id, "key_id")?;
    let blob =
        plaintext.with(|pt| krypto::seal(&key.inner, &kid, pt, (*alg).into()).map_err(err))?;
    Ok(PyBytes::new(py, &blob))
}

#[pyfunction]
fn open(key: &DerivedKey, blob: &[u8]) -> PyResult<SecretBuf> {
    krypto::open(&key.inner, blob)
        .map(SecretBuf::wrap)
        .map_err(err)
}

#[pyfunction]
fn reseal<'py>(
    py: Python<'py>,
    old: &DerivedKey,
    new: &DerivedKey,
    new_key_id: &[u8],
    blob: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let kid = array::<16>(new_key_id, "new_key_id")?;
    let out = krypto::reseal(&old.inner, &new.inner, &kid, blob).map_err(err)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
fn blob_key_id<'py>(py: Python<'py>, blob: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let id = krypto::blob_key_id(blob).map_err(err)?;
    Ok(PyBytes::new(py, &id))
}

// --------------------------------------------------------------------------- //
// SecretStore
// --------------------------------------------------------------------------- //

/// `krypto::SecretStore`. In Rust it borrows the `MasterKey`; here it keeps
/// the `MasterKey` object alive instead. `rotate` consumes it, as in Rust.
#[pyclass(frozen, module = "krypto_py", name = "SecretStore")]
struct SecretStore {
    // Field order matters: the store is dropped before the master key it
    // refers to.
    store: Mutex<Option<krypto::SecretStore<'static>>>,
    _master: Py<MasterKey>,
}

/// A `&'static` to the `krypto::MasterKey` inside `master`.
///
/// SAFETY of the callers: the reference is only kept in a `SecretStore` that
/// also holds `master`, so the object outlives it; `MasterKey` is frozen, so
/// what it points to never moves or changes.
fn master_ref(master: &Py<MasterKey>) -> &'static krypto::MasterKey {
    let r: &krypto::MasterKey = &master.get().inner;
    // SAFETY: see above.
    unsafe { &*(r as *const krypto::MasterKey) }
}

impl SecretStore {
    fn with<R>(
        &self,
        f: impl FnOnce(&mut krypto::SecretStore<'static>) -> PyResult<R>,
    ) -> PyResult<R> {
        match lock(&self.store).as_mut() {
            Some(s) => f(s),
            None => Err(PyValueError::new_err("this SecretStore was rotated away")),
        }
    }
}

#[pymethods]
impl SecretStore {
    #[staticmethod]
    fn open(path: PathBuf, master: Py<MasterKey>) -> PyResult<Self> {
        let store = krypto::SecretStore::open(path, master_ref(&master)).map_err(err)?;
        Ok(Self {
            store: Mutex::new(Some(store)),
            _master: master,
        })
    }

    fn put(&self, name: &str, secret: &SecretBuf) -> PyResult<()> {
        self.with(|s| secret.with(|b| s.put(name, b).map_err(err)))
    }

    fn get(&self, name: &str) -> PyResult<SecretBuf> {
        self.with(|s| s.get(name).map(SecretBuf::wrap).map_err(err))
    }

    fn delete(&self, name: &str) -> PyResult<()> {
        self.with(|s| s.delete(name).map_err(err))
    }

    fn contains(&self, name: &str) -> PyResult<bool> {
        self.with(|s| Ok(s.contains(name)))
    }

    fn list(&self, prefix: &str) -> PyResult<Vec<String>> {
        self.with(|s| Ok(s.list(prefix)))
    }

    /// Re-encrypts the store under `new_master` and returns the new handle;
    /// this one is consumed, as in Rust.
    fn rotate(&self, new_master: Py<MasterKey>) -> PyResult<SecretStore> {
        let old = lock(&self.store)
            .take()
            .ok_or_else(|| PyValueError::new_err("this SecretStore was rotated away"))?;
        let store = old.rotate(master_ref(&new_master)).map_err(err)?;
        Ok(SecretStore {
            store: Mutex::new(Some(store)),
            _master: new_master,
        })
    }

    fn __repr__(&self) -> &'static str {
        "SecretStore"
    }
}

// --------------------------------------------------------------------------- //
// Utilities and hardening
// --------------------------------------------------------------------------- //

#[pyfunction]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    krypto::ct_eq(a, b)
}

#[pyfunction]
fn sha256<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, &krypto::sha256(data))
}

#[pyfunction]
fn random_bytes<'py>(py: Python<'py>, len: usize) -> PyResult<Bound<'py, PyBytes>> {
    let b = krypto::random_bytes(len).map_err(err)?;
    Ok(PyBytes::new(py, &b))
}

#[pyfunction]
fn random_bytes_with_limit<'py>(
    py: Python<'py>,
    len: usize,
    limit: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let b = krypto::random_bytes_with_limit(len, limit).map_err(err)?;
    Ok(PyBytes::new(py, &b))
}

/// Hardens the calling process, as in Rust.
#[pyfunction]
fn harden_process() -> PyResult<()> {
    krypto::harden_process().map_err(err)
}

#[pyfunction]
fn no_new_privs() -> PyResult<()> {
    krypto::no_new_privs().map_err(err)
}

/// Closes every descriptor above stderr in the calling process — the Python
/// interpreter's own included.
#[pyfunction]
fn close_inherited_fds() -> PyResult<()> {
    krypto::close_inherited_fds().map_err(err)
}

#[pyfunction]
fn drop_filesystem(dir: PathBuf) -> PyResult<()> {
    krypto::drop_filesystem(dir).map_err(err)
}

// --------------------------------------------------------------------------- //
// password
// --------------------------------------------------------------------------- //

/// `krypto::password::Preset`.
#[pyclass(eq, eq_int, frozen, module = "krypto_py.password", name = "Preset")]
#[derive(Clone, Copy, PartialEq)]
enum Preset {
    Interactive,
    Balanced,
    High,
}

impl From<Preset> for krypto::password::Preset {
    fn from(p: Preset) -> Self {
        match p {
            Preset::Interactive => krypto::password::Preset::Interactive,
            Preset::Balanced => krypto::password::Preset::Balanced,
            Preset::High => krypto::password::Preset::High,
        }
    }
}

#[pyfunction(name = "hash")]
fn password_hash(py: Python<'_>, password: &SecretString, preset: &Preset) -> PyResult<String> {
    let pw = &password.inner;
    let preset: krypto::password::Preset = (*preset).into();
    py.detach(|| krypto::password::hash(pw, preset))
        .map_err(err)
}

#[pyfunction(name = "verify")]
fn password_verify(py: Python<'_>, password: &SecretString, phc: &str) -> PyResult<()> {
    let pw = &password.inner;
    py.detach(|| krypto::password::verify(pw, phc)).map_err(err)
}

#[pyfunction(name = "derive_key")]
fn password_derive_key(
    py: Python<'_>,
    password: &SecretString,
    salt: &[u8],
    preset: &Preset,
) -> PyResult<SecretBuf> {
    let pw = &password.inner;
    let preset: krypto::password::Preset = (*preset).into();
    py.detach(|| krypto::password::derive_key(pw, salt, preset))
        .map(SecretBuf::wrap)
        .map_err(err)
}

// --------------------------------------------------------------------------- //
// sign, exchange
// --------------------------------------------------------------------------- //

fn keypair<'py>(
    py: Python<'py>,
    pair: (krypto::SecretBuf, Vec<u8>),
) -> (SecretBuf, Bound<'py, PyBytes>) {
    (SecretBuf::wrap(pair.0), PyBytes::new(py, &pair.1))
}

#[pyfunction]
fn ed25519_keypair<'py>(py: Python<'py>) -> PyResult<(SecretBuf, Bound<'py, PyBytes>)> {
    let (s, p) = krypto::sign::ed25519_keypair().map_err(err)?;
    Ok(keypair(py, (s, p.to_vec())))
}

#[pyfunction]
fn ed25519_public<'py>(py: Python<'py>, seed: &SecretBuf) -> PyResult<Bound<'py, PyBytes>> {
    let p = seed.with(|s| krypto::sign::ed25519_public(s).map_err(err))?;
    Ok(PyBytes::new(py, &p))
}

#[pyfunction]
fn ed25519_sign<'py>(
    py: Python<'py>,
    seed: &SecretBuf,
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sig = seed.with(|s| krypto::sign::ed25519_sign(s, message).map_err(err))?;
    Ok(PyBytes::new(py, &sig))
}

#[pyfunction]
fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> PyResult<()> {
    krypto::sign::ed25519_verify(public, message, signature).map_err(err)
}

#[pyfunction]
fn ecdsa_p256_keypair<'py>(py: Python<'py>) -> PyResult<(SecretBuf, Bound<'py, PyBytes>)> {
    Ok(keypair(
        py,
        krypto::sign::ecdsa_p256_keypair().map_err(err)?,
    ))
}

#[pyfunction]
fn ecdsa_p256_public<'py>(py: Python<'py>, pkcs8: &SecretBuf) -> PyResult<Bound<'py, PyBytes>> {
    let p = pkcs8.with(|s| krypto::sign::ecdsa_p256_public(s).map_err(err))?;
    Ok(PyBytes::new(py, &p))
}

#[pyfunction]
fn ecdsa_p256_sign<'py>(
    py: Python<'py>,
    pkcs8: &SecretBuf,
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let sig = pkcs8.with(|s| krypto::sign::ecdsa_p256_sign(s, message).map_err(err))?;
    Ok(PyBytes::new(py, &sig))
}

#[pyfunction]
fn ecdsa_p256_verify(public_sec1: &[u8], message: &[u8], sig_der: &[u8]) -> PyResult<()> {
    krypto::sign::ecdsa_p256_verify(public_sec1, message, sig_der).map_err(err)
}

#[pyfunction]
fn x25519_keypair<'py>(py: Python<'py>) -> PyResult<(SecretBuf, Bound<'py, PyBytes>)> {
    let (s, p) = krypto::exchange::x25519_keypair().map_err(err)?;
    Ok(keypair(py, (s, p.to_vec())))
}

#[pyfunction]
fn x25519_public<'py>(py: Python<'py>, secret: &SecretBuf) -> PyResult<Bound<'py, PyBytes>> {
    let p = secret.with(|s| krypto::exchange::x25519_public(s).map_err(err))?;
    Ok(PyBytes::new(py, &p))
}

#[pyfunction]
fn x25519_shared(secret: &SecretBuf, peer_public: &[u8]) -> PyResult<SecretBuf> {
    secret.with(|s| {
        krypto::exchange::x25519_shared(s, peer_public)
            .map(SecretBuf::wrap)
            .map_err(err)
    })
}

// --------------------------------------------------------------------------- //
// hex, base64
// --------------------------------------------------------------------------- //

#[pyfunction(name = "encode")]
fn hex_encode(bytes: &[u8]) -> String {
    krypto::hex::encode(bytes)
}

#[pyfunction(name = "decode")]
fn hex_decode<'py>(py: Python<'py>, s: &str) -> PyResult<Bound<'py, PyBytes>> {
    let b = krypto::hex::decode(s).map_err(err)?;
    Ok(PyBytes::new(py, &b))
}

#[pyfunction(name = "encode")]
fn b64_encode(bytes: &[u8]) -> String {
    krypto::base64::encode(bytes)
}

#[pyfunction(name = "encode_nopad")]
fn b64_encode_nopad(bytes: &[u8]) -> String {
    krypto::base64::encode_nopad(bytes)
}

#[pyfunction(name = "decode")]
fn b64_decode<'py>(py: Python<'py>, s: &str) -> PyResult<Bound<'py, PyBytes>> {
    let b = krypto::base64::decode(s).map_err(err)?;
    Ok(PyBytes::new(py, &b))
}

#[pyfunction(name = "decode_nopad")]
fn b64_decode_nopad<'py>(py: Python<'py>, s: &str) -> PyResult<Bound<'py, PyBytes>> {
    let b = krypto::base64::decode_nopad(s).map_err(err)?;
    Ok(PyBytes::new(py, &b))
}

// --------------------------------------------------------------------------- //
// The module
// --------------------------------------------------------------------------- //

/// The submodule `krypto_py.<name>`: an attribute of the parent, and importable.
fn submodule<'py>(
    parent: &Bound<'py, PyModule>,
    name: &str,
    fill: impl FnOnce(&Bound<'py, PyModule>) -> PyResult<()>,
) -> PyResult<()> {
    let py = parent.py();
    let full = format!("krypto_py.{name}");
    let m = PyModule::new(py, &full)?;
    fill(&m)?;
    parent.add(name, &m)?;
    py.import("sys")?.getattr("modules")?.set_item(&full, &m)?;
    Ok(())
}

fn add_errors(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("Error", py.get_type::<Error>())?;
    m.add("IoError", py.get_type::<IoError>())?;
    m.add("HardeningError", py.get_type::<HardeningError>())?;
    m.add("FormatError", py.get_type::<FormatError>())?;
    m.add("AuthError", py.get_type::<AuthError>())?;
    m.add("KeyNotFoundError", py.get_type::<KeyNotFoundError>())?;
    m.add("WrongKeyError", py.get_type::<WrongKeyError>())?;
    Ok(())
}

#[pymodule]
fn krypto_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("VERSION", krypto::VERSION)?;
    m.add("__version__", krypto::VERSION)?;
    m.add("MAX_MASTER_KEY_BYTES", krypto::MAX_MASTER_KEY_BYTES)?;
    m.add("MAX_DERIVE_INPUT_BYTES", krypto::MAX_DERIVE_INPUT_BYTES)?;
    m.add("MAX_STORE_BYTES", krypto::MAX_STORE_BYTES)?;
    m.add("MAX_RANDOM_BYTES", krypto::MAX_RANDOM_BYTES)?;
    add_errors(m)?;
    m.add_class::<SecretBuf>()?;
    m.add_class::<SecretString>()?;
    m.add_class::<MasterKey>()?;
    m.add_class::<DerivedKey>()?;
    m.add_class::<SecretStore>()?;
    m.add_class::<Alg>()?;
    m.add_function(wrap_pyfunction!(hmac_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(seal, m)?)?;
    m.add_function(wrap_pyfunction!(open, m)?)?;
    m.add_function(wrap_pyfunction!(reseal, m)?)?;
    m.add_function(wrap_pyfunction!(blob_key_id, m)?)?;
    m.add_function(wrap_pyfunction!(ct_eq, m)?)?;
    m.add_function(wrap_pyfunction!(sha256, m)?)?;
    m.add_function(wrap_pyfunction!(random_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(random_bytes_with_limit, m)?)?;
    m.add_function(wrap_pyfunction!(harden_process, m)?)?;
    m.add_function(wrap_pyfunction!(no_new_privs, m)?)?;
    m.add_function(wrap_pyfunction!(close_inherited_fds, m)?)?;
    m.add_function(wrap_pyfunction!(drop_filesystem, m)?)?;

    submodule(m, "error", add_errors)?;
    submodule(m, "harden", |s| {
        s.add_function(wrap_pyfunction!(harden_process, s)?)?;
        s.add_function(wrap_pyfunction!(no_new_privs, s)?)?;
        s.add_function(wrap_pyfunction!(close_inherited_fds, s)?)?;
        s.add_function(wrap_pyfunction!(drop_filesystem, s)?)
    })?;
    submodule(m, "password", |s| {
        s.add_class::<Preset>()?;
        s.add_function(wrap_pyfunction!(password_hash, s)?)?;
        s.add_function(wrap_pyfunction!(password_verify, s)?)?;
        s.add_function(wrap_pyfunction!(password_derive_key, s)?)
    })?;
    submodule(m, "sign", |s| {
        s.add("ED25519_SEED_LEN", krypto::sign::ED25519_SEED_LEN)?;
        s.add("ED25519_PUBLIC_LEN", krypto::sign::ED25519_PUBLIC_LEN)?;
        s.add("ED25519_SIG_LEN", krypto::sign::ED25519_SIG_LEN)?;
        s.add_function(wrap_pyfunction!(ed25519_keypair, s)?)?;
        s.add_function(wrap_pyfunction!(ed25519_public, s)?)?;
        s.add_function(wrap_pyfunction!(ed25519_sign, s)?)?;
        s.add_function(wrap_pyfunction!(ed25519_verify, s)?)?;
        s.add_function(wrap_pyfunction!(ecdsa_p256_keypair, s)?)?;
        s.add_function(wrap_pyfunction!(ecdsa_p256_public, s)?)?;
        s.add_function(wrap_pyfunction!(ecdsa_p256_sign, s)?)?;
        s.add_function(wrap_pyfunction!(ecdsa_p256_verify, s)?)
    })?;
    submodule(m, "exchange", |s| {
        s.add("X25519_KEY_LEN", krypto::exchange::X25519_KEY_LEN)?;
        s.add_function(wrap_pyfunction!(x25519_keypair, s)?)?;
        s.add_function(wrap_pyfunction!(x25519_public, s)?)?;
        s.add_function(wrap_pyfunction!(x25519_shared, s)?)
    })?;
    submodule(m, "hex", |s| {
        s.add_function(wrap_pyfunction!(hex_encode, s)?)?;
        s.add_function(wrap_pyfunction!(hex_decode, s)?)
    })?;
    submodule(m, "base64", |s| {
        s.add_function(wrap_pyfunction!(b64_encode, s)?)?;
        s.add_function(wrap_pyfunction!(b64_encode_nopad, s)?)?;
        s.add_function(wrap_pyfunction!(b64_decode, s)?)?;
        s.add_function(wrap_pyfunction!(b64_decode_nopad, s)?)
    })?;
    Ok(())
}
