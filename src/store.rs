// SPDX-License-Identifier: MIT OR Apache-2.0
//! `SecretStore` — encrypted key-value store on file.
//!
//! Every value is encrypted with a **per-key-name** derived DEK
//! (`HKDF(master, salt, info = "krypto/store/v1|" + name)`). That binds the
//! value to its name: a blob cannot be moved to another name without `open`
//! failing with `Auth`. Key names are plaintext (addresses, not secrets).
//! Writes are atomic (tmp + fsync + rename), file mode 0600. One handle per
//! file at a time, held by a lock (0.7.2).

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::aead::{self, Alg};
use crate::error::Error;
use crate::kdf::{DerivedKey, MasterKey};
use crate::secret::SecretBuf;

const STORE_MAGIC: &[u8; 4] = b"FST1";
const STORE_VER: u8 = 1;
const SALT_LEN: usize = 16;
const KEY_ID_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + KEY_ID_LEN;

/// Upper bound on a store file. The store holds small secrets (keys/tokens);
/// 16 MiB is very generous and prevents OOM on a tampered/bloated file
/// (bounded input).
pub const MAX_STORE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum length of a key name in the store.
const MAX_NAME_LEN: usize = 512;

/// Validate a key name: non-empty, bounded, printable ASCII only.
///
/// Printable ASCII (`[\x20-\x7e]`): names are listed back out through `list()`
/// and may end up in a consumer's log, so a control character has no business
/// in one.
fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::Format("key name is empty".into()));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(Error::Format(format!(
            "key name is {} bytes — max {MAX_NAME_LEN}",
            name.len()
        )));
    }
    if let Some(c) = name.chars().find(|&c| !(' '..='~').contains(&c)) {
        return Err(Error::Format(format!(
            "key name contains the illegal character {c:?} — printable ASCII only, \
             because names are listed out and may end up in a log"
        )));
    }
    Ok(())
}

/// File-based, encrypted KV store. The master key is borrowed for the store's lifetime.
///
/// One handle per file (0.7.2). A store reads the whole file into memory and
/// writes the whole file back, so two handles on one file would overwrite each
/// other's writes. The caller is responsible for not opening a file twice at
/// once; krypto also guards against it, with a lock taken in [`SecretStore::open`].
pub struct SecretStore<'a> {
    path: PathBuf,
    master: &'a MasterKey,
    salt: [u8; SALT_LEN],
    key_id: [u8; KEY_ID_LEN],
    entries: HashMap<String, Vec<u8>>, // name -> FAFN blob
    /// The lock that keeps this file to this handle, held while it lives
    /// (0.7.2). `None` only when the directory cannot be written, so nothing
    /// can be saved there either.
    lock: Option<std::fs::File>,
}

impl<'a> SecretStore<'a> {
    /// Open an existing store, or create a new one if the file is missing.
    ///
    /// Distinguishes `ErrorKind::NotFound` — any other I/O error (permission,
    /// ELOOP, …) is propagated instead of being treated as "empty store", so we
    /// never rename a fresh empty store over an existing one we simply failed
    /// to read.
    ///
    /// (0.7.2) Takes an exclusive lock on the file for as long as the handle
    /// lives. If another handle, in this or another process, holds it, `open`
    /// fails at once with [`Error::Io`] (`WouldBlock`) instead of letting the two
    /// overwrite each other's writes.
    pub fn open(path: impl AsRef<Path>, master: &'a MasterKey) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let lock = take_lock(&path)?;
        match read_capped(&path, MAX_STORE_BYTES)? {
            Some(data) => {
                make_private(&path)?;
                Self::load(path, master, &data, lock)
            }
            None => {
                // The file does not exist → create a new, empty store.
                let mut salt = [0u8; SALT_LEN];
                let mut key_id = [0u8; KEY_ID_LEN];
                getrandom::fill(&mut salt)
                    .map_err(|e| Error::Hardening(format!("getrandom: {e}")))?;
                getrandom::fill(&mut key_id)
                    .map_err(|e| Error::Hardening(format!("getrandom: {e}")))?;
                let store = SecretStore {
                    path,
                    master,
                    salt,
                    key_id,
                    entries: HashMap::new(),
                    lock,
                };
                store.persist()?;
                Ok(store)
            }
        }
    }

    /// Store a secret under `name` (overwrites an existing one).
    ///
    /// The name is validated on **character set and length**, not just length.
    /// Names are not secret and are exposed through [`SecretStore::list`] — a
    /// name with a newline could shift lines in a consumer's log, and an empty
    /// name is not a key anyone can look up again.
    pub fn put(&mut self, name: &str, secret: &SecretBuf) -> Result<(), Error> {
        validate_name(name)?;
        let dek = self.dek_for(name)?;
        let blob = aead::seal(&dek, &self.key_id, secret, Alg::Aegis256)?;
        // Persist BEFORE memory and disk can diverge: if persist fails, roll
        // back the insert so a later `get` cannot return a value that was
        // never stored.
        let previous = self.entries.insert(name.to_string(), blob);
        if let Err(e) = self.persist() {
            match previous {
                Some(old) => {
                    self.entries.insert(name.to_string(), old);
                }
                None => {
                    self.entries.remove(name);
                }
            }
            return Err(e);
        }
        Ok(())
    }

    /// Fetch a secret. `KeyNotFound` if the name does not exist.
    ///
    /// A blob that does not hold is [`Error::Auth`]: tampered, sealed under
    /// another key, or carrying another key id than the store's (0.7.3). A
    /// store holds one key generation, and `rotate` replaces it whole, so a
    /// different key id inside a store is never routing; before 0.7.3 it gave
    /// [`Error::WrongKey`].
    pub fn get(&self, name: &str) -> Result<SecretBuf, Error> {
        let blob = self.entries.get(name).ok_or(Error::KeyNotFound)?;
        // The key id in the blob and in the store header must agree; a change to
        // either is tampering. Neither is authenticated on its own (the blob's is
        // AAD, verified by `open`), so the check is what catches the header's.
        if aead::blob_key_id(blob)? != self.key_id {
            return Err(Error::Auth);
        }
        let dek = self.dek_for(name)?;
        aead::open(&dek, blob)
    }

    /// Delete a secret. Not an error if the name does not exist.
    pub fn delete(&mut self, name: &str) -> Result<(), Error> {
        if let Some(old) = self.entries.remove(name) {
            if let Err(e) = self.persist() {
                self.entries.insert(name.to_string(), old); // roll back on persist failure
                return Err(e);
            }
        }
        Ok(())
    }

    /// Whether a name exists (without decrypting).
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Sorted key names with the given prefix (names are not secret).
    pub fn list(&self, prefix: &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .entries
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// Re-encrypt the whole store under a new master key — the rotation
    /// *action* (0.6.0). krypto is stateless: both keys come from the caller,
    /// which owns when and why a rotation happens.
    ///
    /// Consumes the store (it is bound to the old master's lifetime) and
    /// returns a new handle bound to `new_master`, with a fresh salt and a
    /// fresh key-generation id. Everything is decrypted with the old master
    /// FIRST — if any entry fails ([`Error::Auth`] on a wrong old key or
    /// tampering), nothing is written and the file is untouched. The file
    /// then flips old → new in one atomic rename: never a half-rotated store.
    ///
    /// The handle is consumed even on failure (a stale handle over a replaced
    /// file could persist old-generation data back over the new one) — on
    /// error, reopen the file; it is unchanged.
    ///
    /// A store file that was rotated away from an old master fails `get` with
    /// [`Error::Auth`] under that master (the per-name DEKs no longer match).
    /// A blob from another generation inside a store is [`Error::Auth`] too
    /// (0.7.3): it can only get there by tampering.
    pub fn rotate<'b>(self, new_master: &'b MasterKey) -> Result<SecretStore<'b>, Error> {
        // 1. Decrypt everything with the old master before anything is written.
        let mut names: Vec<String> = self.entries.keys().cloned().collect();
        names.sort();
        let mut plain = Vec::with_capacity(names.len());
        for name in names {
            let secret = self.get(&name)?;
            plain.push((name, secret));
        }

        // 2. Build the new generation in memory.
        let mut salt = [0u8; SALT_LEN];
        let mut key_id = [0u8; KEY_ID_LEN];
        getrandom::fill(&mut salt).map_err(|e| Error::Hardening(format!("getrandom: {e}")))?;
        getrandom::fill(&mut key_id).map_err(|e| Error::Hardening(format!("getrandom: {e}")))?;
        let mut new_store = SecretStore {
            path: self.path.clone(),
            master: new_master,
            salt,
            key_id,
            entries: HashMap::new(),
            lock: self.lock, // the new handle keeps the file's lock (0.7.2)
        };
        for (name, secret) in &plain {
            let dek = new_store.dek_for(name)?;
            let blob = aead::seal(&dek, &new_store.key_id, secret, Alg::Aegis256)?;
            new_store.entries.insert(name.clone(), blob);
        }

        // 3. One atomic write replaces the file.
        new_store.persist()?;
        Ok(new_store)
    }

    // --- internal ---

    fn dek_for(&self, name: &str) -> Result<DerivedKey, Error> {
        let mut info = Vec::with_capacity(16 + name.len());
        info.extend_from_slice(b"krypto/store/v1|");
        info.extend_from_slice(name.as_bytes());
        self.master.derive(&info, &self.salt)
    }

    fn load(
        path: PathBuf,
        master: &'a MasterKey,
        data: &[u8],
        lock: Option<std::fs::File>,
    ) -> Result<Self, Error> {
        if data.len() < HEADER_LEN {
            return Err(Error::Format("store header truncated".into()));
        }
        if &data[0..4] != STORE_MAGIC {
            return Err(Error::Format("wrong store magic".into()));
        }
        if data[4] != STORE_VER {
            return Err(Error::Format(format!(
                "unsupported store version {}",
                data[4]
            )));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[5..5 + SALT_LEN]);
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&data[5 + SALT_LEN..HEADER_LEN]);

        let mut entries = HashMap::new();
        let mut off = HEADER_LEN;
        while off < data.len() {
            if off + 2 > data.len() {
                return Err(Error::Format("store truncated (name length)".into()));
            }
            let nlen = u16::from_le_bytes([data[off], data[off + 1]]) as usize;
            off += 2;
            // checked_add: a tampered/corrupt file could otherwise wrap off+len
            // and make the bounds check falsely pass → panic in the slice below.
            match off.checked_add(nlen) {
                Some(end) if end <= data.len() => {}
                _ => return Err(Error::Format("store truncated (name)".into())),
            }
            let name = String::from_utf8(data[off..off + nlen].to_vec())
                .map_err(|_| Error::Format("invalid UTF-8 in key name".into()))?;
            // The same fence as `put`. Without it the rule holds only for what
            // THIS process wrote: a corrupt or tampered file could carry a name
            // with a newline straight out through `list()`, which is documented
            // as ending up in a consumer's log.
            validate_name(&name)?;
            off += nlen;
            if off + 4 > data.len() {
                return Err(Error::Format("store truncated (blob length)".into()));
            }
            let blen = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
                as usize;
            off += 4;
            match off.checked_add(blen) {
                Some(end) if end <= data.len() => {}
                _ => return Err(Error::Format("store truncated (blob)".into())),
            }
            if entries
                .insert(name, data[off..off + blen].to_vec())
                .is_some()
            {
                return Err(Error::Format("duplicate key name in store".into()));
            }
            off += blen;
        }
        Ok(SecretStore {
            path,
            master,
            salt,
            key_id,
            entries,
            lock,
        })
    }

    fn persist(&self) -> Result<(), Error> {
        let mut buf = Vec::new();
        buf.extend_from_slice(STORE_MAGIC);
        buf.push(STORE_VER);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.key_id);
        let mut names: Vec<&String> = self.entries.keys().collect();
        names.sort(); // deterministic file
        for name in names {
            let blob = &self.entries[name];
            let blen = u32::try_from(blob.len())
                .map_err(|_| Error::Format("blob too big for the store format".into()))?;
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(&blen.to_le_bytes());
            buf.extend_from_slice(blob);
        }
        // `open` refuses a file past MAX_STORE_BYTES, so writing one would lock
        // every secret in it out (0.7.2). `put` rolls back on this error.
        if buf.len() > MAX_STORE_BYTES {
            return Err(Error::Format(format!(
                "the store would grow past {MAX_STORE_BYTES} bytes, which `open` refuses"
            )));
        }
        atomic_write(&self.path, &buf)
    }
}

/// Read a file with an upper size cap. `Ok(None)` = the file does not exist
/// (the caller creates a new store); `Ok(Some(bytes))` = contents within the
/// cap; `Err(Format)` = too big (bounded input, no OOM); other I/O errors → `Err(Io)`.
fn read_capped(path: &Path, cap: usize) -> Result<Option<Vec<u8>>, Error> {
    use std::io::Read;
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    };
    let mut bytes = Vec::new();
    f.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(Error::Format(format!(
            "store file is too big (> {cap} bytes)"
        )));
    }
    Ok(Some(bytes))
}

/// The directory and file name of a store path.
fn dir_and_name(path: &Path) -> (PathBuf, &str) {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("store");
    (dir, fname)
}

/// Take the lock that keeps a store file to one handle at a time (0.7.2).
///
/// The lock is the kernel's (`flock`) on an empty `.<name>.lock` beside the
/// store file, not on the file itself, because every write replaces that.
/// The kernel drops it when the handle is dropped or the process ends, even in
/// a crash, so the lock file never goes stale; it is never deleted. `None`
/// when the directory cannot be written: nothing can be saved there either.
fn take_lock(path: &Path) -> Result<Option<std::fs::File>, Error> {
    use std::fs::TryLockError;
    let (dir, fname) = dir_and_name(path);
    let lock_path = dir.join(format!(".{fname}.lock"));
    for _ in 0..3 {
        let Some(f) = open_lock_file(&lock_path)? else {
            return Ok(None);
        };
        match f.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "the store file is already open, in this or another process",
                )))
            }
            Err(TryLockError::Error(e)) => return Err(Error::Io(e)),
        }
        // The file at the path must still be the one now locked. If someone
        // replaced or removed it meanwhile, another handle could lock the new
        // one, so take the lock again.
        if is_same_file(&f, &lock_path)? {
            return Ok(Some(f));
        }
    }
    Err(Error::Io(std::io::Error::other(
        "the store's lock file keeps being replaced",
    )))
}

/// Open or create the lock file. `None` when it does not exist and cannot be
/// created, which means the directory cannot be written.
fn open_lock_file(lock_path: &Path) -> Result<Option<std::fs::File>, Error> {
    use std::io::ErrorKind;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(lock_path) {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == ErrorKind::ReadOnlyFilesystem => Ok(None),
        // Not writable for us: an existing lock file can still be locked
        // through a read-only handle; a missing one means a read-only directory.
        Err(e) if e.kind() == ErrorKind::PermissionDenied => match std::fs::File::open(lock_path) {
            Ok(f) => Ok(Some(f)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io(e)),
        },
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(unix)]
fn is_same_file(f: &std::fs::File, path: &Path) -> Result<bool, Error> {
    use std::os::unix::fs::MetadataExt;
    let held = f.metadata()?;
    match std::fs::metadata(path) {
        Ok(now) => Ok(held.dev() == now.dev() && held.ino() == now.ino()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(not(unix))]
fn is_same_file(_f: &std::fs::File, _path: &Path) -> Result<bool, Error> {
    Ok(true)
}

/// Give an existing store file mode 0600, as every write does (0.7.2). A file
/// this process does not own is left as it is: changing it is not its right,
/// and reading it must still work.
#[cfg(unix)]
fn make_private(path: &Path) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode == 0o600 {
        return Ok(());
    }
    match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(not(unix))]
fn make_private(_path: &Path) -> Result<(), Error> {
    Ok(())
}

/// Write `data` atomically to `path` (tmp + fsync + rename), mode 0600 (unix).
///
/// The tmp file is created **with** 0600 (unix) — not chmod'ed afterwards — so
/// there is never a window where it is world-readable. On any failure before
/// the rename the tmp file is removed, so an aborted write leaves no `.tmp-*`
/// files behind.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), Error> {
    let (dir, fname) = dir_and_name(path);
    // An unpredictable name, and the file must be new (0.7.2): a symlink or a
    // file planted where the tmp file goes is refused, never followed or
    // reused, so the tmp file is always this write's own and always 0600.
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|e| Error::Hardening(format!("getrandom: {e}")))?;
    let tmp = dir.join(format!(
        ".tmp-{}-{}-{fname}",
        std::process::id(),
        crate::hex::encode(&nonce)
    ));

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(&tmp)?;
    let result = write_then_rename(f, &tmp, path, &dir, data);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp); // clean up a half-written tmp
    }
    result
}

fn write_then_rename(
    mut f: std::fs::File,
    tmp: &Path,
    path: &Path,
    dir: &Path,
    data: &[u8],
) -> Result<(), Error> {
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(tmp, path)?;
    // Sync the directory too, so the rename itself survives a crash (0.7.2).
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}
