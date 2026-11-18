// SPDX-License-Identifier: MIT OR Apache-2.0
//! `SecretStore` — encrypted key-value store on file.
//!
//! Every value is encrypted with a **per-key-name** derived DEK
//! (`HKDF(master, salt, info = "krypto/store/v1|" + name)`). That binds the
//! value to its name: a blob cannot be moved to another name without `open`
//! failing with `Auth`. Key names are plaintext (addresses, not secrets).
//! Writes are atomic (tmp + fsync + rename), file mode 0600. One handle per
//! file at a time, held by a lock (0.7.2).
//!
//! What is protected is the contents, not the file. Without the master key
//! no value can be read, and none can be made or changed that `get` accepts.
//! The file as a whole is not authenticated: whoever can write to it can
//! remove an entry or put back an older copy, so who may write to it is the
//! caller's to decide. `open` does not check the master key: a wrong one
//! shows as [`Error::Auth`] from `get`.

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
    /// (0.7.2). `None` only when the file system is read-only, or when there
    /// is no lock file and the process may not create one in the directory
    /// (0.8.2), where a write could not create its tmp file either.
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
    /// overwrite each other's writes. (0.8.2) A symbolic link at the lock
    /// file's name is not followed, and something there that is not a regular
    /// file, such as a FIFO, is not used as the lock: `open` fails with
    /// [`Error::Io`] either way, and a FIFO there does not make it wait.
    ///
    /// (0.8.2) If what is at `path` can be opened but is not a regular file,
    /// such as a FIFO, a device or a directory, `open` fails with
    /// [`Error::Format`]; what cannot be opened, for example for lack of
    /// permission or because it is a socket, gives the [`Error::Io`] from
    /// opening it. A FIFO at `path` does not make `open` wait. A symbolic link
    /// at `path` is followed, so a link to a regular file is read through; the
    /// first write replaces the link with a regular file, and the file the link
    /// pointed to keeps its old contents. An existing file gets mode 0600 only
    /// after it has been read as a store.
    ///
    /// (0.8.2) When `open` creates a new store and only the sync of the
    /// directory after the rename fails, it returns [`Error::Io`] although the
    /// new, empty store file is in place.
    ///
    /// The master key is not checked here: `open` reads the file and decrypts
    /// nothing. A wrong master key shows as [`Error::Auth`] from `get`, and a
    /// `put` under it stores that entry under the wrong key, beside the others.
    pub fn open(path: impl AsRef<Path>, master: &'a MasterKey) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let lock = take_lock(&path)?;
        match open_store_file(&path)? {
            Some(file) => {
                let data = read_capped(&file, MAX_STORE_BYTES)?;
                let store = Self::load(path, master, &data, lock)?;
                // 0600 only once the file is known to be a store (0.8.2).
                make_private(&file)?;
                Ok(store)
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
                match store.persist() {
                    Ok(()) => Ok(store),
                    Err(e) => Err(e.into_error(
                        "a new, empty store file is written, but syncing its directory failed, \
                         so it is not confirmed to survive a crash",
                    )),
                }
            }
        }
    }

    /// Store a secret under `name` (overwrites an existing one).
    ///
    /// The name is validated on **character set and length**, not just length.
    /// Names are not secret and are exposed through [`SecretStore::list`] — a
    /// name with a newline could shift lines in a consumer's log, and an empty
    /// name is not a key anyone can look up again.
    ///
    /// (0.8.2) If only the sync of the directory after the rename fails, `put`
    /// returns [`Error::Io`] although the new value is in the file, and the
    /// handle keeps it too.
    pub fn put(&mut self, name: &str, secret: &SecretBuf) -> Result<(), Error> {
        validate_name(name)?;
        let dek = self.dek_for(name)?;
        let blob = aead::seal(&dek, &self.key_id, secret, Alg::Aegis256)?;
        // Memory follows the file. If the write fails before the new file
        // replaces the old one, roll back the insert, so a later `get` cannot
        // return a value that was never stored. If only the directory sync
        // after the rename fails, the file holds the new value, so memory
        // keeps it (0.8.2).
        let previous = self.entries.insert(name.to_string(), blob);
        match self.persist() {
            Ok(()) => Ok(()),
            Err(WriteError::NotReplaced(e)) => {
                match previous {
                    Some(old) => {
                        self.entries.insert(name.to_string(), old);
                    }
                    None => {
                        self.entries.remove(name);
                    }
                }
                Err(e)
            }
            Err(e @ WriteError::ReplacedUnsynced(_)) => Err(e.into_error(CHANGE_UNSYNCED)),
        }
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
    ///
    /// (0.8.2) If only the sync of the directory after the rename fails,
    /// `delete` returns [`Error::Io`] although the entry is gone from the file,
    /// and from the handle too.
    pub fn delete(&mut self, name: &str) -> Result<(), Error> {
        if let Some(old) = self.entries.remove(name) {
            match self.persist() {
                Ok(()) => {}
                // Nothing was replaced: put the entry back.
                Err(WriteError::NotReplaced(e)) => {
                    self.entries.insert(name.to_string(), old);
                    return Err(e);
                }
                // The file no longer holds the entry, so memory does not either.
                Err(e @ WriteError::ReplacedUnsynced(_)) => {
                    return Err(e.into_error(CHANGE_UNSYNCED))
                }
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
    /// error, reopen the file. It is unchanged, except in one case (0.8.2): if
    /// only the sync of the directory after the rename fails, the file is
    /// already under the new master key, and the [`Error::Io`] says so; reopen
    /// it with the new master key then.
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
        match new_store.persist() {
            Ok(()) => Ok(new_store),
            Err(e) => Err(e.into_error(
                "the store file is written under the new master key, but syncing its directory \
                 failed, so it is not confirmed to survive a crash; reopen the store with the new \
                 master key",
            )),
        }
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

    fn persist(&self) -> Result<(), WriteError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(STORE_MAGIC);
        buf.push(STORE_VER);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.key_id);
        let mut names: Vec<&String> = self.entries.keys().collect();
        names.sort(); // deterministic file
        for name in names {
            let blob = &self.entries[name];
            let blen = u32::try_from(blob.len()).map_err(|_| {
                WriteError::NotReplaced(Error::Format("blob too big for the store format".into()))
            })?;
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name.as_bytes());
            buf.extend_from_slice(&blen.to_le_bytes());
            buf.extend_from_slice(blob);
        }
        // `open` refuses a file past MAX_STORE_BYTES, so writing one would lock
        // every secret in it out (0.7.2). `put` rolls back on this error.
        if buf.len() > MAX_STORE_BYTES {
            return Err(WriteError::NotReplaced(Error::Format(format!(
                "the store would grow past {MAX_STORE_BYTES} bytes, which `open` refuses"
            ))));
        }
        atomic_write(&self.path, &buf)
    }
}

/// The error text of `put` and `delete` when only the directory sync after
/// the rename failed (0.8.2).
const CHANGE_UNSYNCED: &str = "the change is written to the store file, but syncing its \
                               directory failed, so it is not confirmed to survive a crash";

/// How a write of the store file failed: before or after the new file replaced
/// the old one (0.8.2). The callers undo their change in memory only when the
/// file was not replaced; after the rename, memory follows the file.
enum WriteError {
    /// The write failed before the rename: the file at the path is as it was.
    NotReplaced(Error),
    /// The new file replaced the old one, but syncing the directory failed:
    /// the change is in the file, but not confirmed to survive a crash.
    ReplacedUnsynced(std::io::Error),
}

impl WriteError {
    /// The error to return to the caller. `NotReplaced` gives its error as it
    /// is; `ReplacedUnsynced` gives [`Error::Io`] of the same kind, with
    /// `written` (what the file now holds) before the original error text.
    fn into_error(self, written: &str) -> Error {
        match self {
            WriteError::NotReplaced(e) => e,
            WriteError::ReplacedUnsynced(e) => {
                Error::Io(std::io::Error::new(e.kind(), format!("{written}: {e}")))
            }
        }
    }
}

/// Open the store file for reading (0.8.2). `Ok(None)` = the file does not
/// exist (the caller creates a new store). On unix it is opened with
/// `O_NONBLOCK`, so a FIFO cannot block; what is opened but is not a regular
/// file is `Err(Format)`, checked on the opened file. A symbolic link is
/// followed, so a link to a regular file is read through. Errors from opening
/// other than `NotFound` → `Err(Io)`.
fn open_store_file(path: &Path) -> Result<Option<std::fs::File>, Error> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NONBLOCK);
    }
    let f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    };
    if !f.metadata()?.file_type().is_file() {
        return Err(Error::Format("the store path is not a regular file".into()));
    }
    Ok(Some(f))
}

/// Read the opened store file with an upper size cap. `Ok(bytes)` = contents
/// within the cap; `Err(Format)` = too big (bounded input, no OOM); I/O
/// errors → `Err(Io)`.
fn read_capped(f: &std::fs::File, cap: usize) -> Result<Vec<u8>, Error> {
    use std::io::Read;
    let mut bytes = Vec::new();
    f.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(Error::Format(format!(
            "store file is too big (> {cap} bytes)"
        )));
    }
    Ok(bytes)
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
/// a crash, so the lock file never goes stale; krypto never deletes it. A
/// symbolic link at the lock file's name is an error, never followed, and so
/// is anything there that is not a regular file (0.8.2).
/// `None` only when the file system is read-only, or when there is no lock
/// file and the process may not create one in the directory, where a write
/// could not create its tmp file either.
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

/// Open or create the lock file. On unix it is opened with `O_NOFOLLOW` and
/// `O_NONBLOCK` (0.8.2): a symbolic link at its name is an error, never
/// followed and never created through, and a FIFO cannot block. What is
/// opened must be a regular file, checked on the opened file; anything else
/// is an error too. `None` only when the file system is read-only, or when
/// the lock file does not exist and the process may not create it.
fn open_lock_file(lock_path: &Path) -> Result<Option<std::fs::File>, Error> {
    use std::io::ErrorKind;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let f = match opts.open(lock_path) {
        Ok(f) => f,
        Err(_) if is_symlink(lock_path) => return Err(lock_file_is_a_symlink()),
        Err(e) if e.kind() == ErrorKind::ReadOnlyFilesystem => return Ok(None),
        // Not writable for us: an existing lock file can still be locked
        // through a read-only handle; a missing one means a read-only directory.
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            match opts.open(lock_path) {
                Ok(f) => f,
                Err(_) if is_symlink(lock_path) => return Err(lock_file_is_a_symlink()),
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(Error::Io(e)),
            }
        }
        Err(e) => return Err(Error::Io(e)),
    };
    if !f.metadata()?.file_type().is_file() {
        return Err(Error::Io(std::io::Error::other(
            "the store's lock file is not a regular file",
        )));
    }
    Ok(Some(f))
}

/// Whether `path` itself is a symbolic link, to tell an open refused by
/// `O_NOFOLLOW` from other failures (0.8.2). Always `false` off unix, where
/// the lock file is opened without that flag.
fn is_symlink(path: &Path) -> bool {
    #[cfg(unix)]
    {
        std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

/// The error for a symbolic link at the lock file's name (0.8.2).
fn lock_file_is_a_symlink() -> Error {
    Error::Io(std::io::Error::other(
        "the store's lock file is a symbolic link, which is not followed",
    ))
}

#[cfg(unix)]
fn is_same_file(f: &std::fs::File, path: &Path) -> Result<bool, Error> {
    use std::os::unix::fs::MetadataExt;
    let held = f.metadata()?;
    // Not following a link (0.8.2): a symbolic link put at the name is not the
    // file held, even when it points to it.
    match std::fs::symlink_metadata(path) {
        Ok(now) => Ok(held.dev() == now.dev() && held.ino() == now.ino()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(not(unix))]
fn is_same_file(_f: &std::fs::File, _path: &Path) -> Result<bool, Error> {
    Ok(true)
}

/// Give the opened store file mode 0600, as every write does (0.7.2). `open`
/// calls it only after the file has been read as a store, and it works on the
/// opened file, not on the path (0.8.2). A file this process may not change
/// is left as it is, and reading it must still work: one it does not own,
/// or one on a read-only file system (0.8.2).
#[cfg(unix)]
fn make_private(file: &std::fs::File) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file.metadata()?.permissions().mode() & 0o777;
    if mode == 0o600 {
        return Ok(());
    }
    match file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        Ok(()) => Ok(()),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(not(unix))]
fn make_private(_file: &std::fs::File) -> Result<(), Error> {
    Ok(())
}

/// Write `data` atomically to `path` (tmp + fsync + rename), mode 0600 (unix).
///
/// The tmp file is created **with** 0600 (unix) — not chmod'ed afterwards — so
/// there is never a window where it is world-readable. On unix the directory
/// is opened before the rename and synced after it (0.8.2). On any failure
/// before the rename the tmp file is removed, so an aborted write leaves no
/// `.tmp-*` files behind, and the result is [`WriteError::NotReplaced`]. A
/// failed sync of the directory after the rename is
/// [`WriteError::ReplacedUnsynced`]: the new file is in place by then.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), WriteError> {
    let (dir, fname) = dir_and_name(path);
    // An unpredictable name, and the file must be new (0.7.2): a symlink or a
    // file planted where the tmp file goes is refused, never followed or
    // reused, so the tmp file is always this write's own and always 0600.
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce)
        .map_err(|e| WriteError::NotReplaced(Error::Hardening(format!("getrandom: {e}"))))?;
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
    let f = opts
        .open(&tmp)
        .map_err(|e| WriteError::NotReplaced(Error::Io(e)))?;
    let result = write_then_rename(f, &tmp, path, &dir, data);
    if let Err(WriteError::NotReplaced(_)) = result {
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
) -> Result<(), WriteError> {
    let not_replaced = |e: std::io::Error| WriteError::NotReplaced(Error::Io(e));
    f.write_all(data).map_err(not_replaced)?;
    f.sync_all().map_err(not_replaced)?;
    drop(f);
    // Open the directory before the rename (0.8.2): if it cannot be opened,
    // the write fails while the old file still stands.
    #[cfg(unix)]
    let dir_handle = std::fs::File::open(dir).map_err(not_replaced)?;
    #[cfg(not(unix))]
    let _ = dir;
    std::fs::rename(tmp, path).map_err(not_replaced)?;
    // Sync the directory too, which holds the rename (0.7.2). The new file is
    // in place by now, so a failure here is not "nothing written" (0.8.2).
    #[cfg(unix)]
    dir_handle
        .sync_all()
        .map_err(WriteError::ReplacedUnsynced)?;
    Ok(())
}
