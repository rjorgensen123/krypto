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
//! File format version 1 (frozen) authenticates each entry on its own, but not
//! the file as a whole, and `open` does not check the master key. Version 2
//! (0.9.0) adds a `key_check` (which master key the file is under, verified at
//! `open`), a `container_mac` over the whole header-plus-entries, and a write
//! `counter` for rollback detection, so an entry cannot be removed, swapped,
//! injected or reordered, and an older copy of the file is detected against a
//! caller-supplied minimum counter. New stores are written as version 2; a
//! store keeps the version it was opened with (sticky), and `upgrade` moves a
//! v1 file to v2 one-way. What is protected is the contents and the file as a
//! whole; who may write to it is still the caller's to decide.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::aead::{self, Alg};
use crate::error::Error;
use crate::kdf::{DerivedKey, MasterKey};
use crate::secret::SecretBuf;

const STORE_MAGIC: &[u8; 4] = b"FST1";
/// File format version 1 (frozen): 37-byte header, no container MAC.
const STORE_VER_V1: u8 = 1;
/// File format version 2 (0.9.0): 109-byte header with key-check, counter and
/// container MAC.
const STORE_VER_V2: u8 = 2;
/// The version a new store is created with, unless the caller asks for v1.
const STORE_VER_NEW: u8 = STORE_VER_V2;
const SALT_LEN: usize = 16;
const KEY_ID_LEN: usize = 16;
const KEY_CHECK_LEN: usize = 32;
const COUNTER_LEN: usize = 8;
const MAC_LEN: usize = 32;
/// v1 header: magic | ver | salt | key_id.
const HEADER_LEN_V1: usize = 4 + 1 + SALT_LEN + KEY_ID_LEN; // 37
/// v2 header: v1 fields | key_check | counter (u64 LE) | container_mac.
const V2_HEADER_LEN: usize = HEADER_LEN_V1 + KEY_CHECK_LEN + COUNTER_LEN + MAC_LEN; // 109
/// Offset of the v2 counter within the header (right after key_check).
const V2_COUNTER_OFF: usize = HEADER_LEN_V1 + KEY_CHECK_LEN; // 69
/// Offset of the v2 container_mac within the header (right after the counter).
const V2_MAC_OFF: usize = V2_COUNTER_OFF + COUNTER_LEN; // 77
/// HKDF context of the v2 key-check key (frozen: stored key_checks depend on it).
const CTX_V2_KEY_CHECK: &[u8] = b"krypto/store/v2|key-check";
/// HKDF context of the v2 container-MAC key (frozen: stored MACs depend on it).
const CTX_V2_CONTAINER_MAC: &[u8] = b"krypto/store/v2|container-mac";

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
    /// The file format version of the opened file (1 or 2). Writes keep it:
    /// versioning is sticky, so a v1 file stays v1 and a v2 file stays v2
    /// until an explicit [`SecretStore::upgrade`] (0.9.0).
    version: u8,
    /// The v2 write counter: 0 for a new store, +1 on every write, reset to 0
    /// on rotation. 0 for a v1 file, which has no counter (0.9.0).
    counter: u64,
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
    /// A new store is created as **file format version 2** (0.9.0); use
    /// [`SecretStore::open_with_version`] to create a v1 file explicitly. An
    /// existing file keeps its own version (sticky): this function reads both
    /// v1 and v2.
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
    /// (0.9.0) On a **v2** file the master key is checked here: the header's
    /// `key_check` and `container_mac` are verified before the handle is
    /// returned, so a wrong master key or any tampering with the header or
    /// the entry table is [`Error::Auth`] from `open` itself. On a **v1** file
    /// the master key is not checked: `open` reads the file and decrypts
    /// nothing, a wrong master key shows as [`Error::Auth`] from `get`, and a
    /// `put` under it stores that entry under the wrong key, beside the others.
    pub fn open(path: impl AsRef<Path>, master: &'a MasterKey) -> Result<Self, Error> {
        Self::open_impl(path, master, STORE_VER_NEW, None)
    }

    /// Like [`SecretStore::open`], but a store file that does not exist yet is
    /// created with the given file format `version`: 1 or 2 (0.9.0). Anything
    /// else is [`Error::Format`]. The version only chooses what a NEW file is
    /// written as — an existing file keeps its own version (sticky), so this
    /// never rewrites or upgrades a file that is already there.
    pub fn open_with_version(
        path: impl AsRef<Path>,
        master: &'a MasterKey,
        version: u8,
    ) -> Result<Self, Error> {
        match version {
            STORE_VER_V1 | STORE_VER_V2 => {}
            n => {
                return Err(Error::Format(format!("unsupported store version {n}")));
            }
        }
        Self::open_impl(path, master, version, None)
    }

    /// Like [`SecretStore::open`], but anchored against rollback (0.9.0): after
    /// the file is loaded, its v2 `counter` is compared with `min_counter`,
    /// which the caller keeps outside the file (krypto is stateless). If the
    /// file's counter is lower, the file is an older copy than the caller has
    /// seen, and `open` fails with [`Error::Rollback`] instead of returning a
    /// handle. A v1 file counts as counter 0, so any `min_counter > 0` on a v1
    /// file is [`Error::Rollback`] too. With no anchor (`open`), no freshness
    /// check is performed; on a v2 file `key_check` and `container_mac` are
    /// always verified regardless.
    pub fn open_with_min_counter(
        path: impl AsRef<Path>,
        master: &'a MasterKey,
        min_counter: u64,
    ) -> Result<Self, Error> {
        Self::open_impl(path, master, STORE_VER_NEW, Some(min_counter))
    }

    /// The file format version of the opened store: 1 or 2 (0.9.0).
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The v2 write counter of the opened store (0.9.0): 0 for a new store,
    /// +1 on every write, reset to 0 on rotation. A v1 file has no counter and
    /// reports 0. The counter is covered by the v2 container MAC, so it cannot
    /// be lowered without breaking the MAC; compare it (or anchor it with
    /// [`SecretStore::open_with_min_counter`]) against a value kept outside the
    /// file to detect a rolled-back copy.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The shared body of the `open` family: `new_version` is the version a
    /// missing file is created with, `min_counter` the optional rollback
    /// anchor checked after load (0.9.0).
    fn open_impl(
        path: impl AsRef<Path>,
        master: &'a MasterKey,
        new_version: u8,
        min_counter: Option<u64>,
    ) -> Result<Self, Error> {
        let path = path.as_ref().to_path_buf();
        let lock = take_lock(&path)?;
        match open_store_file(&path)? {
            Some(file) => {
                let data = read_capped(&file, MAX_STORE_BYTES)?;
                let store = Self::load(path, master, &data, lock)?;
                // (0.9.0) Rollback anchor: only meaningful for a file that was
                // actually loaded. v1 counts as counter 0.
                if let Some(min) = min_counter {
                    if store.counter < min {
                        return Err(Error::Rollback {
                            file_counter: store.counter,
                            min_counter: min,
                        });
                    }
                }
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
                    version: new_version,
                    counter: 0,
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
    ///
    /// (0.9.0) On a v2 store the write counter is bumped by 1, so the file's
    /// counter increases on every write (it is covered by the container MAC).
    pub fn put(&mut self, name: &str, secret: &SecretBuf) -> Result<(), Error> {
        validate_name(name)?;
        // (0.9.0) The cap is checked on the size the file WOULD get, before
        // anything is sealed or built (the blob would be 86 + value bytes:
        // 54-byte FAFN header + 32-byte tag). Over the cap: the same `Format`
        // persist would give, but no sealing, no blob allocation and no file
        // build happen first. The check in `persist` stays as the guard.
        let new_blob_len = 86usize.saturating_add(secret.len());
        if self.prospective_file_len(name, new_blob_len) > MAX_STORE_BYTES {
            return Err(Error::Format(format!(
                "the store would grow past {MAX_STORE_BYTES} bytes, which `open` refuses"
            )));
        }
        let dek = self.dek_for(name)?;
        let blob = aead::seal(&dek, &self.key_id, secret, Alg::Aegis256)?;
        // The counter the coming write carries (v2 only). Computed before
        // anything is changed, so an overflow leaves the handle as it was.
        let prev_counter = self.counter;
        let new_counter = self.next_counter()?;
        // Memory follows the file. If the write fails before the new file
        // replaces the old one, roll back the insert, so a later `get` cannot
        // return a value that was never stored. If only the directory sync
        // after the rename fails, the file holds the new value, so memory
        // keeps it (0.8.2).
        let previous = self.entries.insert(name.to_string(), blob);
        self.counter = new_counter;
        match self.persist() {
            Ok(()) => Ok(()),
            Err(WriteError::NotReplaced(e)) => {
                self.counter = prev_counter;
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
    ///
    /// (0.9.0) On a v2 store the write counter is bumped by 1, like on `put`.
    pub fn delete(&mut self, name: &str) -> Result<(), Error> {
        let Some(old) = self.entries.remove(name) else {
            return Ok(());
        };
        let prev_counter = self.counter;
        let new_counter = match self.next_counter() {
            Ok(c) => c,
            Err(e) => {
                // Nothing was written: put the entry back.
                self.entries.insert(name.to_string(), old);
                return Err(e);
            }
        };
        self.counter = new_counter;
        match self.persist() {
            Ok(()) => {}
            // Nothing was replaced: put the entry back.
            Err(WriteError::NotReplaced(e)) => {
                self.counter = prev_counter;
                self.entries.insert(name.to_string(), old);
                return Err(e);
            }
            // The file no longer holds the entry, so memory does not either.
            Err(e @ WriteError::ReplacedUnsynced(_)) => {
                return Err(e.into_error(CHANGE_UNSYNCED))
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
    ///
    /// (0.9.0) The file's format version is preserved (sticky): rotating a v2
    /// store writes a v2 file with a fresh salt, a fresh key id, `counter`
    /// reset to 0, and `key_check` + `container_mac` recomputed; rotating a v1
    /// store writes a v1 file.
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
            version: self.version, // the file's version is preserved (sticky)
            counter: 0,            // a new generation starts at 0 (v2)
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

    /// Upgrade a **v1** store file to file format **version 2** (0.9.0).
    ///
    /// This is explicit and one-way: after it, the file is v2 and stays v2
    /// (versioning is sticky — not even [`SecretStore::open_with_version`] with
    /// 1 writes a v1 file over it), and binaries that accept only version 1
    /// report `unsupported store version 2`. A store that is already v2 is
    /// returned unchanged.
    ///
    /// All entries are decrypted and verified with the master FIRST — if any
    /// fails ([`Error::Auth`]: wrong master, or tampering), nothing is written
    /// and the file is untouched. The file is then written as v2 in a single
    /// atomic rename. Because the salt, the `key_id` and the per-name key
    /// context (`krypto/store/v1|` + name) are unchanged, the upgrade re-wraps
    /// the existing blobs — it does not re-encrypt them — and the v2 counter
    /// starts at 0.
    ///
    /// The handle is consumed even on failure (a stale handle over a replaced
    /// file could persist old-generation data back over the new one) — on
    /// error, reopen the file. It is unchanged, except in one case (0.8.2): if
    /// only the sync of the directory after the rename fails, the file is
    /// already v2, and the [`Error::Io`] says so; reopen it.
    pub fn upgrade(mut self) -> Result<Self, Error> {
        if self.version == STORE_VER_V2 {
            // Already v2; the upgrade is one-way, so there is nothing to do.
            return Ok(self);
        }
        // 1. Decrypt and verify every entry before anything is written. Any
        //    Auth aborts here, with the file untouched.
        let mut names: Vec<String> = self.entries.keys().cloned().collect();
        names.sort();
        for name in &names {
            self.get(name)?;
        }

        // 2. The same generation, now as a v2 container: same salt and key id,
        //    the blobs re-wrapped as they are, a fresh counter and MACs.
        let upgraded = SecretStore {
            path: self.path.clone(),
            master: self.master,
            salt: self.salt,
            key_id: self.key_id,
            version: STORE_VER_V2,
            counter: 0,
            entries: std::mem::take(&mut self.entries),
            lock: self.lock,
        };

        // 3. One atomic write replaces the file.
        match upgraded.persist() {
            Ok(()) => Ok(upgraded),
            Err(e) => Err(e.into_error(
                "the store file is upgraded to version 2, but syncing its directory failed, so \
                 it is not confirmed to survive a crash",
            )),
        }
    }

    // --- internal ---

    /// The header length of this store's file version: 37 for v1, 109 for v2
    /// (0.9.0).
    fn header_len(&self) -> usize {
        if self.version == STORE_VER_V2 {
            V2_HEADER_LEN
        } else {
            HEADER_LEN_V1
        }
    }

    /// The size the store file would get if `name` were stored with a blob of
    /// `blob_len` bytes: the current file size with the old entry under the
    /// same name (if any) replaced by the new one. Header included, so the
    /// v2 header counts too (0.9.0).
    fn prospective_file_len(&self, name: &str, blob_len: usize) -> usize {
        let mut size = self.header_len();
        for (n, b) in &self.entries {
            size = size.saturating_add(2 + n.len() + 4 + b.len());
        }
        if let Some(old) = self.entries.get(name) {
            size = size.saturating_sub(2 + name.len() + 4 + old.len());
        }
        size.saturating_add(2 + name.len() + 4 + blob_len)
    }

    fn dek_for(&self, name: &str) -> Result<DerivedKey, Error> {
        let mut info = Vec::with_capacity(16 + name.len());
        info.extend_from_slice(b"krypto/store/v1|");
        info.extend_from_slice(name.as_bytes());
        self.master.derive(&info, &self.salt)
    }

    /// The counter the next v2 write must carry: the current one + 1 (0.9.0).
    /// A v1 file has no counter and always reports 0. An overflow of u64 is
    /// `Hardening`, never a wrap.
    fn next_counter(&self) -> Result<u64, Error> {
        if self.version == STORE_VER_V2 {
            self.counter
                .checked_add(1)
                .ok_or_else(|| Error::Hardening("the store's v2 counter overflowed".into()))
        } else {
            Ok(self.counter)
        }
    }

    /// Parse a store file (both versions, 0.9.0). Check order per the spec:
    /// magic, version, header length, entry structure — then, for v2, the
    /// `key_check` and the `container_mac`, both compared in constant time;
    /// a mismatch of either is [`Error::Auth`].
    fn load(
        path: PathBuf,
        master: &'a MasterKey,
        data: &[u8],
        lock: Option<std::fs::File>,
    ) -> Result<Self, Error> {
        if data.len() < 5 {
            return Err(Error::Format("store header truncated".into()));
        }
        if &data[0..4] != STORE_MAGIC {
            return Err(Error::Format("wrong store magic".into()));
        }
        let version = data[4];
        let header_len = match version {
            STORE_VER_V1 => HEADER_LEN_V1,
            STORE_VER_V2 => V2_HEADER_LEN,
            n => {
                return Err(Error::Format(format!("unsupported store version {n}")));
            }
        };
        if data.len() < header_len {
            return Err(Error::Format("store header truncated".into()));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&data[5..5 + SALT_LEN]);
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&data[5 + SALT_LEN..5 + SALT_LEN + KEY_ID_LEN]);
        // v2-only header fields (v1 has none).
        let mut key_check = [0u8; KEY_CHECK_LEN];
        let mut container_mac = [0u8; MAC_LEN];
        let mut counter = 0u64;
        if version == STORE_VER_V2 {
            key_check.copy_from_slice(&data[HEADER_LEN_V1..V2_COUNTER_OFF]);
            let cbytes: [u8; COUNTER_LEN] = data[V2_COUNTER_OFF..V2_MAC_OFF]
                .try_into()
                .map_err(|_| Error::Format("store header truncated".into()))?;
            counter = u64::from_le_bytes(cbytes);
            container_mac.copy_from_slice(&data[V2_MAC_OFF..V2_HEADER_LEN]);
        }

        let mut entries = HashMap::new();
        let mut off = header_len;
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

        // v2: authenticate the container. First the key_check — which master
        // key the file is under, so a wrong master is caught here at `open` —
        // then the container_mac over header[0..77] || entries, which makes
        // the file as a whole one authenticated unit.
        if version == STORE_VER_V2 {
            let k_check = master.derive(CTX_V2_KEY_CHECK, &salt)?;
            // key_check = HMAC-SHA256(K_check, "FST1" || ver || salt) = data[0..21]
            let expected_check = crate::hmac_sha256(&k_check, &data[0..5 + SALT_LEN])?;
            if !crate::ct_eq(&expected_check, &key_check) {
                return Err(Error::Auth);
            }
            let k_mac = master.derive(CTX_V2_CONTAINER_MAC, &salt)?;
            let mut mac_input =
                Vec::with_capacity(V2_MAC_OFF + (data.len() - V2_HEADER_LEN));
            mac_input.extend_from_slice(&data[..V2_MAC_OFF]); // header[0..77]
            mac_input.extend_from_slice(&data[V2_HEADER_LEN..]); // entries
            let expected_mac = crate::hmac_sha256(&k_mac, &mac_input)?;
            if !crate::ct_eq(&expected_mac, &container_mac) {
                return Err(Error::Auth);
            }
        }

        Ok(SecretStore {
            path,
            master,
            salt,
            key_id,
            version,
            counter,
            entries,
            lock,
        })
    }

    /// Write the whole store to disk, in the version it was loaded with
    /// (sticky, 0.9.0): a v1 file is written byte-for-byte as before, a v2 file
    /// with its key_check, counter and container_mac.
    fn persist(&self) -> Result<(), WriteError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(STORE_MAGIC);
        buf.push(self.version);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.key_id);
        if self.version == STORE_VER_V2 {
            // key_check = HMAC-SHA256(K_check, "FST1" || ver || salt), the part
            // of the header that proves at `open` which master key the file is
            // under, before any entry is touched.
            let k_check = self
                .master
                .derive(CTX_V2_KEY_CHECK, &self.salt)
                .map_err(WriteError::NotReplaced)?;
            // The MAC input is "FST1" || ver || salt — the first 21 bytes of the
            // header, key_id excluded.
            debug_assert_eq!(5 + SALT_LEN, 21);
            let key_check = crate::hmac_sha256(&k_check, &buf[..5 + SALT_LEN])
                .map_err(WriteError::NotReplaced)?;
            buf.extend_from_slice(&key_check);
            buf.extend_from_slice(&self.counter.to_le_bytes());
            debug_assert_eq!(buf.len(), V2_MAC_OFF); // 77
            // container_mac = HMAC-SHA256(K_mac, header[0..77] || entries): the
            // whole file as one authenticated unit, so no entry can be removed,
            // swapped, injected or reordered, and the counter cannot be lowered,
            // without breaking the MAC.
            let mut entries = Vec::new();
            self.encode_entries(&mut entries)?;
            let k_mac = self
                .master
                .derive(CTX_V2_CONTAINER_MAC, &self.salt)
                .map_err(WriteError::NotReplaced)?;
            let mut mac_input = Vec::with_capacity(buf.len() + entries.len());
            mac_input.extend_from_slice(&buf);
            mac_input.extend_from_slice(&entries);
            let mac = crate::hmac_sha256(&k_mac, &mac_input).map_err(WriteError::NotReplaced)?;
            buf.extend_from_slice(&mac);
            buf.extend_from_slice(&entries);
        } else {
            self.encode_entries(&mut buf)?;
        }
        // `open` refuses a file past MAX_STORE_BYTES, so writing one would lock
        // every secret in it out (0.7.2). `put` rolls back on this error. The
        // cap covers the whole file, header included — for v2 the 109-byte
        // header is part of `buf` (0.9.0).
        if buf.len() > MAX_STORE_BYTES {
            return Err(WriteError::NotReplaced(Error::Format(format!(
                "the store would grow past {MAX_STORE_BYTES} bytes, which `open` refuses"
            ))));
        }
        atomic_write(&self.path, &buf)
    }

    /// Append the entry table (`name_len u16LE | name | blob_len u32LE | blob`)
    /// to `buf`, sorted by name so the file is deterministic (and the v2 MAC
    /// over it stable). The encoding is identical in versions 1 and 2.
    fn encode_entries(&self, buf: &mut Vec<u8>) -> Result<(), WriteError> {
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
        Ok(())
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
/// opened file, not on the path (0.8.2). A file this process does not own is
/// left as it is: changing it is not its right, and reading it must still
/// work.
#[cfg(unix)]
fn make_private(file: &std::fs::File) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file.metadata()?.permissions().mode() & 0o777;
    if mode == 0o600 {
        return Ok(());
    }
    match file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(()),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store(version: u8) -> SecretStore<'static> {
        let mk: &'static MasterKey = Box::leak(Box::new(
            MasterKey::from_bytes(SecretBuf::from_vec(vec![7u8; 32]).unwrap()).unwrap(),
        ));
        SecretStore {
            path: PathBuf::from("/tmp/krypto-store-unittest.store"),
            master: mk,
            salt: [1u8; SALT_LEN],
            key_id: [2u8; KEY_ID_LEN],
            version,
            counter: 0,
            entries: HashMap::new(),
            lock: None,
        }
    }

    #[test]
    fn header_len_matches_the_file_version() {
        assert_eq!(test_store(STORE_VER_V1).header_len(), 37);
        assert_eq!(test_store(STORE_VER_V2).header_len(), 109);
    }

    /// 0.9.0: the cap is computed on the prospective file size (header
    /// included, old entry of the same name replaced) before `put` seals
    /// anything.
    #[test]
    fn prospective_len_counts_header_entries_and_replacement() {
        let mut s = test_store(STORE_VER_V2);
        s.entries.insert("a".to_string(), vec![0u8; 10]); // 109 + (2+1+4+10) = 126
        assert_eq!(s.prospective_file_len("a", 10), 126, "replace same size");
        assert_eq!(
            s.prospective_file_len("b", 100),
            126 + (2 + 1 + 4 + 100),
            "add new entry"
        );
        let mut s1 = test_store(STORE_VER_V1);
        s1.entries.insert("a".to_string(), vec![0u8; 10]);
        assert_eq!(s1.prospective_file_len("a", 10), 37 + 17, "v1 header is 37");
    }
}
