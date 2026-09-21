// SPDX-License-Identifier: MIT OR Apache-2.0
//! # krypto
//!
//! Secure handling of secrets in memory and at rest. A thin, opinionated
//! wrapper around established primitives — no cryptography of our own.
//!
//! Built for a set of programs in Rust and Python that had to agree on one way
//! of doing this. That is why the crate has a canon rather than options: hex
//! for keys and signatures on the wire, one blob format, one set of password
//! profiles. Where an alternative exists, it is there for a format that demands
//! it — not as a choice.
//!
//! ## Invariants
//! - Plaintext is only ever exposed through [`SecretBuf::expose`] / [`SecretString::expose_str`].
//! - `Debug`/`Display` are always redacted (`[REDACTED]`), never contents.
//! - No `Clone`, no `Serialize`.
//! - All `unsafe` lives in [`ffi`]; the rest of the crate is `#![deny(unsafe_code)]`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod aead;
mod ffi;
mod kdf;
mod secret;
mod store;
mod util;

pub mod base64;
pub mod error;
pub mod exchange;
pub mod harden;
pub mod hex;
pub mod password;
pub mod sign;

/// The crate version, for consumers that surface component versions
/// (e.g. an About page). Mirrors `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub use aead::{blob_key_id, open, reseal, seal, Alg};
pub use error::Error;
pub use harden::{close_inherited_fds, drop_filesystem, harden_process, no_new_privs};
// 0.5.0: MAX_MASTER_KEY_BYTES and MAX_STORE_BYTES are now re-exported — they were
// named in the contract but unreachable (`pub` in private modules).
pub use kdf::{hmac_sha256, DerivedKey, MasterKey, MAX_DERIVE_INPUT_BYTES, MAX_MASTER_KEY_BYTES};
pub use secret::{SecretBuf, SecretString};
pub use store::{SecretStore, MAX_STORE_BYTES};
// 0.5.0 (§8d.1): the utilities every consumer was rolling on its own.
pub use util::{ct_eq, random_bytes, sha256};
