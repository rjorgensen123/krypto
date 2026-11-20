// SPDX-License-Identifier: MIT OR Apache-2.0
//! Broken input: valid blobs, store files, keys, signatures, hex, base64 and a
//! PHC string are broken at random places and handed to the functions that read
//! them, and none of them may panic or take more than 5 seconds; what a call
//! answers is not checked. Each run draws a new seed and so tries new inputs. A
//! failure prints its seed, and `KRYPTO_MUTATION_SEED=<seed> cargo test --test
//! mutation` repeats it exactly.

use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use krypto::{
    base64, exchange, hex, password, sign, MasterKey, SecretBuf, SecretStore, SecretString,
};

/// The longest one call may take.
const SLOW: Duration = Duration::from_secs(5);

/// RFC 8032 §7.1 TEST 2: public key and signature of the one-byte message 0x72.
const ED25519_PUBLIC: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const ED25519_SIG: &str = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                           085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";
/// RFC 6979 A.2.5: the P-256 public key (SEC1) and the DER signature of "sample".
const P256_PUBLIC: &str = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
                           7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";
const P256_SIG: &str = "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
                        022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";
/// RFC 7748 §6.1: Alice's private key and Bob's public key.
const X25519_ALICE: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const X25519_BOB: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
/// A PHC string `password::verify` accepts, so Argon2 runs; the password here does not match it.
const PHC: &str = "$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA\
                   $aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g";

/// xorshift64: a few lines, and the same numbers for the same seed everywhere.
struct Rng(u64);

impl Rng {
    /// A number below `n`, which is above 0.
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % n as u64) as usize
    }
}

/// Breaks `input` one to three times: a bit flipped, a byte replaced, the end
/// cut off, a slice repeated in place, bytes appended or a byte inserted.
fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut b = input.to_vec();
    for _ in 0..=rng.below(3) {
        let at = rng.below(b.len() + 1);
        match rng.below(6) {
            0 if at < b.len() => b[at] ^= 1 << rng.below(8),
            1 if at < b.len() => b[at] = rng.below(256) as u8,
            2 => b.truncate(at),
            3 => {
                let end = at + rng.below(b.len() - at + 1);
                b.splice(end..end, b[at..end].to_vec());
            }
            4 => b.extend((0..=rng.below(4)).map(|_| rng.below(256) as u8)),
            _ => b.insert(at, rng.below(256) as u8),
        }
    }
    b
}

/// `KRYPTO_MUTATION_SEED` (a decimal `u64`) when it is set, otherwise a new seed.
fn seed() -> u64 {
    match std::env::var("KRYPTO_MUTATION_SEED") {
        Ok(s) => s
            .parse()
            .unwrap_or_else(|_| panic!("KRYPTO_MUTATION_SEED is not a decimal u64: {s:?}")),
        Err(std::env::VarError::NotPresent) => {
            u64::from_le_bytes(krypto::random_bytes(8).unwrap().try_into().unwrap())
        }
        Err(e) => panic!("KRYPTO_MUTATION_SEED: {e}"),
    }
}

/// `b` split after `n` bytes, or whole and empty when it is shorter.
fn split(b: &[u8], n: usize) -> (&[u8], &[u8]) {
    b.split_at(n.min(b.len()))
}

/// A directory of the test's own, removed when the test ends, a failed one included.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Hands one input to a function under test; the answer is not checked.
type Call<'a> = Box<dyn Fn(&[u8]) -> bool + 'a>;

/// A function under test: its name, its rounds, its valid starting inputs and its call.
struct Target<'a>(&'a str, usize, Vec<Vec<u8>>, Call<'a>);

fn target<'a>(
    name: &'a str,
    rounds: usize,
    starts: Vec<Vec<u8>>,
    call: impl Fn(&[u8]) -> bool + 'a,
) -> Target<'a> {
    Target(name, rounds, starts, Box::new(call))
}

#[test]
fn no_broken_input_makes_krypto_panic() {
    let seed = seed();
    // Written past the harness's capture, so the seed is known also when a
    // call aborts the process (a stack overflow, a sanitizer report).
    let _ = writeln!(std::io::stderr(), "mutation seed {seed}");
    let unhex = |s: &str| hex::decode(s).unwrap();
    // The fixtures' master key and derived key, as in `files_made_once_still_open`.
    let mk = MasterKey::from_bytes(SecretBuf::from_vec((0u8..32).collect()).unwrap()).unwrap();
    let key = mk.derive(b"ctx/v1", b"s").unwrap();
    let new_key = mk.derive(b"ctx/v2", b"s").unwrap();
    let alice = SecretBuf::from_vec(unhex(X25519_ALICE)).unwrap();
    let pw = SecretString::from_string("mutation".to_string()).unwrap();
    let dir = TempDir(std::env::temp_dir().join(format!("krypto-mutation-{}", std::process::id())));
    std::fs::create_dir_all(&dir.0).unwrap();
    let file = dir.0.join("store");
    let store_file = |b: &[u8]| {
        std::fs::write(&file, b).expect("write the store file");
        file.as_path()
    };
    let blobs = vec![
        include_bytes!("fixtures/rust-blob-aegis256.bin").to_vec(),
        include_bytes!("fixtures/rust-blob-aes256gcm.bin").to_vec(),
        include_bytes!("fixtures/rust-blob-xchacha20.bin").to_vec(),
    ];
    let stores = vec![
        include_bytes!("fixtures/rust.store").to_vec(),
        include_bytes!("fixtures/rust-v2.store").to_vec(),
    ];
    // Text is broken as bytes; where that leaves it invalid UTF-8, each invalid
    // sequence becomes U+FFFD.
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let b64 = vec!["c2FsdHNhbHRzYWx0c2FsdA==".into(), "a3J5cHRvISE=".into()];
    let b64_nopad = vec!["c2FsdHNhbHRzYWx0c2FsdA".into(), "a3J5cHRvISE".into()];
    // The verify inputs are key and signature end to end, split at the key's length.
    let ed25519 = vec![[unhex(ED25519_PUBLIC), unhex(ED25519_SIG)].concat()];
    let p256 = vec![[unhex(P256_PUBLIC), unhex(P256_SIG)].concat()];
    let bob = vec![unhex(X25519_BOB)];
    let master_bytes = vec![(0u8..32).collect()];
    // The rounds follow what a call costs in a debug build, about 2.5 s in all.
    // `password::verify` runs Argon2 (64 MiB or more) whenever its broken input
    // is still a PHC string it accepts, so it has few rounds.
    let targets = vec![
        target("open", 400, blobs.clone(), |b| {
            krypto::open(&key, b).is_ok()
        }),
        target("open_with_aad", 400, blobs.clone(), |b| {
            krypto::open_with_aad(&key, b, b"aad").is_ok()
        }),
        target("blob_key_id", 5000, blobs.clone(), |b| {
            krypto::blob_key_id(b).is_ok()
        }),
        target("reseal", 400, blobs, |b| {
            krypto::reseal(&key, &new_key, &[2; 16], b).is_ok()
        }),
        target("hex::decode", 5000, vec![ED25519_PUBLIC.into()], |b| {
            hex::decode(&text(b)).is_ok()
        }),
        target("base64::decode", 5000, b64, |b| {
            base64::decode(&text(b)).is_ok()
        }),
        target("base64::decode_nopad", 5000, b64_nopad, |b| {
            base64::decode_nopad(&text(b)).is_ok()
        }),
        target("password::verify", 24, vec![PHC.into()], |b| {
            password::verify(&pw, &text(b)).is_ok()
        }),
        target("sign::ed25519_verify", 400, ed25519.clone(), |b| {
            let (public, sig) = split(b, 32);
            sign::ed25519_verify(public, &[0x72], sig).is_ok()
        }),
        target("sign::ed25519_verify_relaxed", 400, ed25519, |b| {
            let (public, sig) = split(b, 32);
            sign::ed25519_verify_relaxed(public, &[0x72], sig).is_ok()
        }),
        target("sign::ecdsa_p256_verify", 400, p256, |b| {
            let (public, sig) = split(b, 65);
            sign::ecdsa_p256_verify(public, b"sample", sig).is_ok()
        }),
        target("exchange::x25519_shared", 2000, bob, |b| {
            exchange::x25519_shared(&alice, b).is_ok()
        }),
        target("MasterKey::from_bytes", 2000, master_bytes, |b| {
            SecretBuf::from_vec(b.to_vec())
                .and_then(MasterKey::from_bytes)
                .is_ok()
        }),
        target("SecretStore::open", 400, stores.clone(), |b| {
            SecretStore::open(store_file(b), &mk).is_ok()
        }),
        // Names the version the file says it has, so that both versions are read.
        target("SecretStore::open_with_version", 400, stores.clone(), |b| {
            let version = b.get(4).copied().unwrap_or(2);
            SecretStore::open_with_version(store_file(b), &mk, version).is_ok()
        }),
        target("SecretStore::key_id_from_file", 1000, stores.clone(), |b| {
            SecretStore::key_id_from_file(store_file(b)).is_ok()
        }),
        target("SecretStore::open_with_min_counter", 400, stores, |b| {
            SecretStore::open_with_min_counter(store_file(b), &mk, 1).is_ok()
        }),
    ];
    // xorshift64 never leaves 0, so seed 0 runs as seed 1.
    let mut rng = Rng(seed.max(1));
    for Target(name, rounds, starts, call) in &targets {
        for round in 0..*rounds {
            let input = mutate(&mut rng, &starts[round % starts.len()]);
            let started = Instant::now();
            let what = match catch_unwind(AssertUnwindSafe(|| call(&input))) {
                Err(_) => "panicked".to_string(),
                Ok(_) if started.elapsed() > SLOW => format!("took {:?}", started.elapsed()),
                Ok(_) => continue,
            };
            let hex: String = input.iter().map(|b| format!("{b:02x}")).collect();
            panic!(
                "`{name}` {what} in round {round} of seed {seed}\ninput ({} bytes): {hex}\n\
                 repeat it with: KRYPTO_MUTATION_SEED={seed} cargo test --test mutation",
                input.len()
            );
        }
    }
}
