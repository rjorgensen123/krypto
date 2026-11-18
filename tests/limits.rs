// SPDX-License-Identifier: MIT OR Apache-2.0
//! The shared limit on an amount of data, `MAX_DATA_BYTES` (0.9.0), for the
//! inputs held in ordinary memory: a blob, the data of `hmac_sha256`, a
//! message to sign or verify, the input to `encode` and the text to `decode`.
//! Each input over the limit here is one the function would take without it,
//! so `Format` is the limit's answer. The content and the secret types are in
//! `tests/secret.rs`.

use krypto::sign::{
    ecdsa_p256_keypair, ecdsa_p256_sign, ecdsa_p256_verify, ed25519_keypair, ed25519_sign,
    ed25519_verify, ed25519_verify_relaxed,
};
use krypto::{
    base64, blob_key_id, hex, hmac_sha256, open, open_with_aad, reseal, reseal_with_aad, seal,
    seal_with_aad, Alg, Error, MasterKey, SecretBuf, MAX_DATA_BYTES,
};

/// What a blob adds to its plaintext at most: the 54-byte header and the
/// longest tag, 32 bytes.
const BLOB_OVERHEAD: usize = 54 + 32;

fn is_format<T>(r: Result<T, Error>) -> bool {
    matches!(r, Err(Error::Format(_)))
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

/// One buffer, built once, gives every input: a blob at and one byte over
/// its limit, data one byte over `MAX_DATA_BYTES`, and the hex and base64 of
/// one byte more than `MAX_DATA_BYTES`.
#[test]
fn data_over_max_data_bytes_gives_format() {
    assert_eq!(MAX_DATA_BYTES, 64 * 1024 * 1024);
    let mk = MasterKey::from_bytes(SecretBuf::from_vec(vec![7u8; 32]).unwrap()).unwrap();
    let dk = mk.derive(b"krypto/test/v1", b"salt").unwrap();
    let id = [0u8; 16];
    // `0` is a hex digit, and a base64 character whose low bits are zero.
    let mut big = vec![b'0'; 2 * MAX_DATA_BYTES + 2];

    // A blob: the magic, format 1 and AEGIS-256, then the rest.
    big[..6].copy_from_slice(b"FAFN\x01\x01");
    blob_key_id(&big[..MAX_DATA_BYTES + BLOB_OVERHEAD]).unwrap();
    let blob = &big[..MAX_DATA_BYTES + BLOB_OVERHEAD + 1];
    assert!(is_format(open(&dk, blob)), "open");
    assert!(is_format(open_with_aad(&dk, blob, b"")), "open_with_aad");
    assert!(is_format(reseal(&dk, &dk, &id, blob)), "reseal");
    assert!(
        is_format(reseal_with_aad(&dk, &dk, &id, blob, b"", b"")),
        "reseal_with_aad"
    );
    assert!(is_format(blob_key_id(blob)), "blob_key_id");
    big[..6].copy_from_slice(b"000000");

    // Data, a message, the input to encode.
    let data = &big[..MAX_DATA_BYTES + 1];
    assert!(is_format(hmac_sha256(&dk, data)), "hmac_sha256");
    let (seed, ed_public) = ed25519_keypair().unwrap();
    assert!(is_format(ed25519_sign(&seed, data)), "ed25519_sign");
    assert!(
        is_format(ed25519_verify(&ed_public, data, &[0u8; 64])),
        "ed25519_verify"
    );
    assert!(
        is_format(ed25519_verify_relaxed(&ed_public, data, &[0u8; 64])),
        "ed25519_verify_relaxed"
    );
    let (pkcs8, p256_public) = ecdsa_p256_keypair().unwrap();
    let sig = ecdsa_p256_sign(&pkcs8, b"m").unwrap();
    assert!(is_format(ecdsa_p256_sign(&pkcs8, data)), "ecdsa_p256_sign");
    assert!(
        is_format(ecdsa_p256_verify(&p256_public, data, &sig)),
        "ecdsa_p256_verify"
    );
    assert!(is_format(hex::encode(data)), "hex::encode");
    assert!(is_format(base64::encode(data)), "base64::encode");
    assert!(
        is_format(base64::encode_nopad(data)),
        "base64::encode_nopad"
    );

    // The text of one byte more than the limit. Its padded base64 is as long
    // as that of `MAX_DATA_BYTES` bytes, with one `=` where that has two.
    let over = MAX_DATA_BYTES + 1;
    assert!(
        is_format(hex::decode(text(&big[..2 * over]))),
        "hex::decode"
    );
    let padded = over.div_ceil(3) * 4;
    big[padded - 1] = b'=';
    assert!(
        is_format(base64::decode(text(&big[..padded]))),
        "base64::decode"
    );
    big[padded - 1] = b'0';
    assert!(
        is_format(base64::decode_nopad(text(&big[..(4 * over).div_ceil(3)]))),
        "base64::decode_nopad"
    );
}

/// (0.9.0) When the memory for the result cannot be had, the encoders and the
/// decoders answer `Hardening`; they do not abort the process. Shown in a
/// forked child whose data size is capped just above what it already uses
/// (`RLIMIT_DATA`: no new writable memory, whether mapped or taken from the
/// allocator's own reserve), so every result here is too big to reserve.
#[cfg(all(target_os = "linux", not(miri)))]
#[test]
fn a_result_that_cannot_be_reserved_gives_hardening() {
    const MIB: usize = 1024 * 1024;
    // Built in the parent: the child only has to reserve the results.
    let bytes = vec![0u8; 16 * MIB];
    let hex_text = "0".repeat(32 * MIB);
    let b64_text = "A".repeat(24 * MIB);

    // One field of /proc/self/statm, in bytes: field 0 is the address space,
    // field 5 the data and stack.
    fn statm(field: usize) -> usize {
        let statm = std::fs::read_to_string("/proc/self/statm").unwrap();
        let pages: usize = statm
            .split_whitespace()
            .nth(field)
            .unwrap()
            .parse()
            .unwrap();
        // SAFETY: sysconf takes no pointer.
        pages * unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize
    }
    if statm(0) > 1 << 40 {
        eprintln!("skipped: under a sanitizer the allocator aborts where it would fail");
        return;
    }

    // SAFETY: fork(); the child only calls setrlimit and the functions under
    // test, and leaves with _exit. glibc's atfork handlers make its
    // allocations safe.
    let code = unsafe {
        match libc::fork() {
            -1 => panic!("fork failed"),
            0 => {
                let mut lim = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::getrlimit(libc::RLIMIT_DATA, &mut lim) != 0 {
                    libc::_exit(2);
                }
                // Measured in the child, so what other tests of this binary
                // take while it forks does not count.
                lim.rlim_cur = (statm(5) + 4 * MIB) as libc::rlim_t;
                if libc::setrlimit(libc::RLIMIT_DATA, &lim) != 0 {
                    libc::_exit(2);
                }
                let hardening = [
                    matches!(hex::encode(&bytes), Err(Error::Hardening(_))),
                    matches!(base64::encode(&bytes), Err(Error::Hardening(_))),
                    matches!(base64::encode_nopad(&bytes), Err(Error::Hardening(_))),
                    matches!(hex::decode(&hex_text), Err(Error::Hardening(_))),
                    matches!(base64::decode(&b64_text), Err(Error::Hardening(_))),
                    matches!(base64::decode_nopad(&b64_text), Err(Error::Hardening(_))),
                ];
                match hardening.iter().position(|ok| !ok) {
                    None => libc::_exit(0),
                    Some(i) => libc::_exit(10 + i as i32),
                }
            }
            pid => {
                let mut status = 0;
                assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
                assert!(libc::WIFEXITED(status), "child did not exit normally");
                libc::WEXITSTATUS(status)
            }
        }
    };
    assert_eq!(
        code, 0,
        "2 = the limit could not be set; 10.. = that call (in the order above) did not give Hardening"
    );
}

/// (0.9.0) `seal` and `seal_with_aad` refuse a plaintext over
/// `MAX_DATA_BYTES` themselves. The plaintext is a `SecretBuf`, and
/// `from_vec` already refuses that much, so it is made with the caller's own
/// limit: 64 MiB of locked memory, the most any test holds. Without the
/// check both calls would give a blob.
#[test]
fn a_plaintext_over_max_data_bytes_gives_format() {
    let master = MasterKey::from_bytes(SecretBuf::from_vec(vec![7u8; 32]).unwrap()).unwrap();
    let key = master.derive(b"limits/plaintext", b"").unwrap();
    let over = SecretBuf::random_with_limit(MAX_DATA_BYTES + 1, MAX_DATA_BYTES + 1).unwrap();
    assert!(is_format(seal(&key, &[1u8; 16], &over, Alg::Aegis256)));
    assert!(is_format(seal_with_aad(
        &key,
        &[1u8; 16],
        &over,
        Alg::Aegis256,
        b"aad"
    )));
}
