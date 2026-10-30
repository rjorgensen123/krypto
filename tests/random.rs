// SPDX-License-Identifier: MIT OR Apache-2.0
//! The per-call cap on random bytes (0.7.3): `MAX_RANDOM_BYTES` by default,
//! the caller's own cap through the `_with_limit` variants, and an error —
//! never a crash — when the memory cannot be had.

use krypto::{random_bytes, random_bytes_with_limit, Error, SecretBuf, MAX_RANDOM_BYTES};

#[test]
fn the_default_cap_is_one_mib_and_holds() {
    assert_eq!(MAX_RANDOM_BYTES, 1 << 20);
    assert_eq!(
        random_bytes(MAX_RANDOM_BYTES).unwrap().len(),
        MAX_RANDOM_BYTES
    );
    assert!(matches!(
        random_bytes(MAX_RANDOM_BYTES + 1),
        Err(Error::Format(_))
    ));
    // Refused before any memory is mapped or locked.
    assert!(matches!(
        SecretBuf::random(MAX_RANDOM_BYTES + 1),
        Err(Error::Format(_))
    ));
}

#[test]
fn a_caller_can_state_its_own_cap_per_call() {
    // Above the default cap, allowed by the caller's own cap for this call.
    let n = MAX_RANDOM_BYTES + 1;
    assert_eq!(random_bytes_with_limit(n, n).unwrap().len(), n);
    // The caller's cap holds below the default too. `SecretBuf` is kept small,
    // so the test needs no more locked memory than the rest of the suite.
    assert!(matches!(
        random_bytes_with_limit(65, 64),
        Err(Error::Format(_))
    ));
    assert!(matches!(
        SecretBuf::random_with_limit(65, 64),
        Err(Error::Format(_))
    ));
    assert_eq!(SecretBuf::random_with_limit(64, 64).unwrap().len(), 64);
}

/// A length no system can back is an error, where `vec!` used to abort or
/// panic. `usize::MAX` is refused before any allocation or mapping is tried,
/// so the answer is the same under AddressSanitizer.
#[test]
fn memory_that_cannot_be_had_is_an_error_not_a_crash() {
    assert!(matches!(
        random_bytes_with_limit(usize::MAX, usize::MAX),
        Err(Error::Hardening(_))
    ));
    assert!(matches!(
        SecretBuf::random_with_limit(usize::MAX, usize::MAX),
        Err(Error::Hardening(_))
    ));
}
