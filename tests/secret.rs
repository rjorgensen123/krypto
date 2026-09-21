//! Integration tests against the public API surface of `krypto`.

use krypto::{SecretBuf, SecretString};

#[test]
fn expose_gives_the_right_bytes() {
    let s = SecretBuf::from_vec(b"hunter2".to_vec()).unwrap();
    assert_eq!(s.len(), 7);
    assert!(!s.is_empty());
    s.expose(|b| assert_eq!(b, b"hunter2"));
}

#[test]
fn debug_and_display_are_redacted() {
    let s = SecretBuf::from_vec(b"topsecret".to_vec()).unwrap();
    let dbg = format!("{s:?}");
    let disp = format!("{s}");
    assert_eq!(dbg, "SecretBuf([REDACTED], len=9)");
    assert_eq!(disp, "SecretBuf([REDACTED], len=9)");
    assert!(!dbg.contains("topsecret"));
    assert!(!disp.contains("topsecret"));
}

#[test]
fn random_has_the_right_length_and_varies() {
    let a = SecretBuf::random(32).unwrap();
    let b = SecretBuf::random(32).unwrap();
    assert_eq!(a.len(), 32);
    assert_eq!(b.len(), 32);
    let equal = a.expose(|ab| b.expose(|bb| ab == bb));
    assert!(!equal, "two random buffers should (almost surely) differ");
}

#[test]
fn empty_buffer() {
    let s = SecretBuf::from_vec(Vec::new()).unwrap();
    assert_eq!(s.len(), 0);
    assert!(s.is_empty());
    assert_eq!(format!("{s:?}"), "SecretBuf([REDACTED], len=0)");
}

#[test]
fn secretstring_roundtrip_and_redacted() {
    // Non-ASCII on purpose: len() counts bytes, not characters.
    let secret = "password-æøå";
    let s = SecretString::from_string(secret.to_string()).unwrap();
    assert_eq!(s.len(), secret.len()); // bytes, not characters
    s.expose_str(|t| assert_eq!(t, secret));
    let dbg = format!("{s:?}");
    assert!(dbg.starts_with("SecretString([REDACTED], len="));
    assert!(!dbg.contains("password"));
}
