// SPDX-License-Identifier: MIT OR Apache-2.0
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

// (0.8.0) The secret types stay Send and Sync: checked when the tests compile.
const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<SecretBuf>();
    send_sync::<SecretString>();
    send_sync::<krypto::MasterKey>();
    send_sync::<krypto::DerivedKey>();
    send_sync::<krypto::SecretStore<'static>>();
};

/// One mapping in `/proc/self/smaps`.
#[cfg(all(target_os = "linux", not(miri)))]
#[derive(Debug)]
struct Mapping {
    start: usize,
    end: usize,
    perms: String,
    flags: Vec<String>,
}

#[cfg(all(target_os = "linux", not(miri)))]
fn mappings() -> Vec<Mapping> {
    let text = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut all: Vec<Mapping> = Vec::new();
    for line in text.lines() {
        if let Some(flags) = line.strip_prefix("VmFlags:") {
            if let Some(m) = all.last_mut() {
                m.flags = flags.split_whitespace().map(String::from).collect();
            }
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some((s, e)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (usize::from_str_radix(s, 16), usize::from_str_radix(e, 16))
        else {
            continue;
        };
        all.push(Mapping {
            start,
            end,
            perms: perms.to_string(),
            flags: Vec::new(),
        });
    }
    all
}

#[cfg(all(target_os = "linux", not(miri)))]
fn containing(maps: &[Mapping], addr: usize) -> Option<&Mapping> {
    maps.iter().find(|m| m.start <= addr && addr < m.end)
}

/// (0.8.0) The pages of a secret, as the kernel sees them: locked (`lo`) and
/// kept out of core dumps (`dd`), an inaccessible guard page on each side,
/// apart from any other secret, and gone once the secret is dropped. The size
/// is unusual on purpose, so no other test's mapping is taken for this one.
#[cfg(all(target_os = "linux", not(miri)))]
#[test]
fn a_secret_has_locked_guarded_pages_of_its_own() {
    const LEN: usize = 5 * 4096 + 123;
    let a = SecretBuf::from_vec(vec![7u8; LEN]).unwrap();
    let b = SecretBuf::from_vec(vec![9u8; LEN]).unwrap();
    let addr = |s: &SecretBuf| s.expose(|bytes| bytes.as_ptr() as usize);
    let (at_a, at_b) = (addr(&a), addr(&b));
    let protected =
        |m: &Mapping| m.flags.iter().any(|f| f == "lo") && m.flags.iter().any(|f| f == "dd");

    let maps = mappings();
    let pages_a = containing(&maps, at_a).expect("the secret is mapped");
    assert!(
        protected(pages_a),
        "not locked and out of core dumps: {pages_a:?}"
    );
    let guard = |at| containing(&maps, at).map(|m| m.perms.as_str());
    assert_eq!(
        guard(pages_a.start - 1),
        Some("---p"),
        "no guard page before"
    );
    assert_eq!(guard(pages_a.end), Some("---p"), "no guard page after");
    let pages_b = containing(&maps, at_b).unwrap();
    assert!(
        pages_b.end <= pages_a.start || pages_a.end <= pages_b.start,
        "two secrets share pages"
    );
    let (start_b, end_b) = (pages_b.start, pages_b.end);

    drop(b);
    let maps = mappings();
    assert!(
        protected(containing(&maps, at_a).unwrap()),
        "dropping one secret unprotected another"
    );
    assert!(
        maps.iter().all(|m| (m.start, m.end) != (start_b, end_b)),
        "a dropped secret's pages are still mapped"
    );
    drop(a);
}
