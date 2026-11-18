// SPDX-License-Identifier: MIT OR Apache-2.0
//! `SecretBuf::from_vec` wipes the source it was given, when it takes it and
//! when it refuses it (0.9.0). The source is freed inside `from_vec`, so the
//! only place to see it is the allocator: this test binary has its own, which
//! looks at a block of one of two watched sizes at the moment it is freed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU8, Ordering};

use krypto::{Error, SecretBuf, MAX_DATA_BYTES};

/// A size no other allocation in this binary has: the source `from_vec` takes.
const TAKEN: usize = 4099;
/// One byte over the limit: the source `from_vec` refuses.
const REFUSED: usize = MAX_DATA_BYTES + 1;

const NOT_SEEN: u8 = 0;
const ALL_ZERO: u8 = 1;
const NOT_ZERO: u8 = 2;
static TAKEN_SEEN: AtomicU8 = AtomicU8::new(NOT_SEEN);
static REFUSED_SEEN: AtomicU8 = AtomicU8::new(NOT_SEEN);

struct Watch;

// SAFETY: every call goes to `System` unchanged; `dealloc` only reads the
// block it was handed, which is valid for `layout.size()` bytes until it is
// freed on the last line.
unsafe impl GlobalAlloc for Watch {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let seen = match layout.size() {
            TAKEN => Some(&TAKEN_SEEN),
            REFUSED => Some(&REFUSED_SEEN),
            _ => None,
        };
        if let Some(seen) = seen {
            let zero = std::slice::from_raw_parts(ptr, layout.size())
                .iter()
                .all(|b| *b == 0);
            seen.store(if zero { ALL_ZERO } else { NOT_ZERO }, Ordering::SeqCst);
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static WATCH: Watch = Watch;

#[test]
fn from_vec_wipes_the_source_it_takes() {
    // The watch sees what a plain drop leaves behind: the bytes.
    drop(vec![0xABu8; TAKEN]);
    assert_eq!(TAKEN_SEEN.load(Ordering::SeqCst), NOT_ZERO);

    let secret = SecretBuf::from_vec(vec![0xABu8; TAKEN]).unwrap();
    assert_eq!(TAKEN_SEEN.load(Ordering::SeqCst), ALL_ZERO);
    assert_eq!(secret.len(), TAKEN);
}

#[test]
fn from_vec_wipes_the_source_it_refuses() {
    assert!(matches!(
        SecretBuf::from_vec(vec![0xABu8; REFUSED]),
        Err(Error::Format(_))
    ));
    assert_eq!(REFUSED_SEEN.load(Ordering::SeqCst), ALL_ZERO);
}
