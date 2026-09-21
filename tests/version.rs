//! Version guard: 0.4.3 and 0.4.4 shipped without the
//! `VERSION` file or the changelog following along. These tests make that
//! impossible to repeat — a version bump that skips either file fails `cargo test`.

use std::fs;

/// `VERSION` must match `Cargo.toml` exactly.
#[test]
fn version_file_matches_cargo_toml() {
    let on_disk = fs::read_to_string("VERSION").expect("VERSION file must exist");
    assert_eq!(
        on_disk.trim(),
        env!("CARGO_PKG_VERSION"),
        "VERSION file and Cargo.toml disagree — update both in the same commit"
    );
}

/// The changelog must have an entry for the current version.
#[test]
fn changelog_has_entry_for_current_version() {
    let changelog = fs::read_to_string("CHANGELOG.md").expect("CHANGELOG.md must exist");
    let heading = format!("## [{}]", env!("CARGO_PKG_VERSION"));
    assert!(
        changelog.contains(&heading),
        "CHANGELOG.md has no entry `{heading}` — a release without a changelog entry \
         is exactly what this guard exists to prevent"
    );
}
