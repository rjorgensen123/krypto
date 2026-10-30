// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Python API is the Rust API (0.8.0): the same names in the same places,
//! both ways.
//!
//! The Rust side is read from the crate's source, the same way
//! `tests/docs.rs` does it: the root's `pub mod`, `pub const` and `pub use`,
//! the `pub` items of the public modules, the `pub fn` of each public type, and
//! the variants of its enums. The Python side is what `krypto_py` shows under
//! the Python that `PYO3_PYTHON` names, with `krypto_py` installed
//! (`maturin develop`). A name on one side only fails the test, unless it is
//! in `PYTHON_ONLY` with its reason.
//!
//! The mapping: `Alg::Aegis256` is `Alg.Aegis256`, `SecretBuf::from_vec` is
//! `SecretBuf.from_vec`, `password::hash` is `password.hash`, and each
//! `Error` variant is an exception, `Error::Auth` being `AuthError` (also as
//! `error.AuthError`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Names only Python has, and why.
const PYTHON_ONLY: &[(&str, &str)] = &[(
    "krypto_py",
    "the compiled module itself, as maturin packages it",
)];

/// What `krypto_py` shows: every public name, the submodules' names, and the
/// public members of each class that is not an exception.
const PYTHON_SURFACE: &str = r#"
import types
import krypto_py

out = set()

def walk(obj, prefix):
    for name in dir(obj):
        if name.startswith("_"):
            continue
        value = getattr(obj, name)
        out.add(prefix + name)
        if isinstance(value, types.ModuleType):
            if not prefix and name != "krypto_py" and value.__name__ == "krypto_py." + name:
                walk(value, name + ".")
        elif isinstance(value, type) and not issubclass(value, BaseException):
            out.update(prefix + name + "." + m for m in dir(value) if not m.startswith("_"))

walk(krypto_py, "")
print("\n".join(sorted(out)))
"#;

fn ident(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// The crate's public names, written as Python paths.
fn rust_surface() -> BTreeSet<String> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../src");
    let read = |file: &str| {
        fs::read_to_string(src.join(file)).unwrap_or_else(|e| panic!("cannot read src/{file}: {e}"))
    };
    let mut names = BTreeSet::new();

    // The root: public modules, constants, and re-exports.
    let mut modules = Vec::new();
    let mut root = BTreeSet::new();
    for line in read("lib.rs").lines() {
        if let Some(rest) = line.strip_prefix("pub mod ") {
            modules.push(ident(rest));
        } else if let Some(rest) = line.strip_prefix("pub const ") {
            root.insert(ident(rest));
        } else if let Some(rest) = line.strip_prefix("pub use ") {
            assert!(
                rest.ends_with(';'),
                "a `pub use` over several lines: teach this test to read it"
            );
            match (rest.find('{'), rest.find('}')) {
                (Some(open), Some(close)) => root.extend(
                    rest[open + 1..close]
                        .split(',')
                        .map(str::trim)
                        .filter(|n| !n.is_empty())
                        .map(String::from),
                ),
                _ => {
                    root.insert(ident(rest.rsplit("::").next().unwrap()));
                }
            }
        }
    }
    names.extend(modules.iter().cloned());
    names.extend(root.iter().cloned());

    // Every file: the public items of public modules, and for each type its
    // `pub fn` and enum variants.
    let mut places: BTreeMap<String, Vec<String>> = BTreeMap::new(); // type -> prefixes
    let mut members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new(); // type -> members
    let mut variants: BTreeMap<String, Vec<String>> = BTreeMap::new(); // enum -> variants
    let mut files: Vec<_> = fs::read_dir(&src)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .collect();
    files.sort();
    for path in files {
        let module = path.file_stem().unwrap().to_string_lossy().into_owned();
        if module == "lib" {
            continue;
        }
        let public = modules.contains(&module);
        let text = fs::read_to_string(&path).unwrap();
        let mut in_impl: Option<String> = None;
        let mut in_enum: Option<String> = None;
        for line in text.lines() {
            if line == "}" {
                in_impl = None;
                in_enum = None;
                continue;
            }
            if let Some(ty) = &in_impl {
                if let Some(rest) = line.strip_prefix("    pub fn ") {
                    members.entry(ty.clone()).or_default().insert(ident(rest));
                }
                continue;
            }
            if let Some(ty) = &in_enum {
                if let Some(rest) = line.strip_prefix("    ") {
                    if rest.starts_with(|c: char| c.is_ascii_uppercase()) {
                        variants.entry(ty.clone()).or_default().push(ident(rest));
                    }
                }
                continue;
            }
            if let Some(rest) = line.strip_prefix("impl") {
                if line.ends_with('{') && !line.contains(" for ") {
                    let rest = match rest.strip_prefix('<') {
                        Some(r) => &r[r.find('>').unwrap() + 1..],
                        None => rest,
                    };
                    in_impl = Some(ident(rest.trim_start()));
                }
                continue;
            }
            for kind in ["pub fn ", "pub const ", "pub struct ", "pub enum "] {
                let Some(rest) = line.strip_prefix(kind) else {
                    continue;
                };
                let name = ident(rest);
                if public {
                    names.insert(format!("{module}.{name}"));
                }
                if kind == "pub struct " || kind == "pub enum " {
                    let mut at = Vec::new();
                    if root.contains(&name) {
                        at.push(String::new());
                    }
                    if public {
                        at.push(format!("{module}."));
                    }
                    places.insert(name.clone(), at);
                    if kind == "pub enum " {
                        in_enum = Some(name);
                    }
                }
            }
        }
    }

    for (ty, at) in &places {
        for prefix in at {
            for m in members.get(ty).into_iter().flatten() {
                names.insert(format!("{prefix}{ty}.{m}"));
            }
            for v in variants.get(ty).into_iter().flatten() {
                if ty == "Error" {
                    names.insert(format!("{prefix}{v}Error"));
                } else {
                    names.insert(format!("{prefix}{ty}.{v}"));
                }
            }
        }
    }
    names
}

fn python_surface() -> BTreeSet<String> {
    let python = std::env::var_os("PYO3_PYTHON").unwrap_or_else(|| "python3".into());
    let out = Command::new(&python)
        .args(["-I", "-c", PYTHON_SURFACE])
        .output()
        .unwrap_or_else(|e| panic!("cannot run {python:?}: {e}"));
    assert!(
        out.status.success(),
        "PYO3_PYTHON must name a Python with krypto_py installed (maturin develop):\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(String::from)
        .collect()
}

#[test]
fn the_python_api_is_the_rust_api() {
    let rust = rust_surface();
    assert!(
        rust.len() >= 90,
        "the Rust side found suspiciously few names ({}): is the reader broken?",
        rust.len()
    );
    let mut python = python_surface();
    for (name, _why) in PYTHON_ONLY {
        assert!(
            python.remove(*name),
            "{name} is in PYTHON_ONLY but not in krypto_py"
        );
    }
    let only_rust: Vec<_> = rust.difference(&python).collect();
    let only_python: Vec<_> = python.difference(&rust).collect();
    assert!(
        only_rust.is_empty() && only_python.is_empty(),
        "the APIs differ.\nOnly in Rust (add to krypto-py): {only_rust:?}\n\
         Only in Python (add to krypto, or to PYTHON_ONLY with a reason): {only_python:?}"
    );
}
