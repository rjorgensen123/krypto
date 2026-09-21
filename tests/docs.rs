//! Doc guard (0.6.0): every public name in the crate must appear in the
//! shipped reference doc (`docs/API.md`). A surface
//! change that skips the docs fails `cargo test` — the same fence
//! `tests/version.rs` puts around VERSION/CHANGELOG.

use std::collections::BTreeSet;
use std::fs;

fn read(rel: &str) -> String {
    fs::read_to_string(format!("{}/{rel}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// Does `text` mention `name` as a whole identifier?
///
/// A plain `contains` is close to vacuous for the short names in this surface:
/// `len` hides inside "si**len**tly", `get` inside "tar**get**", `list` inside
/// "listed". Requiring the neighbours to be non-identifier characters kills
/// those accidental hits while still accepting every real form the docs use —
/// `` `name` ``, a heading, a signature, or `Alg::Aes256Gcm` for `Alg`.
fn mentions(text: &str, name: &str) -> bool {
    let bytes = text.as_bytes();
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    text.match_indices(name).any(|(i, _)| {
        let before = i == 0 || !ident(bytes[i - 1]);
        let end = i + name.len();
        let after = end >= bytes.len() || !ident(bytes[end]);
        before && after
    })
}

fn ident_prefix(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// Every root re-export, root const, public module, and `pub fn/const/
/// struct/enum` in the public modules.
fn pub_names() -> BTreeSet<String> {
    let mut names = BTreeSet::new();

    let lib = read("src/lib.rs");
    let mut rest = lib.as_str();
    while let Some(i) = rest.find("pub use ") {
        rest = &rest[i + 8..];
        let (Some(open), Some(close)) = (rest.find('{'), rest.find('}')) else {
            break;
        };
        if open < close {
            for n in rest[open + 1..close].split(',') {
                let n = n.trim();
                if !n.is_empty() {
                    names.insert(n.to_string());
                }
            }
        }
        rest = &rest[close..];
    }
    for line in lib.lines() {
        let l = line.trim_start();
        for p in ["pub mod ", "pub const "] {
            if let Some(r) = l.strip_prefix(p) {
                names.insert(ident_prefix(r));
            }
        }
    }

    for f in [
        "password.rs",
        "sign.rs",
        "exchange.rs",
        "hex.rs",
        "base64.rs",
        "harden.rs",
        "error.rs",
        "store.rs",
    ] {
        let t = read(&format!("src/{f}"));
        for line in t.lines() {
            let l = line.trim_start();
            for p in ["pub fn ", "pub const ", "pub struct ", "pub enum "] {
                if let Some(r) = l.strip_prefix(p) {
                    let name = ident_prefix(r);
                    if !name.is_empty() {
                        names.insert(name);
                    }
                }
            }
        }
    }
    names
}

#[test]
fn every_public_name_is_in_the_reference_docs() {
    let names = pub_names();
    assert!(
        names.len() >= 50,
        "the extractor found suspiciously few names ({}) — is it broken?",
        names.len()
    );
    let doc = "docs/API.md";
    let text = read(doc);
    let missing: Vec<&String> = names.iter().filter(|n| !mentions(&text, n)).collect();
    assert!(
        missing.is_empty(),
        "{doc} does not mention these public names: {missing:?} — \
         the reference docs must follow the surface"
    );
}

/// The CLI is half the shipped surface. Its dispatch validates every command
/// against `COMMANDS`, so that constant IS the authoritative list — parse it
/// instead of guessing from match arms. A new command that skips the
/// reference docs must fail the build: the same guard covers both surfaces,
/// and half a guard catches half the drift.
fn cli_commands() -> Vec<String> {
    let src = read("src/bin/krypto-cli.rs");
    let i = src
        .find("const COMMANDS")
        .expect("COMMANDS constant not found in krypto-cli.rs");
    // NB: the first '[' after the name is the TYPE ([&str; N]) — the array
    // literal is the first '[' after '='.
    let eq = src[i..].find('=').expect("no = after COMMANDS") + i;
    let open = src[eq..].find('[').expect("no [ after COMMANDS =") + eq;
    let close = src[open..].find(']').expect("no ] after COMMANDS =") + open;
    src[open + 1..close]
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[test]
fn every_cli_command_is_in_the_reference_docs() {
    let cmds = cli_commands();
    assert!(
        cmds.len() >= 15,
        "the extractor found suspiciously few CLI commands ({}) — is it broken?",
        cmds.len()
    );
    let doc = "docs/API.md";
    let text = read(doc);
    let missing: Vec<&String> = cmds
        .iter()
        .filter(|c| !text.contains(&format!("`{c}`")) && !text.contains(&format!("`{c} ")))
        .collect();
    assert!(
        missing.is_empty(),
        "{doc} does not document these CLI commands: {missing:?} — \
         the contract must follow both surfaces"
    );
}
