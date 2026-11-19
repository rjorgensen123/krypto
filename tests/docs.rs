// SPDX-License-Identifier: MIT OR Apache-2.0
//! Doc guard: the public declarations given in the Rust code blocks of
//! `docs/API.md` and the ones in the source under `src/` must be the same
//! list, and every `krypto-cli` command must be in `docs/Cli.md`. What the
//! text says about behaviour is not checked.
//!
//! The source is read line by line in the layout rustfmt gives it (CI runs
//! `cargo fmt --check`): items start in column 0, the methods of an `impl`
//! block four spaces in, and an item's head runs to the line that ends with
//! `{` or `;`.

use std::collections::BTreeSet;
use std::fs;

fn read(rel: &str) -> String {
    fs::read_to_string(format!("{}/{rel}", env!("CARGO_MANIFEST_DIR")))
        .unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

fn ident_prefix(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// One declaration as one line of text: the `{` or `;` that ends it dropped,
/// white space collapsed to single spaces, and the few spellings of the
/// source that a reader of the API does not see written as the document
/// writes them.
fn normalise(head: &str) -> String {
    let mut s = head
        .trim_end_matches(['{', ';'])
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    // rustfmt puts a long parameter list or an enum body one entry per line,
    // with a comma after the last; the document writes it on one line.
    s = s
        .replace("( ", "(")
        .replace(", )", ")")
        .replace(", }", " }");
    // `mut` on a parameter belongs to the body, not to the signature.
    s = s.replace("(mut ", "(").replace(", mut ", ", ");
    // An internal path such as `crate::secret::SecretBuf` is the type the
    // reader knows as `SecretBuf`.
    while let Some(at) = s.find("crate::") {
        let path = &s[at..];
        let end = path
            .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':'))
            .unwrap_or(path.len());
        let cut = path[..end].rfind("::").map_or(end, |i| i + 2);
        s.replace_range(at..at + cut, "");
    }
    s
}

/// The text of the item whose first line is `first`: up to the line that
/// ends with `{` or `;`, or, for an enum or a `use` (`balanced`), up to the
/// line where its braces close; attribute lines left out.
fn item<'a>(first: &str, balanced: bool, lines: &mut impl Iterator<Item = &'a str>) -> String {
    let mut text = first.to_string();
    let done = |t: &str| {
        if balanced {
            t.matches('{').count() == t.matches('}').count() && t.ends_with(['}', ';'])
        } else {
            t.ends_with(['{', ';'])
        }
    };
    while !done(&text) {
        let line = lines
            .next()
            .unwrap_or_else(|| panic!("the item `{first}` has no end"));
        if !line.trim_start().starts_with("#[") {
            text.push(' ');
            text.push_str(line);
        }
    }
    text
}

/// The public declarations in `text`, one line of text each: functions,
/// methods (as `Type :: pub fn …`), constants, enums, the names of `pub use`
/// and the `pub mod` lines. Structs are not listed; an item after
/// `#[doc(hidden)]` or `#[cfg(test)]` is left out. `exported` says, by name,
/// whether an item or the type of an inherent `impl` block is public API.
fn declarations(text: &str, exported: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut lines = text
        .lines()
        .map(|l| l.find("//").map_or(l, |i| &l[..i]).trim_end());
    let mut found = Vec::new();
    let mut owner: Option<String> = None; // the type of the `impl` block being read
    let mut skip = false;
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed == "#[doc(hidden)]" || trimmed == "#[cfg(test)]" {
            skip = true;
        }
        if trimmed.is_empty() || trimmed.starts_with("#[") || std::mem::take(&mut skip) {
            continue;
        }
        if line == "}" {
            owner = None;
        } else if line.starts_with("impl ") || line.starts_with("impl<") {
            // `impl<'a> SecretStore<'a> {`: the type follows the generics; a
            // trait `impl` has no public methods of its own.
            let ty = line.split_whitespace().nth(1).map(ident_prefix);
            owner = ty.filter(|t| !line.contains(" for ") && exported(t));
        } else if let (Some(ty), Some(method)) = (&owner, line.strip_prefix("    pub ")) {
            assert!(method.starts_with("fn "), "the test does not read `{line}`");
            let head = item(trimmed, false, &mut lines);
            found.push(format!("{ty} :: {}", normalise(&head)));
        } else if let Some(rest) = line.strip_prefix("pub ") {
            let (kind, after) = rest.split_once(' ').unwrap_or((rest, ""));
            match kind {
                "struct" => {}
                "fn" | "const" | "enum" | "mod" => {
                    let head = normalise(&item(line, kind == "enum", &mut lines));
                    if exported(&ident_prefix(after)) {
                        found.push(head);
                    }
                }
                "use" => {
                    // `pub use path::{a, b};` gives one entry per name.
                    let head = normalise(&item(line, true, &mut lines));
                    let used = &head["pub use ".len()..];
                    let (path, names) = match used.split_once("::{") {
                        Some((path, list)) => (path, list.trim_end_matches('}')),
                        None => used
                            .rsplit_once("::")
                            .unwrap_or_else(|| panic!("cannot read `{head}`")),
                    };
                    for name in names.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                        if exported(name) {
                            found.push(format!("pub use {path}::{name}"));
                        }
                    }
                }
                _ => panic!("the test does not read `{line}`"),
            }
        }
    }
    found
}

/// The text of the Rust code blocks of a Markdown document.
fn rust_blocks(doc: &str) -> String {
    let mut text = String::new();
    let mut inside = false;
    for line in doc.lines() {
        if inside && line.trim_end() == "```" {
            inside = false;
        } else if inside {
            text.push_str(line);
            text.push('\n');
        } else if line.trim_end() == "```rust" {
            inside = true;
        }
    }
    assert!(!inside, "a Rust code block is not closed");
    text
}

/// Does `text` declare `name` as a `pub` item in column 0?
fn declares_pub(text: &str, name: &str) -> bool {
    text.lines()
        .filter_map(|l| l.strip_prefix("pub ")?.split_once(' '))
        .any(|(_, rest)| ident_prefix(rest) == name)
}

/// The public declarations of the source: those of the crate root, every
/// public item of a public module, and the items of a private module that the
/// root re-exports.
fn source_declarations() -> Vec<String> {
    let mut found = declarations(&read("src/lib.rs"), &|_| true);
    let public: Vec<String> = found
        .iter()
        .filter_map(|d| d.strip_prefix("pub mod "))
        .map(String::from)
        .collect();
    let reexported: Vec<(String, String)> = found
        .iter()
        .filter_map(|d| d.strip_prefix("pub use ")?.rsplit_once("::"))
        .map(|(m, n)| (m.to_string(), n.to_string()))
        .collect();
    let modules: BTreeSet<&String> = public
        .iter()
        .chain(reexported.iter().map(|(m, _)| m))
        .collect();
    for module in modules {
        let mut text = read(&format!("src/{module}.rs"));
        // A private constant in a signature means nothing to a reader of the
        // API, so the document writes its value: `[u8; KEY_ID_LEN]` is `[u8; 16]`.
        let private: Vec<(String, String)> = text
            .lines()
            .filter_map(|l| {
                l.strip_prefix("const ")?
                    .strip_suffix(';')?
                    .split_once(": usize = ")
            })
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        for (name, value) in private {
            text = text.replace(&format!("[u8; {name}]"), &format!("[u8; {value}]"));
        }
        let is_public = public.contains(module);
        let exported = |name: &str| {
            (is_public && declares_pub(&text, name))
                || reexported.iter().any(|(m, n)| m == module && n == name)
        };
        found.extend(declarations(&text, &exported));
    }
    found
}

/// The entries of `a` that `b` does not have, counted: an entry `a` holds
/// twice and `b` once is returned once.
fn missing_from(a: &[String], b: &[String]) -> Vec<String> {
    let mut rest = b.to_vec();
    a.iter()
        .filter(|x| match rest.iter().position(|y| y == *x) {
            Some(i) => {
                rest.swap_remove(i);
                false
            }
            None => true,
        })
        .cloned()
        .collect()
}

#[test]
fn api_document_and_source_have_the_same_declarations() {
    let mut documented = declarations(&rust_blocks(&read("docs/API.md")), &|_| true);
    let mut declared = source_declarations();
    for (list, from) in [(&documented, "docs/API.md"), (&declared, "src/")] {
        assert!(
            list.len() >= 100,
            "found only {} declarations in {from}: is the reading broken?",
            list.len()
        );
    }
    documented.sort();
    declared.sort();
    let show = |entries: Vec<String>| {
        if entries.is_empty() {
            "  (none)\n".to_string()
        } else {
            entries.iter().map(|e| format!("  {e}\n")).collect()
        }
    };
    assert!(
        documented == declared,
        "docs/API.md and the source differ.\nOnly in docs/API.md:\n{}Only in the source:\n{}",
        show(missing_from(&documented, &declared)),
        show(missing_from(&declared, &documented))
    );
}

/// The test tool ships with the crate, so its commands are documented, in
/// `docs/Cli.md`, not in the API reference. Its parser checks every command
/// against `COMMANDS`, so that constant IS the authoritative list: parse it
/// instead of guessing from match arms. A new command that skips its document
/// fails the build.
fn cli_commands() -> Vec<String> {
    let src = read("src/bin/krypto-cli/main.rs");
    let i = src
        .find("const COMMANDS")
        .expect("COMMANDS constant not found in krypto-cli/main.rs");
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
fn every_cli_command_is_in_its_document() {
    let cmds = cli_commands();
    assert!(
        cmds.len() >= 9,
        "the extractor found suspiciously few CLI commands ({}) — is it broken?",
        cmds.len()
    );
    let doc = "docs/Cli.md";
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
