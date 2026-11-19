# Development

How krypto's code is laid out, and the rules a change has to follow. Several of the rules are
enforced by tests: the guard named under a rule fails when the rule is broken. What krypto is and
how to use it is in the [README](README.md) and under [`docs/`](docs/Home.md).

## Layout

| Path | What it is |
|---|---|
| `src/` | The crate. `lib.rs` is the public root; each module is one area: `secret` (locked memory), `kdf` (master key, HKDF, HMAC), `aead` (the blob), `store` (`SecretStore`), `password` (Argon2id), `sign`, `exchange`, `hex`, `base64`, `util`, `harden`, `error` |
| `src/ffi.rs` | The only module with `unsafe`: memory locking, guard pages and the hardening system calls. Private |
| `src/bin/krypto-cli/` | The test tool `krypto-cli`, with `inspect` |
| `krypto-py/` | The Python binding, built from the same code |
| `tests/` | Integration tests, one file per area, and `tests/fixtures/` with files made once that must still open |
| `docs/` | `API.md` is the contract; `Usage.md`, `Python.md`, `Cli.md`, `Inspect.md` and `Home.md` explain |
| `spec/` | The specification: the design and its reasons, the threat model, and the stored formats |
| `.gitea/workflows/`, `.github/workflows/` | CI on Gitea and on GitHub, with the same checks in both; the ASan job runs on Gitea only |

## Fixed design constraints

- **No cryptography of its own.** krypto wraps established primitives and decides how they are used.
- **krypto protects contents.** It keeps no state outside what it is given, does what it is told,
  and leaves the decisions to the caller: where a file lives, who may write it, what to alarm on.
- **Secrets stay in locked memory** and are wiped when dropped. A type that holds a secret has no
  `Clone`, no `PartialEq`, no serialization, and no `Debug` or `Display` that shows its contents.
- **Fail-closed.** What cannot be done as promised is an error, never a weaker result.
- **Linux on x86_64** is the supported platform. The minimum Rust version is `rust-version` in
  `Cargo.toml`.

## Input

**Everything that comes in has an upper bound.** A function that takes data of variable length has
a limit, a `MAX_*` constant or a size that follows from one, refuses more with `Format`, and states
the limit in `docs/API.md`. A change that adds an input adds its limit in the same change. The exceptions are
`sha256` and `ct_eq`, which cannot fail and reserve no memory; paths, which the operating system
bounds; and `random_bytes_with_limit` and `SecretBuf::random_with_limit`, whose limit is the
caller's.

**Input is validated before it is used,** from every source, a file krypto wrote itself included:
type, length, range and character set. Unknown values are refused, not ignored. No input makes the
crate panic.

## Answers

**Each failure has its own answer.** The caller must be able to tell what failed, so two different
failures do not share an error class when the caller would act differently on them. The classes
are in `src/error.rs`, and `docs/API.md` says which one each case gives.

**No answer carries a secret.** No error holds key material or plaintext, and the crate never
logs. Guard: `every_error_says_what_went_wrong_and_nothing_secret`.

## Formats and specifications

**What is stored is frozen.** The blob format, the store file formats and the context strings keys
are derived with cannot change, because stored data depends on them. A new need gets a new
version beside the old one. Guard: `files_made_once_still_open`.

**The specification comes first.** The specification is in `spec/`. A change to a stored format,
or to anything else it settles, is settled there before the code is written. A specification
gives direction, structure and rules, not names or code: whoever writes the code chooses inside
that frame.

## The public surface

**`docs/API.md` is the contract.** Every public name is in it, with what it does, its limits and its
errors, and nothing in it is untrue of the code. Guards: a list of the public declarations built
from the Rust code blocks of `docs/API.md` and one built from the source must be equal,
`api_document_and_source_have_the_same_declarations`; every `krypto-cli` command is in
`docs/Cli.md`, `every_cli_command_is_in_its_document`. What the text says about behaviour has no
guard: it is read against the code.

**Rust and Python have the same surface.** A name on one side is on the other. Guard:
`the_python_api_is_the_rust_api`.

**`unsafe` lives in `src/ffi.rs` only.** The rest of the crate denies it. `krypto-py` denies it too,
with two marked exceptions.

## Dependencies

`Cargo.lock` is committed, and CI builds with `--locked`. `cargo deny check` runs in CI against
`deny.toml`: advisories, licenses, banned crates and sources. The Python packages CI needs are
pinned in `krypto-py/requirements-ci.txt`.

## Language, changelog and commits

- Everything in the repository is in English: code and names, comments, documentation,
  `CHANGELOG.md` and commit messages.
- `CHANGELOG.md` has an entry for every change, with its date, and describes the result for the
  one who uses krypto. A change that breaks an existing use is marked ⚠. It refers to nothing
  outside krypto: no case or issue numbers, reviews or other systems.
- The documentation says what the code does, and no more.
- The developer approves every changelog entry and every commit message before the commit is made.

## Versions and comments

- `VERSION`, `Cargo.toml` and `krypto-py/Cargo.toml` hold the version, and `CHANGELOG.md` has a
  heading for it. Guard: `version_file_matches_cargo_toml`,
  `changelog_has_entry_for_current_version`.
- Every source file starts with its SPDX license line.
- Documentation and doc comments mark the version a rule applies from, as `(x.y.z)`.
- Comments are in English and say what and why. They contain no personal information and no
  status such as "tested" or "pending".

## Tests

- `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`,
  `cargo test --locked` and `cargo doc --locked --no-deps` with `RUSTDOCFLAGS="-D warnings"`. The
  tests hold secrets in locked memory; the README says what limit they need.
- The Python binding: `maturin develop --locked -m krypto-py/Cargo.toml`, then
  `pytest krypto-py/tests` and `cargo test --locked -p krypto-py`.
- A rule the code is to keep gets a test that fails when it is broken. CI runs on pull requests and
  on `main`.
