# krypto — secret handling library

*(Codename: Fafnir — directory `krypto/`.)*

> **This repository is a mirror.** Development happens elsewhere and is pushed here;
> every sync overwrites what is here, so a pull request cannot be merged and a commit
> made here is lost. Issues are read — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
> form a change has to arrive in, and [SECURITY.md](SECURITY.md) for vulnerabilities.

Standalone crypto and secret-handling crate. It grew out of building a real application, but
is fully self-contained — nothing here depends on that app.

It owns all handling of secrets in memory
and at rest: locked secret types, AEAD with a self-describing blob format, HKDF key derivation,
keyed MACs, an encrypted key-value store, key rotation (`reseal`, `SecretStore::rotate`),
argon2id password hashing/derivation, signatures
(Ed25519, ECDSA P-256 — ring-compatible), X25519 key agreement, canonical hex/base64/SHA-256/`ct_eq`
utilities and process hardening. A thin, opinionated wrapper around established primitives — **no cryptography of our
own is implemented**.

- **Type:** Rust crate (library)
- **Lifetime:** long-lived — the version moves when the surface does, and the API document
  carries the version it applies from
- **License:** MIT/Apache-2.0 dual
- **In use:** already in service in more than one application — among them the `nettls`
  crate, which builds its TLS layer on top of it.
- **Docs (ship with the crate):** overview [`docs/Home.md`](docs/Home.md) · usage guide
  [`docs/Usage.md`](docs/Usage.md) · **API contract** [`docs/API.md`](docs/API.md) — every
  public name, guarded by `tests/docs.rs`
- **Changes:** [`CHANGELOG.md`](CHANGELOG.md) · **Version:** see [`VERSION`](VERSION)
  (kept in lockstep with `Cargo.toml` by `tests/version.rs`)

## Why this crate exists

The same handful of primitives kept being written from scratch in one application after
another — sealing a secret at rest, deriving a key from a password, holding a secret in memory
without scattering copies of it. Each rewrite was a new chance to get it subtly wrong.

So the idea was to write it once, carefully, and then never write it again. This crate is
that one time.

The curiosity behind it comes from work on data-plane confidentiality — see
[RFC 8061](https://www.rfc-editor.org/rfc/rfc8061.html).

## Getting started

```toml
[dependencies]
krypto = { version = "0.6", registry = "gitea" }
```

```rust
fn main() -> Result<(), krypto::Error> {
    krypto::harden_process()?;                            // first thing in main()

    let master = krypto::MasterKey::from_secret_file("/run/secrets/master_key")?;
    let key = master.derive(b"my-app/tokens/v1", b"per-store-salt")?;

    let secret = krypto::SecretBuf::from_vec(b"api-token".to_vec())?;
    let blob = krypto::seal(&key, &[0u8; 16], &secret, krypto::Alg::Aegis256)?;
    let back = krypto::open(&key, &blob)?;                // SecretBuf — plaintext stays fenced
    back.expose(|b| assert_eq!(b, b"api-token"));
    Ok(())
}
```

Secrets live in `SecretBuf`/`SecretString` (mlock'ed, zeroized, redacted `Debug`) and never cross
an API boundary as `String` or `Vec<u8>` — a rule enforced by
the type system. Non-Rust consumers use the bundled **`krypto-cli`** binary (seal/open/mac/keyid
and more over stdin/stdout; key material never enters the calling process) — the CLI mirrors the
crate surface, and every deliberate gap is documented in the API contract.

**Open question — the Python side: bindings instead of a subprocess.** Python
reaches this crate through `krypto-cli`, and the parity suite under `python/`
checks that route in both directions. PyO3 bindings are the other way to do it.
The subprocess keeps key material out of the calling process by construction;
bindings would have to earn that on purpose, and they would tie the Python side
to a build toolchain the CLI does not need. Which is the better trade is not
settled, and nothing here depends on the answer.

## Test

```sh
cargo test                     # incl. official AEAD/signature/DH vectors, a docs guard and a version guard
cargo clippy --all-targets -- -D warnings
cargo audit                    # RustSec advisory scan

# Rust ↔ Python parity: pytest drives the real binary against independent
# implementations (cryptography / argon2-cffi) — both directions; also a CI job
python3 -m venv python/.venv && python/.venv/bin/pip install -r python/krav-ci.txt
cargo build --bin krypto-cli && python/.venv/bin/pytest python/ -q
```

## Author

**Roger Jorgensen** — rogerj@gmail.com

Design, architecture and structure; the security model and what it means to fail closed; the
contracts the crate presents outwards; and the decisions about what it does and deliberately
does not do. The code is written by Claude AI (Opus and Fable).

Reviewed independently by DeepSeek, Qwen, Gemini and Fable.

## License

MIT **or** Apache-2.0, at the recipient's choice — the Rust ecosystem norm for libraries.
See [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).
