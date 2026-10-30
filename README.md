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

- **Type:** Rust crate (library), and the same API as a Python module, `krypto-py` (from 0.8.0)
- **Lifetime:** long-lived — the version moves when the surface does, and the API document
  carries the version it applies from
- **License:** MIT/Apache-2.0 dual
- **In use:** already in service in more than one application — among them the `nettls`
  crate, which builds its TLS layer on top of it.
- **Docs (ship with the crate):** overview [`docs/Home.md`](docs/Home.md) · usage guide
  [`docs/Usage.md`](docs/Usage.md) (Rust) and [`docs/Python.md`](docs/Python.md) (Python) ·
  **API contract** [`docs/API.md`](docs/API.md), one for both — every public name, guarded by
  `tests/docs.rs`
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
krypto = "0.8"
```

From Python 3.11 or newer: `pip install krypto-py`, then `import krypto_py` — the same API; see
[`docs/Python.md`](docs/Python.md).

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
the type system.

From Python, the same API is **`krypto-py`** (`pip install krypto-py`, `import krypto_py`): every
function, type, constant and module of the crate, with the same names, built from the same code — so
what one seals, the other opens. They differ only in what can be guaranteed for the copies Python
itself holds; the API contract says exactly where. The bundled **`krypto-cli`** binary runs the
same functions from a shell.

## Test

```sh
cargo test                     # incl. official AEAD/signature/DH vectors, a docs guard and a version guard
cargo clippy --all-targets -- -D warnings
cargo audit                    # RustSec advisory scan

# Rust ↔ Python parity: pytest drives the real binary against independent
# implementations (cryptography / argon2-cffi) — both directions; also a CI job
python3 -m venv python/.venv && python/.venv/bin/pip install -r python/requirements-ci.txt
cargo build --bin krypto-cli && python/.venv/bin/pytest python/ -q

# krypto-py: built with maturin and tested from Python; cargo test checks that it
# has the crate's API, and that Rust and Python open what the other made; also a CI job
python3 -m venv .venv && .venv/bin/pip install -r krypto-py/requirements-ci.txt
VIRTUAL_ENV=.venv .venv/bin/maturin develop --locked -m krypto-py/Cargo.toml
.venv/bin/pytest krypto-py/tests -q
PYO3_PYTHON=$PWD/.venv/bin/python cargo test -p krypto-py
```

## Author

**Roger Jorgensen** — rogerj@gmail.com

Design, architecture and structure; the security model and what it means to fail closed; the
contracts the crate presents outwards; and the decisions about what it does and deliberately
does not do. 

The code is written by Claude AI (Opus and Fable).

Reviewed independently by DeepSeek, Qwen, Gemini and Fable.

## License

MIT **or** Apache-2.0, at the recipient's choice.
See [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).

Both permit the same use. They differ on patents, and that is the reason for offering both:
MIT is silent on them, Apache-2.0 grants one explicitly and withdraws it from anyone who sues
over it (§3). Organisations differ on which of the two their own rules already accept — and in
cryptography the question comes up more often than elsewhere. Offering both means you take the
one you are already cleared for, without having to ask.

### Contributions

**Reports are what is wanted here — not patches.** If something behaves differently from what
the documentation says, or a guarantee does not hold, say so and show how to see it. That is
the most useful thing anyone outside can send. The crate is deliberately narrow, with one
canonical way of doing each thing, so a fix has to fit that canon — and it is quicker and safer
for the fix to be made here than for a patch to be reviewed and reshaped into it.

Code is not refused. It is simply not what is being asked for, and it is not prioritised.
**If you do send it, it is accepted only under the same terms as the crate.** By submitting
code for inclusion you license it as MIT **or** Apache-2.0, at the recipient's choice, with no
additional conditions. Code offered on other terms cannot be merged — not as a judgement on it,
but because the choice this crate gives its users only holds if it holds for every line in it.
A single file on other terms breaks that promise for everyone downstream.

[CONTRIBUTING.md](CONTRIBUTING.md) says how to file a report. [SECURITY.md](SECURITY.md) covers
anything security-related, which does not belong in an issue.
