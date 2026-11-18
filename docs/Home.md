# Krypto

**In short:** a small, reusable building block that makes sure secrets — passwords, keys and other
sensitive material — are handled safely, both while in use and at rest. It does not invent its own
cryptography; it wraps proven, recognized methods so everything is done one correct way, in one
place. It comes for Rust (the crate `krypto`) and for Python (the package `krypto-py`, imported as
`krypto_py`): the same API in both, running the same code.

## Why does it exist?

Because handling secrets is easy to get *almost* right.

A password sitting in an ordinary string can end up in a core dump, linger in memory after use, or
show up in a log line because someone printed a variable. Data that is "encrypted" can still be
silently modified. A password check can leak the answer through how long it takes.

None of these are obvious, and all of them are easy to fall into. Krypto collects the solutions in
one place, so whoever builds on top of it does not need to know every single trap — and so fixes
happen once, not in every program.

That is also how it started. The same handful of primitives kept being written from scratch in one
application after another — sealing a secret at rest, deriving a key from a password, holding a
secret in memory without scattering copies of it. Each rewrite was a new chance to get it subtly
wrong. So the idea was to write it once, carefully, and then never write it again. This crate is
that one time.

The curiosity behind it comes from work on data-plane confidentiality — see
[RFC 8061](https://www.rfc-editor.org/rfc/rfc8061.html).

## What can you use it for?

| | |
|---|---|
| **Hold a secret while the program runs** | locked memory, zeroed automatically, cannot be printed by accident |
| **Encrypt something for storage** | and detect with certainty if anyone changed it |
| **Make many keys out of one** | one key per purpose, without storing several |
| **A small encrypted store on disk** | secrets under names, like a keyring |
| **Store and check passwords** | the check takes as long whether the password is right or wrong |
| **Unlock data with a password** | the key is derived, and no password hash is stored beside the data; the encrypted data itself can still be used to test guesses |
| **Put a seal on something** | so it can be proven unchanged afterwards |
| **Sign and verify** | Ed25519 and ECDSA P-256 — prove a message came from you |
| **Agree on a key with a peer** | X25519 — the foundation under sealed envelopes |
| **The small utilities everyone needs** | canonical hex, plain SHA-256, constant-time comparison, randomness for non-secrets |
| **Tighten the process itself** | memory, privileges, open file descriptors — and finally the whole filesystem. Each step is one call |

All of it is there from Rust and from Python. `krypto-py` is the same API in Python, with the
same names, running the same Rust code inside, so what one seals, the other opens. A small helper,
`krypto-cli`, checks from a shell what they made, and how fast Argon2 is on the machine.

**[How to use krypto](Usage.md)** shows how each of them is done, with examples in Rust, and
**[from Python](Python.md)** the same with Python code. **[API](API.md)** is the reference over
every type and function, for both. The design has its own specification in
[`spec/`](../spec/README.md): what krypto is and why it is built as it is, the threat model, and
the stored formats.

## What it does not do

Just as important as what it can:

- **It does not invent cryptography.** Everything under the hood is published, recognized methods.
- **It does not know what your data means.** You tell it what purpose a key has; it only makes
  sure different purposes get different keys.
- **It does not handle login, permissions or roles.** It gives you the building blocks; who is
  allowed to do what is your program's job.
- **It does not decide where your master key comes from.** You must provide it — from a file,
  from a password, or from something you unlocked yourself.
- **It does not log, alarm or count attempts.** It answers what happened, and no answer carries a
  secret; what to record, what to alarm on and how often a password may be tried is your
  program's.

What krypto protects, against whom, and what it leaves to you is in the
[threat model](../spec/THREAT-MODEL.md).

## What it is built on

Krypto does **not** invent its own cryptography. Everything is published, recognized methods — the
library's job is to make sure they are used correctly, in one place, instead of every user rolling
their own variant. Here is what actually runs, with a reference for each:

| Purpose | Algorithm | Reference |
|---|---|---|
| Encryption (AEAD) — **default** | AEGIS-256 | [RFC 10032](https://www.rfc-editor.org/rfc/rfc10032) |
| Encryption (AEAD) — variant | XChaCha20-Poly1305 | [XChaCha draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha) · basis: [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) |
| Encryption (AEAD) — interop | AES-256-GCM | [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800-38d/final) |
| Key derivation | HKDF (with SHA-256) | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) |
| Hash | SHA-256 (SHA-2) | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) |
| Password hashing and key derivation | Argon2id | [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) |
| Signatures | Ed25519 | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) |
| Signatures | ECDSA P-256 (SHA-256, deterministic) | [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) · [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) |
| Key agreement | X25519 | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) |
| Randomness | the operating system's CSPRNG: the `getrandom` system call, or `/dev/urandom` where that call is unavailable or blocked | — |

Why the three ciphers and the key forms were chosen, and how each algorithm is checked against its
definition, is in [SPEC-krypto](../spec/SPEC-krypto.md) and
[SPEC-primitives](../spec/SPEC-primitives.md).

**Why three encryption algorithms and not one?**

**AEGIS-256** is the first choice — fast and modern. **XChaCha20-Poly1305** is there as an exit:
should the analysis of AEGIS-256 ever turn, you can switch without converting data, because they
share a format. **AES-256-GCM** exists to talk to systems that require exactly that one.

Encrypted data says for itself which algorithm was used, so the reader does not need to know in
advance — and a switch does not make old data unreadable.

All `unsafe` in the library is isolated in a single layer that talks to the operating system
(memory locking and process hardening). The rest of the library is compiled with
`deny(unsafe_code)`, which only that layer overrides. `krypto-py`, the Python binding, has `unsafe`
of its own: *(0.8.2)* it is compiled with `deny(unsafe_code)` too, and two places in its source
override it, each with its own `allow`.

## Built alongside

**nettls** is a sister building block that handles
TLS — certificates, pinning and rotation. It uses krypto for its secrets and for locking its own
state at rest, instead of rolling its own cryptography.

The two are made on the same principle: generic, reusable, and with no knowledge of what is built
on top. If you need both TLS and secret handling, they belong together — but each works on its own.

## Maturity

The format of encrypted data has been the same since early on, but AEGIS-256 blobs from 0.4.4 and
older do not open in 0.5.0 and newer: 0.5.0 fixed a key and nonce swap in AEGIS-256, and such
blobs, the entries of store files those versions wrote included, must be encrypted again. From
0.9.0 a blob larger than 64 MiB plus 86 bytes does not open, also one an earlier krypto sealed, and
a new `SecretStore` file is format version 2, which krypto before 0.9.0 does not read; version 1
files are read and written as before.

## Reviews

krypto has been reviewed by AI models. These are not audits by a security firm.

| Date | Reviewer | Version | Kind |
|---|---|---|---|
| 2026-10-09 | MiMo V2.6 Flash | 0.7.0 | code review, read only |
| 2026-10-30 | MiMo V2.6 Flash | 0.8.0, before release | code review, read only |
| 2026-11-08 | Mistral Vibe | 0.8.0 | code review |
| 2026-11-12 | Gemini | 0.8.0 | security audit |
| 2026-11-12 | MiMo V2.6 Flash | 0.8.0 | security audit |

Earlier versions were also reviewed by DeepSeek, Qwen, Gemini and Fable.

The MiMo security audit used Cloudflare's
[`security-audit`](https://github.com/cloudflare/security-audit-skill) skill.

Each finding is assessed against the code, and the ones that hold are fixed;
the CHANGELOG records the fixes.

## Author

**Roger Jorgensen** — rogerj@gmail.com

Design, architecture and structure; the security model and what it means to fail closed; the
contracts the crate presents outwards; and the decisions about what it does and deliberately
does not do. 

The code is written by Claude AI (Opus and Fable).


## License

Open source: **MIT / Apache-2.0** — your choice. Free to use and build on.

*(Internal working name: "Fafnir".)*
