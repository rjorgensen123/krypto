# Krypto

**In short:** a small, reusable building block that makes sure secrets — passwords, keys and other
sensitive material — are handled safely, both while in use and at rest. It does not invent its own
cryptography; it wraps proven, recognized methods so everything is done one correct way, in one
place.

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
| **Store and check passwords** | without the timing giving anything away |
| **Unlock data with a password** | the key is derived; nothing is stored to guess against |
| **Put a seal on something** | so it can be proven unchanged afterwards |
| **Sign and verify** | Ed25519 and ECDSA P-256 — prove a message came from you |
| **Agree on a key with a peer** | X25519 — the foundation under sealed envelopes |
| **The small utilities everyone needs** | canonical hex, plain SHA-256, constant-time comparison, randomness for non-secrets |
| **Tighten the process itself** | memory, privileges, inherited file descriptors — and finally the whole filesystem. Each step is one call |

If you are not using Rust, a command-line tool ships with the crate and provides the most
important of these — so your program does not have to invent its own crypto.

**[How to use krypto](Usage.md)** shows how each of them is done, with examples.
**[API](API.md)** is the reference over every type and function.

## What it does not do

Just as important as what it can:

- **It does not invent cryptography.** Everything under the hood is published, recognized methods.
- **It does not know what your data means.** You tell it what purpose a key has; it only makes
  sure different purposes get different keys.
- **It does not handle login, permissions or roles.** It gives you the building blocks; who is
  allowed to do what is your program's job.
- **It does not decide where your master key comes from.** You must provide it — from a file,
  from a password, or from something you unlocked yourself.

## What it is built on

Krypto does **not** invent its own cryptography. Everything is published, recognized methods — the
library's job is to make sure they are used correctly, in one place, instead of every user rolling
their own variant. Here is what actually runs, with a reference for each:

| Purpose | Algorithm | Reference |
|---|---|---|
| Encryption (AEAD) — **default** | AEGIS-256 | [IETF CFRG draft (AEGIS)](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/) |
| Encryption (AEAD) — variant | XChaCha20-Poly1305 | [XChaCha draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha) · basis: [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) |
| Encryption (AEAD) — interop | AES-256-GCM | [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800-38d/final) |
| Key derivation | HKDF (with SHA-256) | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) |
| Hash | SHA-256 (SHA-2) | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) |
| Password hashing and key derivation | Argon2id | [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) |
| Signatures | Ed25519 | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) |
| Signatures | ECDSA P-256 (SHA-256, deterministic) | [FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final) · [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979) |
| Key agreement | X25519 | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) |
| Randomness | the operating system's CSPRNG (`getrandom`) | — |

**Why three encryption algorithms and not one?**

**AEGIS-256** is the default — fast and modern. **XChaCha20-Poly1305** is there as an exit: should
the analysis of the default ever turn, you can switch without converting data, because they share a
format. **AES-256-GCM** exists to talk to systems that require exactly that one.

Encrypted data says for itself which algorithm was used, so the reader does not need to know in
advance — and a switch does not make old data unreadable.

All `unsafe` in the library is isolated in a single layer that talks to the operating system
(memory locking and process hardening). The rest of the code cannot contain `unsafe` — the compiler
refuses.

## Built alongside

**nettls** is a sister building block that handles
TLS — certificates, pinning and rotation. It uses krypto for its secrets and for locking its own
state at rest, instead of rolling its own cryptography.

The two are made on the same principle: generic, reusable, and with no knowledge of what is built
on top. If you need both TLS and secret handling, they belong together — but each works on its own.

## Maturity

The library is in active use and covers what is needed today. The format of encrypted data has been
stable since early on.


## Possible future extensions

Not planned — but thought through, and the format is laid out so they can arrive without breakage:

- **Multiple key generations in the store** (`active`/`historic`/`retired`). Rotation exists
  today as an action (`reseal` and the store's `rotate`); this would let a store know several
  generations at once, so re-encryption can happen gradually — and a leaked old backup can be
  made worthless. The format already carries a generation id per entry, precisely for this.
- **Peppered HMAC for passwords.** A second layer on top of Argon2id, keyed with a secret that
  lives outside the database — whoever steals only the database then has nothing to brute-force
  against. The pepper would live with whoever owns login policy, not in the library.

## Author

**Roger Jorgensen** — rogerj@gmail.com

Design, architecture and structure; the security model and what it means to fail closed; the
contracts the crate presents outwards; and the decisions about what it does and deliberately
does not do. 

The code is written by Claude AI (Opus and Fable).

Reviewed independently by DeepSeek, Qwen, Gemini and Fable.


## License

Open source: **MIT / Apache-2.0** — your choice. Free to use and build on.

*(Internal working name: "Fafnir".)*
