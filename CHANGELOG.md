# Changelog — krypto (codename: Fafnir)

Every notable change to this crate is recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/).

## [0.7.0] — 2026-09-21

*Found by two independent reviews of the crate. Three of these refuse input that
earlier versions accepted, so a consumer that passed oversized input will see
an error where it saw none.*

### ⚠ Security — `SecretBuf::from_vec` left the source unwiped when `mlock` failed

`from_vec` promised to zeroize the `Vec` it takes over, and did — except on the
one path where it matters. `locked_zeroed(...)?` returned before `v.zeroize()`,
so a failing `mlock` dropped the secret into the heap unwiped, on precisely the
path that is meant to be fail-closed. `SecretString::from_string` inherited it,
so it applied to passwords.

Not hypothetical: a container gets 8 MiB of memlock by default, and the crate
locks every `SecretBuf`. The wipe is unconditional now, and the buffer becomes a
`SecretBuf` before it is filled — the same shape as `random`, so `Drop` owns it
from the first instant.

### Added — `MAX_DERIVE_INPUT_BYTES` (1 KiB)

`MasterKey::derive` took `info` and `salt` of any length. Both reach the API from
command lines and config files, where the size is the caller's to choose, and
bounded input is the rule everywhere else in the crate. Measured against real
use: the longest `info` the crate itself builds is the store's prefix plus a key
name, 528 bytes.

### Changed — `MasterKey::from_bytes` caps the key at `MAX_MASTER_KEY_BYTES`

`from_secret_file` always did; `from_bytes` accepted anything above 32 bytes. Two
ways into one type must not mean two different rules — and the API contract
already said the cap applied to both.

### Changed — `SecretStore` validates key names on read, not only on write

`put` has fenced the character set from the start, so the rule held only for what
this process had written. A store file need not come from `put`: a restore, a
copy or tampering can put anything there, and `list()` hands names to a consumer
that logs them. Reading is fenced like writing now.

### Changed — the doc guard matches whole identifiers

It compared with a plain substring, which is close to vacuous for short names:
`len` hides inside "si**len**tly", `get` inside "tar**get**". Tightening it found
no gaps — the names were all genuinely documented — but the guard can now tell.

### Note — the repository history starts here, on purpose

Between 0.6.2 and this release the repository was cleaned out and started fresh.
The earlier commits were written while a larger private system was being built,
and they describe it: sibling services, internal documents, decisions that
belong to that system rather than to this crate. Carrying them along would have
mixed design for other things into a crate that is meant to stand on its own.

What each release changed is in this file, and the code is what it always was —
the tree at 0.7.0 is the tree that was there before, minus the references that
pointed out of it. Only the commit history was left behind.

## [0.6.2] — 2026-08-30 (the filesystem hardening)

### Added — hardening step 2: `no_new_privs` · `close_inherited_fds` · `drop_filesystem`

Three separate, optional calls. The crate offers the mechanism; the service decides when:

- **`no_new_privs()`** — the process and every child can never gain further privileges
  (`PR_SET_NO_NEW_PRIVS`). Safe for anyone; call it early, right after `harden_process()`.
- **`close_inherited_fds()`** — closes everything inherited above stderr in one call
  (`close_range`, Linux 5.9+, no `/proc`). Its own call because it also closes deliberately
  inherited sockets, as in socket activation — the service decides.
- **`drop_filesystem(dir)`** — `chroot` into an **empty** directory, verified empty before
  the call, plus `chdir("/")`, once the key material has been read. Irreversible; needs root
  or `CAP_SYS_CHROOT`. After it the crate has no use for the filesystem: randomness is the
  `getrandom` syscall, and AEAD, KDF, signing and passwords never touch disk.

All of it is fail-closed, like mlock: called and failing is a hard error, never a silent
downgrade. Off Linux the new calls fail honestly instead of pretending (`harden_process`
keeps its best-effort behaviour unchanged). **Deliberately absent from `krypto-cli`**:
hardening is process-local, and hardening a subprocess does not protect its caller.

### Added — `libc` as a dev dependency

The dangerous calls are tested in a **forked child**, so a success — as root in CI, say —
cannot damage the test binary itself. The chroot attempt is verified both ways (root gives
success in the child; unprivileged gives a hard error), and the fd closing is verified with
`fcntl` on an inherited descriptor.

## [0.6.1] — 2026-08-30

*Documentation and tooling. No change to the crate's surface.*

### Added — possible future extensions, written down as possible

Multi-key generations in the store, and peppered HMAC for passwords: the formats leave room
for both, neither is planned. The doc comment in `password.rs` now explains the pepper
boundary itself instead of pointing elsewhere.

### Added — the doc guard covers the CLI too

`tests/docs.rs` guarded the library surface — every public name must appear in the API
contract — but was blind to the binary, so a new CLI command could ship undocumented without
anything failing. The test now reads the `COMMANDS` constant in `krypto-cli.rs`, which is
what dispatch itself validates against, and requires every command to be documented. Half a
guard catches half the drift.

### Changed — the language transition is finished

The overview pages still said the changelog carried a Norwegian/English table "while the
transition lasts". The transition is over; the table stands as history.

### Changed — the README stands on its own

It pointed outside the repository, at paths that only resolve when sibling repositories sit
side by side, and at a file that had been removed. It carried two release summaries the
changelog owns — one of them wrong, saying rotation was a later delivery when it had landed
in 0.6.0 — a consumer table it did not own, a migration note `[0.5.0]` already carries, and
numbers that rot: a test count and a version string. Now it says what the crate is, how to
start, how to test, and the licence.

### Removed — the plan file

It repeated what other documents owned — purpose, licence, dependencies, API surface, input
validation, invariants, milestones, test requirements — and had gone stale where those were
corrected: it described 0.4.2, named a preset that had since been renamed, and said rotation
was not built. It was also the source of most of the out-of-repository paths. Archived
unedited; the decisions it held live on in the API contract and `Cargo.toml`.

### Changed — cargo-deny 0.18.4 → 0.20.2 in CI

0.18.4 broke on CVSS 4.0 in a fresh advisory database. Tooling only; the crate untouched.

## [0.6.0] — 2026-08-26 (modulrunden)

### Added — `pub const VERSION`

`krypto::VERSION` mirrors `Cargo.toml`, so a consumer can report the component
version instead of "unknown". **krypto-cli:** new `version` command — the CLI
mirrors the crate surface.

### Added — `krypto-cli rand`

`rand --n <bytes>` writes hex: a CSPRNG for values that are NOT secret — salts, seeds —
through `random_bytes`, so a caller in another language need not improvise its own source.
**Deliberate gaps in the CLI surface**, documented in the API contract: `ct_eq` is
not exposed — secrets as shell arguments leak on their own, and `verify` /
`password-verify` cover the cases — and neither is `SecretStore`, because no
consumer needed it. Either can be added if a real need turns up.

### Changed — `Preset::Balanced`: p 2 → 3 (m=128 MiB, t=3, p=3)

A middle profile between the two the reference gives, 64/3/2 and 256/4/4. Free
to tune later: the parameters live in the PHC string, so existing hashes verify
unchanged.

### Added — dependency audit and memory verification in CI

`deny.toml` and a `deny` job: RustSec advisories, a license allowlist, a ban on `rsa`
(RUSTSEC-2023-0071, verified absent from the tree) and source control. Two more jobs:
`miri` over `secret` and `harden`, the tests above the unsafe layer — `aead` and `store`
cannot run under Miri because aegis is C behind FFI — and `asan` over the whole suite,
natively, with an instrumented std. In `src/ffi.rs` the syscall wrappers are no-ops under
Miri.

### Added — key rotation: `reseal` + `SecretStore::rotate` (L2-066)

The rotation *action*. The crate stays stateless: both keys come from the consumer, who owns
when and why.

- **`reseal(old, new, new_key_id, blob)`** (blob level, for a consumer that keeps its own
  store): opens with the old key, seals with the new one under a new generation id, and
  **preserves the algorithm**. Fail-closed: a wrong old key or a tampered blob gives `Auth`,
  and nothing is produced.
- **`SecretStore::rotate(new_master)`** (file level): consumes the handle, which is bound to
  the old master, decrypts EVERYTHING first, then writes a whole new file atomically with a
  fresh salt and a fresh generation id — never a half-rotated store. If anything fails, the
  file is untouched.
- **krypto-cli:** new command `reseal --key-file <old> --new-key-file <new> --context <s>
  --salt <s>` (blob on stdin, new blob on stdout); an old generation against the wrong
  `--key-file` exits 4, a routing answer, the same as `open`. `rotate` is NOT exposed in the
  CLI — `SecretStore` is already out of scope there.
- **Note:** a `MasterKey::from_passphrase` was considered and is not needed as its own
  function; the composition already exists:
  `MasterKey::from_bytes(password::derive_key(password, salt, preset)?)`.

### Added — doc guard: `tests/docs.rs`

Every public name in the crate MUST appear in the API contract, or the test fails. The
contract can no longer drift from the code without CI saying so.

### Changed — the API contract is the one in the repository

A step of the work was finished and written up, and the API document was tidied to match:
what ships with the crate is the interface reference that applies to the code.

## [0.5.1] — 2026-08-16

### Added — `krypto::base64`

Canonical base64 (the STANDARD alphabet), the same style and philosophy as `hex`: one
spelling out, strictly that same one in. `encode`/`decode` with padding, the PEM body form,
and `encode_nopad`/`decode_nopad`, the ssh fingerprint form `SHA256:<base64-no-pad>`.
Fail-closed decoding: whitespace, invalid characters, wrong padding AND non-canonical
trailing bits are all refused (`Error::Format`) — two spellings of the same bytes must not be
possible. The published RFC 4648 vectors are in the tests.

**Note:** hex remains the canonical form. base64 is only for formats that ARE base64 by
nature — ssh fingerprints, PEM.

**krypto-cli:** nye kommandoer `b64-encode` · `b64-encode-nopad` · `b64-decode` ·
`b64-decode-nopad` (decode skriver hex — kanon). Python-paritet verifisert begge veier
mot stdlib (`test_cli_parity.py`, alle padding-tilfeller).

## [0.5.0] — 2026-08-15

*The crate's first major revision, planned as such: a pre-release review concluded the crate
was stable and good but with clear weaknesses — a 0.5, not a 0.9. This release breaks
things that were previously considered locked, on purpose. From 0.5.0 the changelog is written
in English; the code, error messages, doc comments, tests and CLI texts switched too.*

### ⚠ Security/correctness — AEGIS-256 had key and nonce swapped (found by new test vectors)

The `aegis` crate's constructor is `new(key, nonce)`; krypto called `new(nonce, key)`. Both are
`&[u8; 32]` for AEGIS-256, so the compiler could not catch it — and every roundtrip test passed,
because seal and open made the same swap. The cipher was therefore keyed with the *public*
per-blob nonce from the FAFN header, with the secret derived key in the nonce position. Not the
analyzed AEGIS-256 construction, and interop-broken against any conformant implementation.
Decryption still required the secret, but this is fixed, not defended.

- **Fixed and verified against the official `draft-irtf-cfrg-aegis-aead` vectors** (256-bit
  tag), both directions, plus tag-tampering checks. XChaCha20-Poly1305 and AES-256-GCM passed
  their official vectors (draft-arciszewski A.1, NIST CAVS) on the first attempt — those
  implementations were correct all along.
- **Data consequence: AEGIS-256 blobs sealed by krypto ≤ 0.4.4 cannot be opened by ≥ 0.5.0**
  (and vice versa). Affected at-rest data must be **resealed** — nettls (lockbox, envelope)
  among it, and anything sealed through `krypto-cli` with the `aegis256` default. As of this
  release none of it runs in production. XChaCha and AES-GCM blobs are unaffected.
- Found by the known-answer tests added in this release (below) — the exact gap a review had
  pointed at: *"the AEGIS-256 implementation was only ever verified against itself."*

### Changed — ⚠ BREAKING: Norwegian → English (the language switch)

The public surface is now fully English. Consumers fix their side; this table is the map
(kept through the transition, removed in a later version):

| Before (Norwegian) | Now (English) | Note |
|---|---|---|
| `password::utled_noekkel(pw, salt, preset)` | `password::derive_key(pw, salt, preset)` | same behavior, same signature |
| `Preset::Moderate` (256 MiB, t=4, p=4) | `Preset::High` | **same parameters** — the old name said "middle", the numbers were the strictest |

Known call sites to update: `nettls/src/lockbox.rs` (`utled_noekkel`), and anywhere a consumer
called `utled_noekkel`, named `Preset::Moderate`, or stored the profile name `"moderate"`.

All error messages (`Error::Display`, `Format`/`Hardening` payloads), doc comments, test names
and `krypto-cli` usage/error texts are English now. Anything matching on Norwegian error
substrings must adapt. Exit codes, flags, commands, blob formats and derivation contexts are
**unchanged**: `FAFN`, `FST1`, `krypto/store/v1|`, `krypto/key-id/v1`, alg_ids 1/2/3.

### Added — the §8d.1 extension: one place for what every consumer was rolling itself
- **`sign` module** — Ed25519 (raw 32-byte seed/public, 64-byte signature — the form the
  services already distribute) and ECDSA P-256 (PKCS#8 private key, SEC1 public point,
  ASN.1 DER signature over SHA-256, RFC 6979 deterministic). **Cross-verified against `ring`
  in both directions** (including `ring` parsing krypto's PKCS#8), so nettls can migrate off
  `ring` for §6 signatures without a wire change. Tested against RFC 8032 (TEST 1+2) and
  RFC 6979 A.2.5.
- **`exchange` module** — X25519 key agreement (RFC 7748, tested against §6.1 vectors).
  Rejects non-contributory results. The sealed-envelope *format* stays with the consumer
  (nettls's `NETENV`); krypto provides the primitive + HKDF + AEAD it is built from.
- **`hex` module** — canonical hex: lowercase out, strictly lowercase in (fail-closed).
  One spelling of the same bytes, because hex ends up inside signed canonical forms.
  nettls carried two internal variants; both can go.
- **Root utilities** — `sha256` (plain FIPS 180-4, for fingerprints), `ct_eq` (constant-time
  comparison via `subtle`), `random_bytes` (OS CSPRNG for values that are NOT secrets — the
  deliberate contrast to `SecretBuf::random`).
- **Rust ↔ Python parity is enforced in CI**: `python/test_cli_parity.py` (19 pytest cases,
  pinned deps in `python/krav-ci.txt` — same versions as nettls) drives the real binary as a
  subprocess and checks every answer against an independent Python implementation
  (`cryptography`/`argon2-cffi`/`hashlib`), in both directions: AES-GCM blobs sealed on one
  side and opened on the other, Ed25519/ECDSA signatures both ways including key-file
  interchange (raw seed / PKCS#8), identical X25519 shared secrets, byte-identical argon2id
  derivation, the PHC parameters of all three presets, and the exit-code semantics (3 = alarm,
  4 = routing). A new `blob-key-id` subcommand answers the routing question after exit 4.
- **`krypto-cli` mirrors the whole surface** — the bridge must give a non-Rust caller the
  same features and API as Rust: new subcommands `keygen`/`public`/`sign`/`verify` (ed25519,
  p256), `shared` (x25519), `derive-key`, `password-hash`/`password-verify`, `sha256`. One rule
  throughout: **private key material never crosses into the calling process** — it goes to
  files (mode 0600, `create_new`: an existing file is never overwritten); the files from
  `shared`/`derive-key` are usable directly as `--key-file` for seal/open/mac. Hex arguments
  are canonical lowercase; passwords come on stdin with one trailing newline stripped.
- New dependencies for the above: `ed25519-dalek`, `p256`, `x25519-dalek`, `subtle`
  (RustCrypto/dalek — established implementations, no crypto of our own). `cargo audit`
  clean with the full tree (73 dependencies).

### Added
- **`Preset::Balanced`** (m = 128 MiB, t = 3, p = 2) — the always-missing middle profile
  A consumer's own contract once invented "128 MiB" precisely because this gap existed. Parameters may still be tuned against real numbers (L2-055).
  Old PHC hashes verify unchanged after any profile revision (the parameters live in the PHC
  string); *rehash at next login* is the consumer's part of a profile upgrade.
- **`Error::WrongKey`** — a blob sealed under a different key generation is now a routing
  outcome, not a tampering alarm. `SecretStore::get` compares the blob's
  `key_id` against the store's own before opening; raw `open()` cannot know the expected id and
  still reports `Auth`. **`krypto-cli open` exits with the new code 4** for a wrong key
  generation, so exit 3 ("tampering, alarm") stops lying about old-generation blobs.
- **`MAX_MASTER_KEY_BYTES` and `MAX_STORE_BYTES` are re-exported** from the crate root — they
  were named in the contract but unreachable (`pub` in private modules).
- **Official known-answer vectors** as tests: AEGIS-256 (draft vectors 2 and 3, 256-bit tag),
  XChaCha20-Poly1305 (draft-arciszewski-03 A.1), AES-256-GCM (NIST CAVS). The AEAD layer is no
  longer verified only against itself.
- **Version guard test** (`tests/version.rs`): a release can no longer ship without `VERSION`
  and a changelog entry following along (the 0.4.3/0.4.4 failure mode, §8b.8).

### Changed
- `[profile.dev.package.argon2] opt-level = 3` — the `High` preset cost ~30 s per hash in debug
  builds; the password test suite went from ~35 s back to ~2 s. Release builds unaffected.
- `Cargo.toml` description is English.

---

*Entries before 0.5.0 have been removed — they were historically inaccurate and of
no relevance to a user of this crate.*
