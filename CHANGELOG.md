# Changelog — krypto (codename: Fafnir)

Every notable change to this crate is recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/).

## [0.9.0]

### Added — store file format version 2, with whole-file authentication and rollback detection *(2026-11-16)*

`SecretStore` files come in two format versions; the normative description is
`spec/SPEC-secretstore.md`. Version 2 keeps the `FST1` magic and the v1 entry encoding and adds
to the header: `key_check` (HMAC-SHA256 under the key derived for `krypto/store/v2|key-check`),
a write `counter`, and `container_mac` (HMAC-SHA256 under `krypto/store/v2|container-mac`) over
the header and all entries, compared in constant time. The per-name entry keys
(`krypto/store/v1|` + name) are unchanged, so an upgrade re-wraps the blobs without
re-encrypting them. New stores are version 2 by default; an opened file is always written back
in its own version (sticky), and `open` reads both versions. `MAX_STORE_BYTES` caps the whole
file, the 109-byte v2 header included, on read and on write. `krypto-cli inspect` reads store
files of both versions.

New API on `SecretStore`: `open_with_version` (an open that names version 1 or 2: it accepts
only a file of that version and creates one if there is none; a file of the other version is
`Format`, and the error says which version the file is), `upgrade` (v1 → v2, one-way: every
entry is decrypted and verified first, any `Auth` leaves the file untouched, then one atomic
write as v2), `open_with_min_counter` (names version 2; fails with the new
`Error::Rollback { file_counter, min_counter }` — `RollbackError` in krypto-py — when the
file's counter is below the caller's minimum; with a minimum above 0 a missing file is `Io`
and nothing is created), and `version()` / `counter()`. A write to a store whose counter is at
its maximum fails with `Hardening`: the store must be rotated. krypto stays stateless: the
rollback anchor is kept by the caller, outside the file. `rotate` keeps the file's version
and, on a v2 file, resets the counter to 0 with a fresh salt and key id, `key_check` and
`container_mac` recomputed.

### Added — caller-supplied AAD on blobs: `seal_with_aad` / `open_with_aad` / `reseal_with_aad` *(2026-11-16)*

`seal`, `open` and `reseal` keep their signatures and behaviour. The new `_with_aad` variants let
the caller bind a blob to a context — a record id, a channel, a timestamp — without putting it in
the plaintext: the AEAD's AAD is the 54-byte header followed by the caller's `aad`. The header has
a fixed length, so the concatenation is unambiguous and an empty `aad` is exactly the AAD
`seal`/`open` have always used: **the `FAFN` blob format is unchanged** and every existing blob
opens as before. The `aad` is not stored in the blob; it must be supplied again at open, and a
missing or different `aad` fails with `Auth` like any other tampering. `reseal_with_aad` takes
the old AAD (to open) and the new AAD (to seal under) and preserves the blob's algorithm, as
`reseal` does. Mirrored in krypto-py (`seal_with_aad`, `open_with_aad`, `reseal_with_aad`).

### ⚠ Changed — `open` on a version 2 file checks the key and the file first *(2026-11-16)*

On a v2 file, `open` checks three things before anything else in the file is read: the whole
header is there (`Auth` if not), `key_check` (`WrongKey`: the master key does not fit the
file), and `container_mac` (`Auth`: the file is not what was written, such as a removed,
swapped or injected entry). Only then is the structure read (`Format`). A wrong master key now
fails at `open`, not first at `get`. An unknown version byte is `Format`
(`unsupported store version N`), so a v2 file read by a pre-0.9.0 krypto is refused, and after
an `upgrade` older binaries can no longer read the store. Version 1 files are unchanged: still
readable, no key check at `open`, no container MAC, a wrong key still shows as `Auth` from `get`.

### ⚠ Changed — a blob cut short past its `FAFN` magic is `Auth`, not `Format` *(2026-11-16)*

The magic is now checked before the length, so data that starts with `FAFN` but is shorter than
the 54-byte header is a changed blob: `Auth`, where it was `Format`, in `open`, `reseal`,
`blob_key_id` and `SecretStore::get` (krypto-py `AuthError` instead of `FormatError`). Data shorter
than the 4-byte magic, or not starting with `FAFN`, is still `Format`. In `krypto-cli`, `open`
gives exit 3 for such a blob (it was 1), and `inspect` reports the header as cut short with exit 3
(it was 0).

### Fixed — `SecretStore::put` checks the 16 MiB cap before sealing *(2026-11-16)*

The prospective file size (header included) is computed before the value is encrypted; over the
cap fails with the same `Format` as before, just without sealing or building the file first.

### Fixed — `hex::decode`, `base64::decode` and `base64::decode_nopad` fail with `Hardening` when the output buffer cannot be reserved *(2026-11-16)*

The decoders reserve the output buffer with `try_reserve_exact`: a failed reservation is
`Error::Hardening` (krypto-py `HardeningError`) where it was a process abort. A length the system
promises but cannot back still fills the memory.

### Added — `MAX_AAD_BYTES`: the caller's AAD is capped at 1024 bytes *(2026-11-17)*

The `aad` of `seal_with_aad` and `open_with_aad`, and both AADs of `reseal_with_aad`, are at most
`MAX_AAD_BYTES` (1024) bytes, the same size as the cap on `info` and salt. A longer one is `Format`
(krypto-py `FormatError`), refused before a nonce is drawn, the blob is read or a key is used. To
bind a blob to something larger, pass a hash of it as the AAD. The constant is in krypto-py too.

### Changed — tests and documentation for the changes above *(2026-11-17)*

- Tests: `krypto-cli open` and `inspect` on a blob cut short in its header; that `put` refuses an
  over-cap value before it seals; a wrong AAD for all three algorithms; and the order of header
  and AAD, checked against an AES-256-GCM implementation krypto did not write.
- The test that compares the Rust and the Python API reads a `pub use` that spans several lines;
  it had stopped before comparing anything.
- Documentation: `docs/Inspect.md`, `docs/Cli.md` and the `inspect` help say that a header cut
  short is exit 3; `docs/API.md` lists the AAD functions in its root block, says that the AAD is
  public data held in ordinary memory, and states what `blob_key_id` does and does not detect.

### Changed — the `SecretStore` spec is revised *(2026-11-17)*

`spec/SPEC-secretstore.md` is now spec version 2.0. Its revision history says what changed.

### Added — a store's `key_id` can be read *(2026-11-17)*

`SecretStore::key_id()` gives the `key_id` of an open store. `SecretStore::key_id_from_file(path)`
reads it from a file without the master key; the value is what the file says and is not
authenticated. Both are in krypto-py too.

### Changed — error texts and the README figure for locked memory *(2026-11-17)*

The text of `WrongKey` covers a store file as well as a blob; `krypto-cli` prints it. In
krypto-py, a `SecretStore` handle used after `rotate` or `upgrade` says that it was consumed by
one of them. The README says that `cargo test` needs a locked-memory limit above 22 MiB; it
said 6 MiB.

### ⚠ Changed — a new store is version 2, which krypto before 0.9.0 cannot read *(2026-11-17)*

A store created by `open` is file format version 2. krypto before 0.9.0 refuses such a file
with `Format` (`unsupported store version 2`). Where older readers must keep working, create
the store with `open_with_version(path, master, 1)`. A version 1 file stays version 1 until it
is upgraded.

### Changed — the store documentation says what each file version protects *(2026-11-17)*

`docs/API.md`, `docs/Usage.md` and `docs/Python.md` say what a version 1 file and a version 2
file protect, each for itself, and that a version 2 file made into a version 1 file is refused
only by an open that names version 2.
They also say that a store file is not tied to its path, and the README and `docs/Home.md`
point to the spec. Tests: duplicate names in a version 2 file, and that the counter follows
the file after a failed write.

### Changed — the documentation is corrected for 0.9.0 *(2026-11-17)*

`docs/API.md` is checked against the code in both directions, and its floor is 0.9.0. It now
says which error each limit gives, the order `put` checks in, what `delete` of a name that is
not there does, and how the Python forms differ. Sentences that said more than the code does,
and notes on how things were in earlier versions, are removed. `docs/Usage.md` has a row for
0.8.2 and a complete row for 0.9.0. The README install line says `krypto = "0.9"`, and
`SECURITY.md` lists 0.9.x as the supported version.

## [0.8.2]

### Added — the README and Home say who has reviewed krypto *(2026-11-15)*

The README and `docs/Home.md` list the reviews of krypto: the date, the model,
the version and the kind of review, and that the MiMo security audit used
Cloudflare's `security-audit` skill. They are reviews by AI models, not audits
by a security firm.

### ⚠ Changed — `ed25519_verify` refuses weak keys; `ed25519_verify_relaxed` is new *(2026-11-15)*

`sign::ed25519_verify` is now strict. A public key of small order (a weak key,
for which anyone can make signatures that hold without a private key) or an R
of small order in the signature is `Auth`, and a public key that is not the
canonical 32-byte encoding of its point is `Format`. Up to 0.8.1 it only
checked the signature equation, so the identity point as key, with R =
identity and S = 0, verified for every message. Keys and signatures made by
krypto verify as before; `krypto-cli verify --alg ed25519` is strict too.

The new `sign::ed25519_verify_relaxed` (`sign.ed25519_verify_relaxed` in
krypto-py) does what `ed25519_verify` did: it only checks the equation and
accepts weak keys. It is for a caller that must accept such keys, never for
checking who signed with a public key from someone else. P-256 is unchanged.

### ⚠ Changed — `password::verify` accepts only the hashes krypto makes *(2026-11-15)*

`password::verify` checks the stored PHC string before Argon2 runs, and refuses
with `Format` what krypto does not make or could not make: Argon2i and Argon2d,
a version other than 19 or a string without `v=`, a `keyid` (a secret key
krypto does not have), and parameters below the floor (`m ≥ 64 MiB, t ≥ 2,
p ≥ 1`) or above a ceiling a little over `High` (m ≤ 320 MiB, t ≤ 5, p ≤ 5; it
follows `High`). Associated data (`data=`) is accepted. Before, the string
decided how much memory and time one call used, without a limit, and a weaker
or foreign hash was verified as if krypto had made it. Hashes made by krypto
keep verifying; hashes made by other tools may now give `Format` (`FormatError`
in `krypto-py`).

### Fixed — `krypto-cli inspect` shows only printable ASCII *(2026-11-15)*

`krypto-cli inspect` removes every character that is not printable ASCII
where the report is written, and the line ends with how many were left out,
for example `[2 characters not shown]`. Before, five fields took text from the
input unfiltered: the label of PGP armor, the `v=` of an Argon2id PHC string,
the cipher and KDF of an OpenSSH private key, the key type inside an SSH key
blob, and the hash of an SSH signature. A crafted file could put control
characters and line breaks there, to drive the terminal or add lines to the
report. The other fields showed such characters as `?`; they now follow the
same rule. Reports on files without such characters are unchanged.

### Fixed — `krypto-cli inspect` reads crafted DER, PEM, OpenPGP and zip input right or says it is invalid *(2026-11-15)*

`krypto-cli inspect` no longer panics or shows a made-up value on crafted
input. An OID whose first part took more than one byte and was below 80, or
did not fit in 64 bits, made a debug build panic (exit 101) and a release
build show a made-up OID. An OID with a part that starts with the byte 0x80,
a last part that is not closed, or no content at all was shown as another
OID or as nothing; it is now `invalid OID`. A valid OID with a part that does
not fit in 64 bits, such as one under `2.25`, was shown with a wrong number;
it is now `OID too long to show`. PEM inside PEM is unwrapped at most two
levels deep, counted together with hex and base64; before, it had no limit.
Where that limit stops the unwrapping, the report ends with a note that says
so. The iteration count of an OpenPGP iterated and salted S2K is read from
its own byte, not from the last byte of the packet, which was wrong when an
encrypted session key followed. The strength of a WinZip AES zip entry is
read from the AES extra field, found record by record, instead of after the
first place the bytes `01 99` appear.

### Changed — the docs say what `SecretStore` protects *(2026-11-15)*

`docs/API.md`, `docs/Usage.md`, `docs/Python.md` and the doc comments in `src/store.rs` say
plainly that a `SecretStore` protects its contents, not the file: the file is not authenticated
as a whole, and `open` does not check the master key, so a wrong one shows as `Auth` from `get`.
No code changed.

### Fixed — `SecretStore`: a write that fails after the rename, the lock file, and what `open` accepts *(2026-11-15)*

A write that failed after the new file was in place was reported as if nothing
had been written: `put` and `delete` undid the change in memory although the
file held it, and a failed `rotate` was documented as leaving the file
unchanged although it was under the new master key. The directory is now
opened before the rename, so a directory that cannot be opened fails the write
while the old file stands. If only the sync of the directory after the rename
fails, the call still returns `Io`, with a text that says the change is
written but not confirmed to survive a crash; `put` and `delete` keep the
change, and for `rotate` the text says the file is under the new master key.

`open` uses the lock file `.<name>.lock` only if it is a regular file, and
does not follow a symbolic link there: a link or a FIFO at that name is `Io`.
Before, a link into a directory the process could not write to gave a store
without a lock. What is at the store path must be a regular file too: a FIFO,
a device or a directory is `Format`, and a FIFO no longer makes `open` wait.
An existing file gets mode 0600 only after `open` has read it as a store;
before, a file that was not a store got 0600 and was then refused. The file
format and the API are unchanged.

### Changed — krypto-py declares that it needs the GIL, and denies `unsafe` *(2026-11-15)*

The `krypto_py` module declares that it needs the GIL (`gil_used = true`),
because krypto-py is built and tested only with Python that has the GIL; it is
not tested on a free-threaded Python. `krypto-py` is compiled with
`deny(unsafe_code)`, like the library, and its two `unsafe` places each carry
their own `allow`. `docs/Python.md` and `docs/API.md` say that `rotate`
consumes the handle also when the rotation fails, and that the file can then
be opened again. A test checks that `password.derive_key` refuses a
`bytearray` or `memoryview` salt: the salt is borrowed while other threads
run, so it must stay immutable.

### Fixed — `hex` and `base64` decode errors no longer show the input *(2026-11-15)*

The `Format` error for an invalid character in `hex::decode`,
`base64::decode` and `base64::decode_nopad` no longer names the character.
It did before, so a logged error could hold one character of, for example,
a hex-encoded key. The message names neither the character nor its position,
only what is accepted: `invalid hex character — canonical hex is lowercase
[0-9a-f]` and `invalid base64 character (STANDARD alphabet, no whitespace)`.
The text of `FormatError` in krypto-py changes with it; the error kind does not.

### Changed — documentation *(2026-11-15)*

- The docs say that `close_inherited_fds` also closes the lock of an open
  `SecretStore`, and that after a `fork` without `exec` parent and child share
  it until both handles are gone, so both can overwrite each other's writes:
  call it, or fork, before opening a store. It closes every descriptor above
  stderr, not only inherited ones.
- How much locked memory krypto needs: a non-empty secret locks at least one
  page, about 16 at a 64 KiB `RLIMIT_MEMLOCK`, `Error::Hardening` at the limit,
  which is raised outside krypto; the test suite needs more than 6 MiB.
- Python: a `bytearray` given to `SecretBuf.from_vec` is zeroed, and consumed
  objects stay consumed, also when the operation itself fails; a panic surfaces
  as `pyo3_runtime.PanicException`, which `except Exception` does not catch.
- The examples seal under `master.key_id()` and define their salt; the
  krypto-py README covers a wrong password and says core dumps are excluded on
  Linux; `docs/Cli.md` says `krypto-cli` warns when hardening fails; the
  comments on Miri and on what `tests/docs.rs` checks say what they cover.

### Changed — `seal`, `open`, `hmac_sha256` and `derive` overwrite the key material they leave on the stack *(2026-11-15)*

Up to 0.8.1, a copy of the derived key stayed on the stack after `seal` and
`open` (and so `reseal`), and the HMAC midstates, enough to compute a MAC under
the same key, after `hmac_sha256`, `key_id` and, in an optimised build,
`derive`. These functions now overwrite that stack after the work. The
dependencies that have a `zeroize` feature are built with it (aes-gcm,
chacha20poly1305, hmac, sha2, argon2). AEGIS-256 and HKDF have none; HKDF's
HMAC state is wiped through sha2, and argon2 wipes only its initial and final
hash, not its working memory. No crate or version changed, and outputs are
unchanged. It is a measure, not a guarantee: what is left depends on the
compiler, the build and the platform. Signing and key exchange are not covered.

### Changed — CI checks the `cargo-deny` download against a checksum *(2026-11-15)*

Both CI workflows download a prebuilt `cargo-deny` at a fixed version. The
download is now checked against a SHA-256 kept in the workflow before it is
unpacked, so a file that has changed fails the job instead of being run. The
checksum is replaced together with the version. The crate is unchanged.

### Changed — the CI job token is read-only and kept away from the build *(2026-11-15)*

On GitHub the workflow states that the job token can only read the repository,
and the checkout no longer leaves the token in the working tree for the steps
that build and run code. On Gitea the checkout step gets the token through its
environment instead of in the script text. The jobs do the same as before, and
the crate is unchanged.

### Changed — Miri and ASan in CI build with `--locked` *(2026-11-16)*

The Miri job in both CI workflows and the AddressSanitizer job on Gitea now
pass `--locked`, like every other build and test step, so they test the
dependencies `Cargo.lock` names. The crate is unchanged.

### Changed — `.gitignore` covers local environment and key files *(2026-11-16)*

`.env*` and `*.key` are ignored, so a local file with secrets is not committed
by accident. Example, sample and template files, such as `.env.example`, stay
committable.

### ⚠ Changed — `password::derive_key` caps the salt at 1024 bytes *(2026-11-16)*

`password::derive_key` refuses a salt longer than `MAX_DERIVE_INPUT_BYTES`
(1024 bytes) with `Format` (`FormatError` in `krypto-py`). Before, the salt had
only a lower bound of 16 bytes, where every other input to krypto has a cap;
`MasterKey::derive` has had this one since 0.7.0. A key made with a longer salt
can no longer be derived; a salt of 16 to 1024 bytes gives the same key as
before.

## [0.8.1] — 2026-11-15

*No functional change. The documentation is corrected where it said more than
the code does, a test file no longer names the machine it was made on, and the
Python packages carry no paths from the machine that built them.*

### Fixed — a test file named the machine it was made on *(2026-11-02)*

`tests/fixtures/inspect/ssh2-rsa.pub` carried the comment `ssh-keygen -e`
writes, with the user and host that converted the key. It is made again with a
neutral one, `test@example.invalid`; the key and its fingerprint are the same.

### Fixed — the Python packages carry no paths from the build machine *(2026-11-15)*

The wheel of 0.8.0 named directories on the machine that built it, in its SBOM
and in the compiled module. 0.8.1 is built where those directories have neutral
names.

### Fixed — the documentation says what the code does *(2026-11-15)*

The documents are corrected where they said more than, or other than, the code
does. Among them: SECURITY.md named *ring*, which krypto does not use, and
listed 0.7.x as supported; the exit codes of `krypto-cli` and what `inspect`
shows were stated too broadly; a password hash that is cut short or altered
gives `Auth`, not `Format`; and `docs/API.md` claimed locked memory for all of
`SecretStore`. The help text of `krypto-cli` is corrected the same way.

### Fixed — two tests shared a temporary key file *(2026-11-15)*

Two tests in `tests/aead.rs` wrote the same temporary key file, so one of them
could fail when they ran at the same time. Each now has a file of its own.

## [0.8.0] — 2026-11-02

*krypto-py, the crate's API from Python with PyO3, and krypto-cli rewritten as a
tool for testing.*

### Added — `krypto-py`: the same API from Python *(2026-10-30)*

`krypto-py` (on PyPI, imported as `krypto_py`) is the crate's API in Python:
every function, type, constant and module, with the same names, built from the
same code with PyO3; a test fails the build if a name is in one and not the
other. What one seals, stores, signs or hashes, the other opens, reads and
verifies, and the tests check it both ways: each side opens and checks what the
other made, and gives the same answer where the input fixes it. Errors are
exceptions, one per `Error` variant. The secrets stay in krypto's locked memory;
what differs is only what can be guaranteed for the copies Python itself holds,
which `docs/API.md` sets out. The repository is a workspace of `krypto` and
`krypto-py`, CI builds and tests the binding, and the published `krypto` crate
does not carry it.

### Added — `MasterKey::key_id` *(2026-10-30)*

The key id of a master key, which says what key generation a blob was sealed
under, is now in the library: HMAC-SHA256 over `key-id` under the key derived
for `krypto/key-id/v1` with an empty salt, the first 16 bytes. It is the value
`krypto-cli` has always written, and `krypto-cli` now uses it; a test pins it.

### Changed — `krypto-py` needs Python 3.11 or newer *(2026-10-30)*

`krypto-py` is tested with Python 3.11 and 3.12, and asks for no less:
`requires-python` is `>=3.11` and the abi3 floor is 3.11, so the wheel is
tagged `cp311` and pip will not install it on an older Python.

### Fixed — the CI job for `krypto-py` installs clippy *(2026-10-30)*

The `python-binding` job ran `cargo clippy` in an image without the clippy
component; it now adds it first, as `build-test` does.

### Added — the README says which platform krypto stands behind *(2026-11-02)*

Linux on x86_64: what CI builds and tests, and what the `krypto-py` wheels are
built for, tested with Python 3.11 and 3.12. Anything else builds from source and
is not vouched for; the code is open for anyone to make a variant of their own.

### Changed — the independent checks run against `krypto-py` *(2026-11-02)*

The tests that check what krypto composed itself against code it did not write
(`cryptography`, `argon2-cffi` and Python's standard library), the blob format,
HKDF, the key id, the presets and the key forms, now call `krypto_py` instead of
running `krypto-cli`: the same 19 checks, in
`krypto-py/tests/test_independent.py`, with the same locked versions.
`python/test_cli_parity.py` and its CI job are gone; its two tests of
`krypto-cli` itself are covered by `tests/cli.rs` and the unit tests of
`base64`.

### Changed — the tests check that the protections take effect *(2026-11-02)*

`harden_process` and `no_new_privs` are read back from the kernel: core dumps
off, the process not dumpable, the bit set. A secret's pages are read back from
`/proc/self/smaps`: locked and kept out of core dumps, a guard page on each
side, apart from any other secret, and unmapped once dropped. The secret types
are checked to be Send and Sync when the tests compile. Every kind of error says
what went wrong and carries no key material or plaintext, and Python raises the
same text. From Python, a secret is locked and out of core dumps,
`harden_process` has the same effect, other Python threads run while Argon2
works, and several threads can share one store. The files made once by an
earlier build open in krypto's own tests, so `cargo test` alone shows that the
format holds. What CI cannot show is left out: that memory was wiped before it
was returned, that no copy is left after Argon2, and what a real core dump
holds.

### Changed — `krypto-cli` is a small helper tool *(2026-11-02)*

`krypto-cli` is now a helper for those who use krypto, not a product and not a
contract: nine commands for checking what krypto and `krypto-py` made, checking
values and timing Argon2. They are `version`, `inspect` (new: the format, the
algorithm and the key id of a blob, without a key; it replaces `blob-key-id`),
`keyid`, `seal`, `open`, `mac`, `sha256`, `verify` and `bench` (new: the time
per Argon2id preset, and per seal and open). `rand`, `reseal`, `keygen`,
`public`, `sign`, `shared`, `derive-key`, `password-hash`, `password-verify` and
the four `b64-*` commands are gone; the crate and `krypto-py` do all of it.
`krypto-cli --help` lists the commands and the exit codes, and `krypto-cli
<command> --help` explains the flags of one. Each command takes only its own
flags. A wrong call is exit 2 and is reported before stdin is read, an empty
`--context` included (it was exit 1). A closed stdout is exit 1 instead of a
panic, and `seal` reads its plaintext without leaving copies of it behind. An
unknown command or flag is told by its position and never repeated back. The
exit codes are otherwise as before.

### Fixed — the memory test under AddressSanitizer *(2026-11-02)*

Under AddressSanitizer `mlock` does nothing, so the test now requires a secret
to be locked only where `mlock` works.

### Added — `krypto-cli inspect` tells what krypto made, and how *(2026-11-02)*

Given a file or a dump, `inspect` tells which of krypto's formats it is and how
it was made, without a key and without showing a key, a plaintext or a hash
value. `docs/Inspect.md` lists what it recognizes.

### Added — `krypto-cli inspect` tells what others made, and how *(2026-11-02)*

Besides what krypto makes, `inspect` now recognizes the common formats from
other tools, such as OpenPGP, X.509 and PKCS, SSH, encrypted files and tokens,
and tells the algorithms used. `docs/Inspect.md` lists them, and which are
tested against real files.

### Changed — `krypto-cli` is documented on its own *(2026-11-02)*

`docs/API.md` is the library's alone; `krypto-cli`, a tool for testing, is
described in `docs/Cli.md`, and `docs/Usage.md` only points to it.

### Fixed — `inspect` no longer takes random bytes for OpenPGP *(2026-11-02)*

A packet without a stated length was taken as the start of an OpenPGP message,
so about two in a hundred random inputs, such as a key, were told as an
encrypted message. Such a packet now counts only after a key packet, and the
first packet must carry a version OpenPGP defines.

### Changed — fewer tests of `krypto-cli` *(2026-11-02)*

`tests/cli.rs` tests only what the tool must do: `seal` and `open` with their
exit codes, that `inspect` recognizes what krypto and the common tools make,
and that a wrong call is exit 2. The files in `tests/fixtures/inspect` are
checked for their format, not for every detail.

## [0.7.3] — 2026-10-30

### Fixed — `drop_filesystem` changes the root only as its last step

`drop_filesystem` checked the path, then looked it up again for the `chroot`, and
moved the process into the new root only afterwards. A path swapped in between
could be made the root without being checked, and if the last step failed, the
process had the new root but stood outside it. It now opens the directory once,
steps into it, checks there that it is empty, and makes it the root as the last
step. On `Err` the root has not changed and the process stands where it stood.
The signature and the result on success are the same.

### Fixed — tampering with a blob header raises `Auth`

A blob whose version or algorithm byte had been changed to a value krypto does
not know gave `Format`, which `krypto-cli` reports as exit 1, so the change
raised no alarm. Every change past the `FAFN` magic now gives `Auth`, in `open`,
`reseal` and `blob_key_id` alike, and a body cut short gives `Auth` for
AEGIS-256 too, as it already did for the other two; `krypto-cli open`, `reseal`
and `blob-key-id` exit 3 for it, not 1. Only data that is not a krypto blob at
all, too short for a header or without the magic, gives `Format` (exit 1). A
blob from a later krypto with a version or algorithm this one does not know also
gives `Auth`: upgrade readers before writers.

### Fixed — `SecretStore::get` reports a mismatched key id as `Auth`

A store holds one key generation, and `rotate` replaces it whole, so a blob and
its store disagree on the key id only if one of them was changed. `get`
answered that with `WrongKey`, the routing answer, so the change raised no
alarm; it now gives `Auth`. No library function returns `WrongKey` any more;
`krypto-cli open` still does, for a blob from another generation.

### Changed — `Hardening` and `Format` say what they cover

`Hardening` was described as "mlock, rlimit or prctl". It covers every
protection step and the environment: locked or protected memory, randomness,
process hardening, and internal steps no input can cause. An empty `info`
passed to `derive` was `Hardening` and is now `Format`, like every other input
with the wrong shape.

### Fixed — random bytes have a cap per call, and fail instead of crashing

`random_bytes` and `SecretBuf::random` took any length, and a huge one made
`random_bytes` abort the process, where every other input to krypto has a cap and
an error. Both now give at most `MAX_RANDOM_BYTES` (1 MiB, the number
`krypto-cli rand` already used) per call; more is `Format`. A program that needs
more in one call states its own cap with `random_bytes_with_limit` or
`SecretBuf::random_with_limit`. Memory that cannot be had is `Hardening`, never
a crash.

## [0.7.2] — 2026-10-28

*Moves every RustCrypto and dalek dependency to its current release line, which
fixes RUSTSEC-2026-0387. Not one public signature moved, and every output is the
same as before: the official vectors in the test suite and the Python parity suite
pin it.*

### ⚠ Security — dependencies on the current RustCrypto line (RUSTSEC-2026-0387)

`crypto-bigint` 0.5, which krypto pulled in through `p256` 0.13, has operations
meant to run in constant time that can branch on secret values
(RUSTSEC-2026-0387). The fix exists only from `crypto-bigint` 0.7.6, which needs
`p256` 0.14. krypto now requires `p256` 0.14, `aes-gcm` 0.11, `chacha20poly1305`
0.11, `hkdf` 0.13, `hmac` 0.13, `sha2` 0.11, `argon2` 0.6, `ed25519-dalek` 3,
`x25519-dalek` 3 and `getrandom` 0.4, all on the same line, so a consumer that
also uses that line carries one copy of it, not two.

None of these types appear in krypto's public API. The blob format, key
derivation, MACs, signatures, key agreement and password hashes produce exactly
what they did.

### ⚠ Changed — `rust-version` is 1.89

The current dependency line needs Rust 1.89 (`aes` 0.9). `rust-version` was 1.74;
a toolchain older than 1.89 cannot build this release.

### Changed — a wrong nonce length is a `Format` error

The current `aead` releases replace the slice conversion that panicked on a wrong
length with a fallible one. XChaCha20-Poly1305 and AES-256-GCM now return
`Error::Format` for a nonce of the wrong length, as AEGIS-256 already did. No
public function can hand them one.

### Added — CI checks the declared `rust-version` and the docs

A new job builds and tests on the `rust-version` that `Cargo.toml` declares,
reading the number from there, so the promise is checked rather than assumed. The
build job now also builds the documentation with warnings as errors. The crate's
top-level documentation linked to the private `ffi` module; it names it as text.

### Changed — the documentation stands on its own

Roadmap sections that did not hold are gone: "What does not exist yet" in
`docs/Usage.md` listed key rotation, which has existed since 0.6.0, and "Possible
future extensions" in `docs/Home.md` promised nothing. Notes about the names used
before 0.5.0 are gone from the reference, the guides and the comments. Comments,
test names and the CI file no longer refer to private systems, and two status
sentences are removed. The Python parity requirements file is now
`python/requirements-ci.txt` (it was `python/krav-ci.txt`).

### Changed — `aegis` is required at 0.9.20

The manifest asked for `aegis = "0"`, which accepts any 0.x release; under Cargo's
rules each new 0.y may break, so a consumer could resolve an untested one. It now
asks for 0.9.20, the current release, and stays within 0.9. `libc` was listed
under both `[dependencies]` and `[dev-dependencies]`; the second entry is gone,
since tests already see the first.

### Changed — `hex::encode` reads from a table

`hex::encode` built a temporary string for every byte through a format string. It
now takes both characters from a fixed sixteen-character table, the way `base64`
already does. The output is the same.

### ⚠ Fixed — `SecretBuf` was not kept out of core dumps and could lose its lock

`SecretBuf` is meant to stay locked in memory and out of core dumps. It kept its
bytes in ordinary heap memory, mixed with other data on the same pages, and
neither held there. The kernel almost always rejected the request to leave the
memory out of core dumps, and the error was ignored, so only `harden_process`,
which turns core dumps off for the whole process, kept secrets out of a dump.
And since memory is locked per page, dropping one secret also unlocked any other
secret on the same page.

Each `SecretBuf` now has memory pages of its own, with an inaccessible page on
each side, so both hold, and a secret is refused with `Error::Hardening` when
they cannot. Inside the crate, these pages are reached only through one type
that keeps their address and length together. The public API is unchanged, but
every secret alive at the same time now uses at least one page (usually 4 KiB)
of the process's locked-memory limit, plaintexts from `open` and derived keys
included.

### Changed — a secret ends where its guard page begins

The guard page after a secret was only reached once an access had run past the
rest of the secret's last page: a 32-byte key had about 4 KiB of unused space
before it. The secret now sits at the end of its pages, so the first byte past
it is on the guard page and stops the process. Before the secret lie the unused
bytes of its first page, then the other guard page.

### Fixed — the password functions wipe what argon2 leaves on the stack

argon2, and the hash it uses inside, left copies of the values they derive from
the password in the stack memory they had used: after `derive_key`, two copies
of the derived key remained once the key itself was dropped. `hash`, `verify`
and `derive_key` now overwrite that memory with zeros when argon2 returns. The
password itself was not left behind.

### Fixed — key material is wiped on every path when keys are read or derived

`MasterKey::from_secret_file` read the key into a buffer that grew as it read,
leaving the earlier, smaller buffers behind unwiped: with a 4096-byte key, 928
bytes of it remained. A failed read also dropped what had been read without a
wipe. The read now has room for the largest key from the start and wipes on
every way out. `derive_key` and `MasterKey::derive` built the derived key in
ordinary memory and copied it into locked memory; they now write it straight
into locked memory, so no unlocked copy exists and a failure leaves nothing
behind.

### Fixed — `MasterKey::derive` wipes what HKDF leaves on the stack

HKDF left copies of the derived key in the stack memory it had used: in an
optimised build, two copies remained once the key itself was dropped. `derive`
now overwrites that memory with zeros when HKDF returns. The overwrite is sized
to what HKDF uses and adds about 0.25 µs to a call that takes 13 µs.

### Added — the per-key limit of AES-256-GCM is documented, and fresh nonces are tested

With a 12-byte random nonce, one AES-256-GCM key should seal at most 2³² blobs
(NIST SP 800-38D, section 8.3); a repeated nonce lets an attacker read the XOR
of two plaintexts and forge blobs. The limit was written nowhere. It now stands
on `Alg::Aes256Gcm`, in the API reference and in the guide. krypto keeps no
count; the caller knows its volume. A new test checks that every `seal` draws
its own nonce, for all three algorithms.

### Changed — the documentation says what the code does

`docs/Usage.md` said key names were checked only on writes, so old names stayed
readable; since 0.7.0 they are checked on reads too, and a store file with a
name outside the rules does not open. It now says so, and how to move such
names before upgrading. The key id was described as HKDF output; it is an
HMAC-SHA256 under an HKDF-derived key, and the API reference and the cli comment
now say that. The API reference states the version it applies from, 0.7.0,
beside the version each part carries; the guide's version table gains 0.6.1 to
0.7.2; an empty `salt` for `derive` is documented as allowed; and the cli no
longer claims to mirror the whole Rust surface.

### Fixed — `SecretStore` no longer follows planted files, outgrows itself or stays open to others

The tmp file a write goes through had a predictable name and was opened even if
something was already there: a symlink planted at that name made the store
overwrite the file it pointed to, and a planted file left the store with that
file's permissions. The tmp file now has an unpredictable name and must be new.
Ordinary puts could grow the store past `MAX_STORE_BYTES`, after which `open`
refused it and every secret in it was out of reach; a put that would cross the
cap now fails with `Format` and changes nothing. The directory is synced after
the rename, so a crash right after a write no longer loses it. An existing store
file with wider permissions gets 0600 when opened, if the process owns it.

### ⚠ Fixed — two handles on one `SecretStore` file no longer lose writes

A store reads its whole file into memory and writes the whole file back. Two
handles on the same file, in one process or two, therefore overwrote each
other's writes without an error, and in one process they could even report a
lost write as stored and a stored one as failed. `open` now takes an exclusive
lock for as long as the handle lives; a second `open` of the same file fails
with `Error::Io` (`WouldBlock`) until the first handle is dropped, and `rotate`
passes the lock on. The lock is the kernel's, on an empty `.<name>.lock` beside
the store file, so it goes away with the handle or the process and never goes
stale. Keeping to one handle per file is still the caller's responsibility;
krypto now guards it too.

## [0.7.1] — 2026-10-07

*No functional change. Not one public signature moved. The release exists because
the crates.io page shows the README from the package, and the one in 0.7.0 told
readers to install krypto from a registry they cannot reach.*

### Fixed — the install snippets

`README.md` said `krypto = { version = "0.6", registry = "gitea" }`: a private
registry and an old version. `docs/Usage.md` still said `0.6`. Both now read
`krypto = "0.7"`. `docs/API.md` annotated `VERSION` with a bare "0.6.0", which
read as its value; it now says "new in 0.6.0", like the rest of the reference.

### Changed — CI configuration is no longer packaged

`exclude` keeps `.gitea/` and `.github/` out of the published crate, and
`publish = ["crates-io"]` refuses any other destination.

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
