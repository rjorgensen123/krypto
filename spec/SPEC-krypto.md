# SPEC-krypto — what krypto is, how it is built, and why

**Status:** draft · **Spec version:** 0.1 (2026-11-18) · **Applies from:** krypto 0.9.0

This is the top document of krypto's specification. It says what krypto is for, the
principles it is built on, how its parts fit together, why the main choices were made, and how
its correctness is established. The other documents each specify one part; section 7 lists
them.

It stands on krypto alone: it points only to the other documents of this specification and to
public sources, listed in section 8. It describes the design in words, not in code.

## 1. What krypto is

krypto is a library, written in Rust, for handling secrets in memory and at rest. A program
uses it to hold keys and passwords safely while it runs, to encrypt what it stores, to check
passwords, to sign and verify, and to protect its own process. krypto-py is the same library
for Python, and krypto-cli is a command-line tool for testing.

It exists so that a program does not write its own cryptography: each program that solves
the same handful of problems on its own makes its own mistakes. krypto solves them once, with
published methods, as a small set of things that are hard to use wrongly. It knows nothing
about the program that uses it: not what the data means, nor where the keys are kept.

Throughout the specification, the **caller** is the program that uses krypto. The **master
key** is the root secret, which comes from outside; a **working key** is derived from it for
one purpose. A **blob** is one sealed plaintext, and the **store** keeps named secrets in one
file. "Key id" always says which of four things it is: the **master key's id**, derived from a
master key, which names a **key generation**; the **key id field** of a blob, which the sealer
fills; the **store's key id**, random and new at each rotation, which names a **store
generation**; or the key identifier parameter of a stored password hash, which krypto refuses.

## 2. The principles

Each principle is a rule the design follows everywhere, given with the reason that decides
the cases it does not name.

**No cryptography of its own.** Every algorithm is a published one, in an implementation that
others use and examine. krypto decides how they are put together: which key is used for what,
what is authenticated, what happens when something fails. That is where programs go wrong.

**Mechanism, not policy.** krypto does what it is told and reports what happened. When to
rotate a key, what to alarm on and how often a password may be tried belong to the program,
which knows its situation. krypto does fix the cryptographic numbers, such as the cost of a
password hash, because getting them right takes knowledge a program should not need.

**One way, not options.** Where an alternative exists, such as a second cipher or a relaxed
signature check, it is there because a format or a peer needs it, not as a choice. Keys and
signatures have their standards' encodings, so they can be exchanged with anything that
follows them. Bytes written as text have one spelling, because two spellings of one value
would make a comparison or a signature depend on who wrote it.

**No state.** krypto keeps no state of its own between calls and decides nothing from memory.
What it writes is what it was asked to write; beside a store file it leaves a lock file, which
it never deletes, and during a write a temporary file. What a caller holds, such as an open
store, is the caller's. So krypto has nothing to lose or keep in step, and what it does
depends only on what it is given.

**Secrets live in protected memory.** A secret is held in pages of its own that are locked,
kept out of dumps, fenced by an inaccessible page on each side, and wiped when released, and
it is reached only through a view handed out for one piece of work. Ordinary memory is copied,
swapped and dumped without anyone deciding it. Some secrets pass through ordinary memory for
the length of one operation first; SPEC-memory says which.

**Fail closed.** What cannot be done as promised is an error: no weaker fallback, no partial
result, no success that hides a missing protection. Experience made this strict: an ignored
error once let secrets reach core dumps, and a store once wrote an empty file over one it had
failed to read. The exceptions are few and deliberate: a store opens without its lock on a
read-only file system and where no lock file exists and the directory cannot be written, and
keeps the mode of a file it may not change, so that reading still works (THREAT-MODEL);
outside Linux a secret is not kept out of dumps and turning off dumps does less
(SPEC-memory).

**Everything that comes in has an upper bound.** Whoever supplies the input does not choose
how much memory or time a call takes, so the bound is checked before the input is used.
SPEC-answers gives the limits, and the few inputs that have none of their own.

**Each failure has its own answer.** A caller acts differently on tampering, a key that does
not fit, malformed input and a failed environment, so they are different answers. Where krypto
cannot tell two of them apart, it says so (SPEC-answers).

**Silent, and safe to log.** krypto never logs: only the program knows what is worth recording.
In return no answer about a failure carries a secret, and names in a store are printable ASCII,
so that every such answer and every name can be recorded as it is. What krypto gives back as a
result is another matter: a password hash is a result, and is not for a log.

**What is stored is frozen, and says what it is.** Stored data carries its own format version
and algorithm, so a change of algorithm does not strand old data. A reader needs the key, and
the associated data if one was used, since a blob does not record that. What stored data
depends on never changes; a new need gets a new version beside the old, and readers are
updated before writers.

**Nothing secret in the source.** No key, salt or other value that protects data is in the
code; such values come from outside or are drawn at random where they are used.

**Correct against the definition, not against itself.** A sealing and an opening that make the
same mistake agree perfectly. A cipher once passed every round-trip test with its key and nonce
swapped; the published test vectors showed it, and the blobs sealed that way do not open
(section 5).

## 3. How it is built

| Part | What it gives | Rests on | Specified in |
|---|---|---|---|
| The operating-system layer | protected memory, control over the process | the kernel | SPEC-memory |
| Secret types | a secret that cannot be copied or compared, prints only as a placeholder, and is wiped | the operating-system layer | SPEC-memory |
| Keys | a master key from outside, a working key for every purpose, the master key's id | secret types | SPEC-keys |
| The blob | one plaintext sealed under one working key, in a form that says what it is | keys | SPEC-blob |
| The store | named secrets in one file, each under its own key; in format version 2 the file authenticated as a whole | keys, the blob | SPEC-secretstore |
| Passwords | a hash to check a password, and a key derived from a password | secret types | SPEC-keys |
| Signatures and key agreement | keys and signatures in standard forms | secret types | SPEC-primitives |
| Hash, keyed hash, encodings, random bytes | the small tools a program otherwise takes from elsewhere | keys, for the keyed hash; secret types, for random secrets | SPEC-primitives |
| Hardening | steps that close the process off | the operating-system layer | SPEC-memory |

The answers and limits (SPEC-answers) and the three ways in (SPEC-interfaces) run through all.

**The path of a secret.** A master key comes in from outside, into protected memory, and is
never used on data. For each purpose, named by a context and a salt, a working key is derived
from it; that key seals a plaintext into a blob, and is derived again to open it. A key from a
password, and a secret agreed with a peer, are each taken as a master key the same way. The
store does this for many named values in one file; in format version 2 it adds what a single
blob cannot give, that the file as a whole is what was written, with a counter against older
copies. The store is for secrets in a file; secrets in a database are sealed as blobs.

**One layer steps outside the language's safety rules.** All of krypto's code that must step
outside Rust's checked memory rules to talk to the kernel is in one layer; the rest is built
under a rule that forbids it, so what must be examined most closely is small and in one place.
The Python binding is built under the same rule, with two marked exceptions of its own.

## 4. The main choices, and why

**AEGIS-256 first, with two ciphers beside it.** AEGIS-256 is the first choice: it is fast, has
a 256-bit key, and its nonce and tag are large enough that random nonces and forgery are no
practical concern. Its costs: it is the youngest of the three, specified in RFC 10032, an
Informational RFC of the IRTF's Crypto Forum Research Group and not an IETF standard; its
implementation is compiled from C and does not wipe its own state, so only the stack overwrite
acts on it (SPEC-memory); and it is checked against published test vectors only, not against an
independent implementation. XChaCha20-Poly1305 shares the blob format as the way out, and
AES-256-GCM is there for a peer whose library offers only that. A blob names its cipher, so all
three live side by side, and blobs leave a cipher by being sealed again under another. The
store has no way out today: it always seals with AEGIS-256, and leaving it would take a change
to krypto.

**The caller names the cipher.** The library has no default cipher, so that the choice stands
in the caller's code and in the blob. AEGIS-256 is the one to name unless a peer needs
another; that is how "one way, not options" is meant here. Re-sealing under a new key keeps
the cipher, because replacing a key is not a change of the choice made at sealing (SPEC-blob).

**Random nonces only.** A counter is state, and state that must never repeat is what fails in
practice; so AES-256-GCM's short nonce limits how many blobs one key may seal (SPEC-blob).

**A key per purpose, a key per name.** Separation between uses is done with keys, not with
care, so a mistake in one place cannot expose another. This holds as far as the caller's
contexts are fixed and distinct, which krypto does not check (SPEC-keys). The store derives a
key for every name, so a value cannot be moved to another name. Names are addresses, not
secrets.

**The header is authenticated with the data,** and so is the associated data a caller binds
to a blob, so a blob opens to what was sealed or does not open.

**Data says which key it is under.** A blob's key id field is 16 bytes that the sealer fills,
so that any identifier fits, and a reader picks its key from the field instead of trying them
all and reading every failure as tampering. The field is authenticated only when the blob
opens, so it chooses a key and never decides trust (SPEC-blob).

**Tampering and malformed input are told apart, as far as krypto can tell.** Where krypto can
tell that data is its own and was altered, the answer is `Auth`; where it cannot, `Format`.
Otherwise whoever alters data would choose the answer nobody alarms on. Where the line runs for
each format, and where a writer can still choose, is in SPEC-answers.

**Two store versions, read side by side.** Version 2 of the store file authenticates the file
as a whole and carries a counter against older copies; version 1 does neither
(SPEC-secretstore). An open that names no version reads both, so that programs and files that
existed before version 2 keep working unchanged; naming version 2 is the deliberate step that
gets what version 2 adds.

**Passwords by preset.** The cost of a password hash is set by three named presets,
Interactive, Balanced and High, not by numbers the caller supplies. A preset is a public
contract, not a frozen format: a stored hash keeps verifying while its parameters lie in the
accepted range, but a key derived from a password depends on the preset's numbers, so a preset
is changed only as a breaking change (SPEC-keys).

**Hardening in separate steps,** because each has consequences only the program can judge: two
cannot be undone, and one closes things the program may have been handed on purpose.

**Three ways in.** The library is the whole, the Python binding has its whole surface, and the
command-line tool does a part, for a person testing by hand (SPEC-interfaces).

## 5. How correctness is established

Algorithms that have published test vectors are checked against them, at the step where the
nonce can be fixed: the three ciphers, SHA-256, base64, Ed25519, ECDSA over P-256 and X25519.
HKDF, HMAC-SHA256 and Argon2id are checked against independent implementations only, and so is
what krypto composes itself: the master key's id, keys from passwords under the two lighter
presets, password hashes (krypto's hashes under all three presets verify in the other
implementation, and one parameter set is checked the other way), the key forms, and the blob
format, for AES-256-GCM only, the one cipher both sides implement. The library and the binding
open each other's output. Blobs and store files made with the formats as they are now are kept
as fixed test files and must keep opening, and so must a store file built byte for byte from
SPEC-secretstore; the two breaks SPEC-blob names stand. The protections of memory and the
hardening steps are read back from the kernel. SPEC-primitives gives the check of each
algorithm in a table.

What the checks cannot show: that memory was wiped before it was given back, that nothing of a
password is left after Argon2, and what a real core dump holds. The layer that steps outside
the language's safety rules is examined by reading and by those kernel checks; the tool that
checks Rust code for undefined behaviour cannot run it, because that layer calls the kernel.

## 6. Where krypto ends

krypto does not handle login, sessions or permissions, decide where a master key comes from,
log, alarm, or count attempts. It is not a service, defines no format for a message sealed to
a public key, and the library reads no certificates. What it withstands is in THREAT-MODEL.

### 6.1 What krypto needs

- **Linux on x86_64,** where it is built and tested and makes its promises. Elsewhere the
  exceptions under "Fail closed" apply.
- **A Linux kernel with the calls krypto uses:** random bytes from Linux 3.17, closing
  inherited descriptors from Linux 5.9. Where the first is unavailable or blocked, krypto reads
  the random device (SPEC-primitives).
- **Room to lock memory.** Each secret takes at least one page while it lives; the limit is
  set outside krypto, and SPEC-memory gives the numbers.
- **For the Python binding,** Python 3.11 or later, with the global interpreter lock.

Nothing else is needed at run time: krypto contacts nothing and reads no configuration.

## 7. The documents

THREAT-MODEL; SPEC-memory, SPEC-keys, SPEC-blob, SPEC-secretstore and SPEC-primitives, the
parts in section 3; SPEC-answers; SPEC-interfaces; and README, with the shared conventions.

## 8. References

Inside krypto: `spec/README.md`, and the documents named in section 7.

Outside krypto:

- RFC 10032 — AEGIS-256, whose test vectors are used
- draft-irtf-cfrg-xchacha (earlier draft-arciszewski-xchacha), with RFC 8439 for the
  underlying construction — XChaCha20-Poly1305
- NIST SP 800-38D — AES-256-GCM
- RFC 9106 — Argon2
- Linux manual pages: getrandom(2), random(4), close_range(2)

## 9. Revision history

| Spec version | Date | What changed |
|---|---|---|
| 0.1 | 2026-11-18 | First draft |
