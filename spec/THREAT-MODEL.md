# THREAT-MODEL — what krypto protects, against whom, and what it leaves to the caller

**Status:** draft · **Spec version:** 0.1 (2026-11-18) · **Applies from:** krypto 0.9.0

This document says what krypto is meant to withstand, so that the design can be judged and not
only the code: what is protected, who is on the other side, what krypto promises against each
and under which conditions, and what it does not promise. Each promise, condition and limit is
stated in a sentence or two; its mechanism is explained in the document named beside it.

It stands on krypto alone: it points only to the other documents of this specification and to
public sources, and everything it relies on from outside krypto is listed under Assumptions
and References.

## 1. What krypto is, for this purpose

A library that runs inside the caller's process, on Linux on x86_64, and holds secrets in
memory and at rest (SPEC-krypto). It is not a service and speaks no network protocol. It keeps
no state of its own between calls; beside a store file it leaves a lock file and, during a
write, a temporary file. krypto-py is the same library from Python; krypto-cli is a tool for
testing, outside the promises about memory.

## 2. What is protected

| Ref | Asset | Examples |
|---|---|---|
| A1 | Key material | the master key, keys derived from it, private keys for signatures and key agreement, keys derived from passwords |
| A2 | Secret values | passwords, the plaintext sealed in a blob, the values in a store |
| A3 | That stored data is what was written | blobs, store files, password hashes, signed messages |

Not protected, and not treated as secret: the names in a store; the master key's id, the key
id field of a blob and the store's key id; salts and public keys; the associated data a caller
supplies, which is held in ordinary memory; which cipher a blob uses; the size of a plaintext,
which shows in its blob; the length of a secret, which a secret printed by mistake shows; a
store's write counter; and which preset a password hash used.

## 3. Who is on the other side

| Ref | Actor | Can do |
|---|---|---|
| T1 | Reader of stored data | read blobs, store files and password hashes: a disk, a backup, a database dump |
| T2 | Writer of stored data | change, remove, replace or add blobs and files, and put back older copies |
| T3 | Sender of input | choose the data that reaches a krypto function through the caller: a blob to open, text to decode, a password, a name, a size |
| T4 | Holder of a memory image | read a copy of the process's memory after the fact: a core dump, swap, a crash report |
| T5 | Another unprivileged user or process on the machine | read and write where the file system lets it, look at other processes as far as the kernel lets it, observe timing |
| T6 | Reader of the source code | read all of krypto, which is public, and every document that describes it |

Outside the model, because nothing krypto does could hold against them:

- whoever holds the master key. A single working key gives less; section 7 says how much;
- code running inside the caller's process, and root on the machine. The hardening steps
  limit what such code can reach, as defence in depth, not as a promise;
- an observer of the hardware: power, emission, faults, a cold-boot read of memory;
- the caller itself. krypto does what it is told and does not defend against its caller.

## 4. What krypto promises

### 4.1 Against a reader of stored data (T1)

- **A sealed plaintext cannot be read without its key,** provided the master key cannot be
  guessed (SPEC-blob). With a guessable master key, every blob, the master key's id and a
  store's key check are each a check for a guess (SPEC-keys); a key derived from a password is
  as strong as the password, at one Argon2 run per guess.
- **krypto's own keys are kept apart:** each has its own context, and the master key is not
  used on data. A caller's keys are kept apart only as far as its contexts are fixed and
  distinct, which krypto does not enforce (SPEC-keys).
- **A stored password hash is Argon2id with at least 64 MiB of memory;** the cost per guess is
  what the hash buys.

What a reader learns, beyond section 2: from two copies of a store file, which entry changed
and how many writes lie between them; that blobs carrying the same master key's id belong to
one master key, also across installations; and that a store is there, from its lock file.

### 4.2 Against a writer of stored data (T2)

- **A blob opens to what was sealed, or not at all,** and associated data binds it to its
  place. Its key id field is authenticated only when it opens, so a key id field the caller
  does not know is suspect, not another key generation (SPEC-blob).
- **A value in a store cannot be moved to another name,** because each entry has a key derived
  from its name (SPEC-keys).
- **A version 2 store file is authenticated as a whole:** a removed, swapped, added or changed
  entry or header is refused at open (SPEC-secretstore). The exception is a version 2 file
  rewritten as a version 1 file, its version 2 fields removed and its version set to 1: an open
  that does not name version 2 reads it as version 1, it stays version 1 through the caller's
  own writes, and only the reported version shows it. A changed version byte alone is refused
  as malformed.
- **An older copy of a version 2 store file is detected when the caller anchors it**
  (SPEC-secretstore, section 7.1). The anchored open compares only the counter, and gives the
  store's key id back: krypto compares what only it can compare once the file has verified,
  and which store belongs where is the caller's knowledge, since krypto keeps no record of
  stores. Without the caller's comparison of the store's key id, another store's file under the
  same master key opens, and so does a copy from before a rotation to the same master key.

**The answer a change gives.** In a blob every change past the magic is `Auth`, except a blob
made larger than its size limit; there, and outside the blob, a writer can sometimes get
another answer (SPEC-answers lists where). A caller that stores krypto's data where others can
write treats an unexpected `Format`, `WrongKey` or `Io` on data it wrote itself as a warning.

What krypto does not detect:

- an older valid blob in place of a newer one, or a blob moved where nothing binds it;
- an older copy of a store file where the caller keeps no anchor, and a swapped store file
  where it does not compare the store's key id;
- in a version 1 store file: removed and added entries, older values of single entries, and
  older copies of the whole file;
- a store file changed by someone else while a handle has it open, which the handle's next
  write overwrites; and a temporary file left with the next counter by a crash before its
  rename, which a writer can later put in place past an anchor;
- destruction. A writer can always delete data, and a missing store file is created anew as
  an empty store unless the open is anchored above 0.

### 4.3 Against a sender of input (T3)

- **Everything that comes in has an upper bound,** checked before it is used; the few inputs
  without one are listed in SPEC-answers. A path to a named pipe makes reading a master key
  wait (SPEC-keys).
- **Input is validated before it is used, and no input makes the library panic.** The answer
  tells what failed and carries no secret.
- **A stored password hash cannot make a check arbitrarily expensive:** only Argon2id within a
  bounded range is accepted, refused before Argon2 runs (SPEC-keys).

What remains with the caller:

- **Memory the sender can spend.** A password check costs up to 320 MiB, and in Python threads
  multiply that. A password is already in protected memory, up to 64 MiB, when its length is
  checked. Sealing and opening need ordinary memory of about the size of the data, and when the
  system cannot give it, the process is ended rather than answered (SPEC-blob).
- **The locked-memory limit,** which large values, many secrets alive at once, or a store with
  more entries than the limit has pages for can use up; then everything that makes a secret
  fails with `Hardening`, and such a store cannot be rotated (SPEC-memory).
- **Contexts a sender cannot influence:** with krypto's own contexts and a store's public salt,
  a caller can be made to derive an entry key or a store's MAC key (SPEC-keys).
- **Blobs that open under two keys.** No binding of a blob to one key is promised; with
  AES-256-GCM and XChaCha20-Poly1305 someone who knows two keys can make one blob that opens
  under both (SPEC-blob). A caller that opens blobs from others under a password-derived key,
  and reveals whether it worked, takes that into account.

### 4.4 Against a holder of a memory image (T4)

- **Secrets are held in protected memory:** pages of their own, locked out of swap, kept out
  of core dumps on Linux, fenced by an inaccessible page on each side, and wiped before
  release (SPEC-memory).
- **Where a secret is:** derived keys, keys from passwords and random secrets go straight into
  protected memory; a decrypted plaintext, an agreed secret, a new ECDSA private key and a key
  read from a file are in ordinary memory for the length of the operation, and that buffer is
  then wiped (SPEC-memory).
- **The stack is overwritten** after the operations SPEC-memory names: a measure, not a
  guarantee, sized on the supported platform, and not done after signing or key agreement.

What is not covered: copies the caller makes; in Python, the interpreter's copies; registers
and suspend-to-disk images; a forked child, whose copies of locked pages are not locked; the
ordinary memory secrets pass through during an operation; text decoded from hex or base64; and
the password function's working memory, 64 to 320 MiB of ordinary memory that is not locked
and not kept out of dumps. It is wiped before release when a key is derived from a password,
and not when a password is hashed or checked; an image taken during a call, or of the released
memory after hashing or checking, helps recover the password or the derived key.

**The hardening steps leave things open** (SPEC-memory): a later change of user or group id
undoes the mark that turning off dumps sets, and crash handlers inside the process are not
reached; closing inherited descriptors also closes descriptors libraries hold, and refuses
while an open store holds its lock rather than close it; leaving the file system does not hold
against a process that keeps the privilege to change its root, and leaves descriptors opened
earlier usable.

### 4.5 Against another user or process on the machine (T5)

- **A store file is private and whole:** created with mode 0600 and replaced whole on every
  write, through a new temporary file with an unpredictable name; the lock file is never
  followed through a link. An existing file whose mode the process may not change keeps its
  mode, so that reading still works.
- **The lock keeps a second krypto handle out,** on a local file system. It is advisory: it
  does not hold against a writer that does not use krypto, anyone who can write in the
  directory, another name for the same file, or a network file system, and whoever can open
  the lock file can hold it and make every open fail with `Io`. It is absent on a read-only
  file system and where no lock file exists and the directory cannot be written; closing
  inherited descriptors refuses while it is held.
- **Memory.** Until turning off dumps has run, a process of the same user can read the
  caller's memory as far as the kernel allows; after it, other unprivileged processes cannot.
- **Timing and cache behaviour,** as other programs on the machine observe them, are not
  defended against beyond what the primitives give. Argon2id's later passes depend on the data
  by design, and hex and base64 take time that depends on the data. MACs, a store's key check
  and password checks are compared in constant time, with length public.

### 4.6 Against a reader of the source code (T6)

Knowing the code does not help to decrypt: no key, salt or fixed value that protects data is
in the source. krypto draws at random what it makes itself (nonces, a store's salt and the
store's key id, a password hash's salt); the salts for key derivation and for keys from
passwords come from the caller.

### 4.7 Signatures, key agreement and the encodings

With Ed25519 sound, a signature that passes the strict check was made with the private key
belonging to the public key; key agreement refuses the all-zero result a peer could force.
Beyond that krypto promises less than callers often assume (SPEC-primitives). An ECDSA
signature has a second valid form, which krypto accepts, so the bytes of a signature do not
identify it: a caller does not use them as a name or to detect a repeat.
Neither scheme separates one use of a key from another, so a signing key serves one purpose.
The relaxed Ed25519 check accepts keys for which anyone can make signatures. Key agreement
gives no authentication: the caller authenticates the peer and binds both public keys into the
derivation. Hex and base64 are for public values: their timing depends on the data, and they
work in ordinary memory.

## 5. What is the caller's

- The master key: where it comes from, who can read it, that it is unpredictable, and a copy
  of it. Without it, what was sealed under it is gone.
- Who may write the stored data, its backups, the store's directory and every directory above
  it, since writes go by path; one handle per store file, no fork with a store open, and no
  change to a store file outside krypto while a handle has it.
- When keys are rotated, where earlier key generations are kept, and, with AES-256-GCM, at most
  2³² blobs per key (SPEC-blob).
- The anchor against rollback, including the comparison of the store's key id.
- Contexts fixed in its own code, distinct, not beginning with `krypto/`, one working key for
  one use; nothing secret in the associated data.
- Alarms on `Auth` and `Rollback`, and the warnings of section 4.2: krypto reports, the caller
  decides.
- Limits on password attempts, on large operations at once, and on outside input before it is
  held as a secret; a locked-memory limit that fits.
- Passwords as krypto takes them, their UTF-8 bytes without Unicode normalisation, and no hash
  of a password beside data sealed under a key from it.
- The hardening steps, early and in order, before a store is opened, and the privilege to
  change the root given up after leaving the file system.
- On Linux, the kernel setting that wipes memory when it is released (`init_on_free=1`):
  krypto recommends it and cannot set it (SPEC-memory).
- What section 4.7 leaves open; logging; access control.

## 6. Assumptions

- The primitives are sound, and so are the open-source implementations krypto depends on.
- krypto's own builds use fixed dependency versions, checked against known advisories and
  licences. A program that takes krypto as a dependency chooses those versions, within the
  ranges krypto states, and features chosen elsewhere in its build can change how a dependency
  behaves. The implementation of AEGIS-256 is compiled from C at build time.
- The master key is unpredictable.
- The kernel's call for random bytes is available; where it is not, krypto reads the random
  device, with the consequences SPEC-primitives gives.
- The operating system's random generator is sound, and the kernel enforces memory
  protection, file permissions and process limits.
- The locked-memory limit fits the secrets the program holds at once (SPEC-memory).
- The file system is local, with atomic rename and working advisory locks.
- The machine's crash handling honours the process's settings.
- Contexts are fixed by the caller and kept apart.
- The stack overwrite was sized on the supported platform, with one compiler.
- The platform is Linux on x86_64; what is weaker elsewhere is in SPEC-memory.

## 7. Known limits

- **One key reads everything under it.** Whoever gets a master key reads all that was sealed
  under it; rotation protects what is sealed afterwards. A single working key gives less: an
  entry key gives one entry; a store's MAC key lets its holder forge that store file, counter
  included; a caller's working key gives what was sealed under its context and salt.
- **Nothing hides that data exists,** how much there is, what entries are called, or which
  changed between two copies. **Freshness is the caller's:** krypto authenticates what was
  written, not when.
- **The password function's working memory is wiped only in part** (section 4.4): after
  deriving a key, not after hashing or checking a password.
- **Random bytes can come from the wrong place.** Where the kernel's call is unavailable,
  krypto reads the random device through a descriptor it keeps; a program that closes
  inherited descriptors afterwards can leave that descriptor pointing at something else
  (SPEC-primitives).
- **AEGIS-256, the cipher the store always uses, is the youngest of the three,** an
  Informational RFC of a research group (RFC 10032), not an IETF standard; the store cannot
  leave it without a change to krypto (SPEC-krypto).
- **krypto has been reviewed by AI models, and a person has read parts of it and commented; it has
  not been audited by a security firm.**

## 8. References

Inside krypto: the other documents in `spec/`, each named where it is used.

Outside krypto:

- The algorithms and their defining documents, listed in `spec/SPEC-blob.md`,
  `spec/SPEC-keys.md` and `spec/SPEC-primitives.md`; RFC 10032 — AEGIS-256
- NIST SP 800-38D, section 8.3 — the limit on blobs per key with AES-256-GCM
- Linux manual pages: core(5), prctl(2), getrandom(2), random(4), flock(2)

## 9. Revision history

| Spec version | Date | What changed |
|---|---|---|
| 0.1 | 2026-11-18 | First draft |
