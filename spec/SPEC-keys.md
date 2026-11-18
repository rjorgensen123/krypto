# SPEC-keys — keys, key derivation, the master key's id, and passwords

**Status:** draft · **Spec version:** 0.1 (2026-11-18) · **Applies from:** krypto 0.9.0

This document specifies the keys krypto works with: what a master key must be, how working
keys are derived from it, how a key generation is named, how a key is replaced, and how
passwords become hashes and keys.

It stands on krypto alone: it points only to other documents of this specification and to
public sources, which are listed under References.

## 1. Scope and definitions

- The **master key** is the root secret. It comes from outside krypto: krypto does not decide
  where it comes from or where it is kept.
- A **working key** is a 256-bit key derived from the master key for one purpose. Sealing,
  opening and the keyed hash take a working key; the master key is never used on data.
- A **context** names a working key's purpose. A **salt**, not secret, separates one use of a
  context from another.
- A **key generation** is one master key. A **store generation** is one salt and one value of
  the store's key id, both new at every rotation of a store, also a rotation to the same
  master key (SPEC-secretstore).
- "Key id" names four different things, kept apart here: **the master key's id**, derived from
  a master key (section 5); **the key id field** of a blob, which the sealer fills
  (SPEC-blob); **the store's key id**, random and not derived from any key
  (SPEC-secretstore); and **the key identifier parameter of a stored password hash**,
  unrelated to the others (section 8).
- krypto keeps no keys of its own between calls. A key lives in an object the caller holds; an
  open store refers to the caller's master key while it lives. Keys for signatures and key
  agreement are not derived from the master key (SPEC-primitives).

## 2. The master key

A master key is any 32 to 4096 bytes, and it must be unpredictable. krypto cannot tell a
random key from a passphrase in a file. With a key that can be guessed, everything under it is
a check for a guess: a blob, at the cost of a key derivation and an opening; the master key's
id or a store's key check, at the cost of a key derivation and a keyed hash. A key from a
password therefore goes through the password function first (section 8).

32 bytes is the size of the working keys made from it. A master key is 32 to 64 bytes in
practice; the ceiling of 4096 leaves room above that and keeps a file that is far too large,
or a device that never ends, from costing memory.

It comes in two ways: read from a file, or made from a byte secret already in memory, such as
a key derived from a password. Both apply the same limits, because two ways into one kind of
key must not mean two rules about what it accepts. A file's bytes are the key as they are, a
line break at the end included. A path that names something that blocks when opened, such as
a named pipe, makes the read wait.

Neither a master key nor a working key gives its bytes back: each is used inside krypto and
leaves it only as what it computes.

## 3. Deriving a working key

A working key is the output of HKDF with SHA-256:

| Input to HKDF | What is given |
|---|---|
| input key material | the master key |
| salt | the salt, which may be empty, as RFC 5869 permits |
| info | the context |
| output length | 32 bytes |

- **The context is never empty.** It is the whole separation between purposes: two purposes
  with the same context and salt get the same key without any sign of it, a failure that
  cannot be seen afterwards. An empty context is refused with `Format`.
- **Context and salt are at most 1024 bytes each.** They reach programs from command lines and
  configuration files, and an unbounded one is work whose size someone else chooses. The
  longest context krypto uses itself is 528 bytes.
- Different contexts give unrelated keys, and so do different salts. A working key says
  nothing about the master key or about another working key: its holder can use it for its
  own context and salt and nothing else.

krypto does not stop one working key from being used both to seal and to compute a keyed
hash; keeping uses apart is done with contexts, and is the caller's.

## 4. Contexts

Contexts that begin with `krypto/` are krypto's own. Each is its ASCII bytes, with nothing
added:

- `krypto/key-id/v1`, with an empty salt — the key behind the master key's id;
- `krypto/store/v1|` followed by the entry's name, with the store's salt — the key of one entry
  in a store;
- `krypto/store/v2|key-check`, with the store's salt — the key check of a version 2 store file;
- `krypto/store/v2|container-mac`, with the store's salt — the MAC over a version 2 store file.

These strings are frozen: stored data depends on them.

A caller fixes its own contexts in its code, keeps them apart, and does not begin them with
`krypto/`. krypto does not enforce this; it does not look into a context. A store's salt is
public, so a caller that used one of these contexts with that salt, under the store's master
key, would get krypto's own key: with an entry's context, the key that opens the entry; with
the MAC context, a key that lets its holder forge the store file, counter included. A caller
that lets a sender influence a context or a salt can be made to do this for the sender.

## 5. The master key's id

A working key is derived for the context `krypto/key-id/v1` with an empty salt. HMAC-SHA256 is
computed with that key over the six ASCII bytes `key-id`. The master key's id is the first 16
bytes of the result.

- It goes through a key of its own, so it is kept apart from every working key. With an empty
  salt it depends on the master key alone, and is the same wherever that key is used. It is 16
  bytes, the size of the key id field of a blob.
- It names a key generation. It is not secret, and cannot be turned back into a key. It shows
  that two blobs belong to the same master key, also across installations that share it.
- It is frozen: stored blobs carry it.

What goes in the key id field of a blob is the sealer's choice. A caller normally writes the
master key's id; the store writes the store's key id (SPEC-blob, SPEC-secretstore).

## 6. Replacing a key

A blob is moved to a new key by re-sealing it (SPEC-blob), and a store by rotating it
(SPEC-secretstore); both verify everything under the old key first, and change nothing if that
fails. Replacing a key is an action, not a state krypto holds: the caller gives both keys, and
owns when, why, and how long the old master key is kept for the data still under it.

## 7. Keys from a password and from key agreement

A key derived from a password, and a secret agreed with X25519, are 32 bytes and are not
working keys. Each becomes usable for sealing by being taken as a master key, from which
working keys are derived with a context and a salt. Nothing in a blob records the preset, the
context or the salts; the caller keeps them. An agreed secret authenticates no one
(SPEC-primitives).

## 8. Passwords

A password is text. Its UTF-8 bytes go to Argon2 as they are, without Unicode normalisation,
so two spellings of the same visible text are two passwords. It is at most 1024 bytes. The
password is held in protected memory, which takes up to 64 MiB, before krypto checks its
length, so the caller bounds what it accepts from outside first.

**Presets.** Passwords go through Argon2id, version 19 (0x13). What krypto makes itself, a
hash or a key, uses no secret key and no associated data. The caller picks a preset by name and stores the name, never the numbers:
numbers kept in two places sooner or later disagree.

| Preset | Memory (m, KiB) | Passes (t) | Lanes (p) | For |
|---|---|---|---|---|
| Interactive | 64 MiB (65 536) | 3 | 2 | a login, where many calls run at once |
| Balanced | 128 MiB (131 072) | 3 | 3 | a secret worth more than a login, not worth 256 MiB per concurrent call |
| High | 256 MiB (262 144) | 4 | 4 | a high-value secret that can be attacked offline |

Memory is per call, so a preset's memory times the calls that run at once is what the machine
must have. The floor is 64 MiB, 2 passes and 1 lane.

**A preset is a public contract, not a frozen format.** A stored hash carries its own
parameters and keeps verifying as long as they lie inside the accepted range, whose ceiling
moves if the highest preset moves; rehashing at the next login is the caller's part. A key
derived from a password depends on the preset's numbers, so changing a preset changes every
key derived under its name. A preset's numbers are therefore not changed lightly: a change is
a breaking change of krypto and is announced as one, and data sealed under keys derived with
the old numbers must be opened with them before the change.

**A hash, to check a password later,** is a PHC string. It begins with `$`, and its fields are
separated by `$`:

| Field | Content |
|---|---|
| algorithm | `argon2id` |
| version | `v=19` |
| parameters | `m=` memory in KiB, `t=` passes, `p=` lanes, as decimal numbers separated by commas; krypto writes them in that order |
| salt | 16 random bytes, in base64 with the standard alphabet and no padding |
| hash | the 32-byte output of Argon2id, in the same base64 |

Checking accepts Argon2id, version 19 with the version field present, and the cost parameters
in any order, each from the floor to a ceiling of the High preset plus a quarter
more memory, one more pass and one more lane: 320 MiB, 5 passes, 5 lanes. It accepts salts of
8 to 48 bytes and hashes of 10 to 64 bytes. It accepts an associated-data parameter, `data`,
and then gives it to Argon2; krypto never writes one. It refuses a key identifier parameter,
which names a secret key krypto does not have. A string that leaves out the passes or the
lanes is read with Argon2's own defaults, 2 passes and 1 lane, which lie in the range. The
string is at most 512 bytes. What lies outside all this is `Format`, refused before Argon2 runs, so a stored string cannot make a check cost much more
than krypto's own hashes do, and a foreign hash is not reported as a wrong password. The
result is compared with the stored hash in constant time.

A wrong password is `Auth`. A hash that was cut or altered is `Auth` or `Format`, depending on
whether what is left still reads (SPEC-answers).

**A key, to seal with,** is 32 bytes from Argon2id over the password and a salt of 16 to 1024
bytes, with the preset's numbers, written straight into protected memory. The salt is not
secret and is kept beside the data; it makes tables computed in advance useless even though it
is stored in the open. A caller does not store a hash of the password beside data sealed under
a key from it: a wrong password already fails when the data is opened, and a hash would give
whoever holds the disk a separate thing to test guesses against. Every such blob is still a
check for a guess, at the cost of one Argon2id run.

krypto adds no secret of its own to a password. A second layer keyed with a server's secret
belongs to the program that owns its login.

## 9. References

Inside krypto:

- `spec/SPEC-blob.md` — what a working key seals, and the key id field
- `spec/SPEC-secretstore.md` — the store's derived keys, and the store's key id
- `spec/SPEC-primitives.md` — signatures, key agreement, the keyed hash
- `spec/SPEC-memory.md` — where keys and passwords are held
- `spec/SPEC-answers.md` — the classes of answer, and the limits
- `spec/THREAT-MODEL.md` — what the keys are meant to withstand

Outside krypto:

- RFC 5869 — HKDF
- RFC 2104 — HMAC
- FIPS 180-4 — SHA-256
- RFC 9106 — Argon2id
- RFC 4648 — base64
- The PHC string format, as the Password Hashing Competition published it

## 10. Revision history

| Spec version | Date | What changed |
|---|---|---|
| 0.1 | 2026-11-18 | First draft |
