# SPEC-answers — the answers krypto gives, and the limits on what it takes

**Status:** draft · **Spec version:** 0.1 (2026-11-18) · **Applies from:** krypto 0.9.0

This document specifies how krypto answers: the rules every answer follows, the classes of
failure and what each means, where the line between them runs for each format, and the limits
on everything a caller hands in.

It stands on krypto alone: it points only to the other documents of this specification, which
say where each answer arises.

## 1. Why the answers are a design of their own

A program that uses krypto has to decide what to do when something fails: alarm, ask for
another key, tell a user the password was wrong, give up. It can decide well only if the
answer tells it what happened. An answer that lumps tampering together with a typing error
forces the program to treat both as the worse case or both as the milder one, and both
choices are wrong. The answers are therefore part of what krypto promises, as much as the
formats are.

## 2. The rules

- **Everything that can fail says so.** Each operation gives its result or one of the classes
  below, never a partial result. The few places where krypto goes on without a protection it
  would otherwise give are named in SPEC-krypto under "Fail closed".
- **No input makes krypto panic.** Malformed, truncated, oversized or hostile input gets an
  answer, and arithmetic on lengths from input is checked. Memory is another matter: memory
  the system refuses is `Hardening` where krypto reserves it, but the ordinary memory that
  sealing and opening need ends the process when the system cannot give it (SPEC-blob).
- **A different failure, a different answer.** Two failures share a class only when a caller
  would do the same about both, or when krypto cannot tell them apart.
- **No answer carries a secret.** No message holds key material, a plaintext, a password, a
  salt, or the hash value of a stored password hash, and a decoder never names the character
  it refused or its position, because the text may be a key. A message may name a detail that
  is not secret: a size and its limit, an unsupported version number, the illegal character of
  a store name, shown in quotes with control characters escaped, a parameter of a password hash
  krypto does not accept, or the name of that hash's algorithm, which holds at most 32
  characters: the letters a to z in lower case, digits and hyphens.
- **Answers are in English,** in the library, the binding and the tool alike.
- **krypto never logs.** The answer is the only thing it gives back, and every answer is made
  to be recorded as it is. Recording is the caller's job.

## 3. The classes

There are seven classes. The set can grow, so a caller handles a class it does not know as a
failure.

| Class | Meaning | What it calls for |
|---|---|---|
| `Auth` | What was given does not verify: a blob or store file that was changed, an entry whose key id field is not the store's key id, a signature that does not hold, a password that does not match, a key agreement whose result is all zeros. A key that does not fit a blob gives this answer too | For data and signatures, an alarm: this is the answer tampering gives. For a password, a wrong password |
| `WrongKey` | The key does not fit, and nothing is said against the data. The library gives it only when a version 2 store file is opened with a master key its key check does not fit; a changed salt or key check looks the same | Another key. If the key is known to be right, the file was changed |
| `Rollback` | An anchored open found a version 2 store file that verifies but is older than the anchor. The answer carries both counters. It is not `Auth`, because the file itself is genuine | An alarm: an older copy was put back |
| `Format` | The input is not what the operation takes: not krypto's data, a store version krypto does not know or other than the one named, malformed, of another kind, or over a limit | Look at the input. On data the caller stored itself where others can write, an unexpected `Format`, like an unexpected `WrongKey` or `Io`, is a warning too (section 4) |
| `KeyNotFound` | No entry under this name in the store; "key" means the entry's name | Nothing; an ordinary outcome |
| `Hardening` | A protection or the environment failed: memory that cannot be had or locked, random bytes, a hardening step, or an internal step no input can cause. One case comes from a file: a version 2 store whose counter is at its maximum refuses to be written | Look at the machine and its limits; for the counter, rotate the store. Never a statement about whether data is genuine |
| `Io` | A file or directory could not be opened, read, written or synced; the store is already open through another handle; its lock file is not a regular file; an anchored open found no file. One case comes when the work is done: a store write has replaced its file and only the sync of the directory afterwards failed, so the change is in the file | Look at the file system |

The classes are uneven in one place. When the working memory of Argon2 cannot be had, hashing
a password and deriving a key from one answer `Hardening`, while checking a password answers
`Format`; when Argon2 fails in another way, hashing answers `Hardening`, and checking and
deriving answer `Format`.

## 4. The lines between the classes

**The principle.** Where krypto can tell that data is its own and has been altered, the answer
is `Auth`; where it cannot tell, the answer is `Format`. Otherwise whoever changes the data
would choose which answer the caller sees, and choose the one nobody alarms on: when changes
to a blob's header once gave `Format`, they raised no alarm. How far krypto can tell differs by
format:

- **A blob** (SPEC-blob). Not a blob at all, or larger than a blob can be, is `Format`.
  Everything after the magic is `Auth`: a blob cut short, an unknown version or algorithm, any
  changed byte, and a key that does not fit, which cannot be told from a change.
- **A store file** (SPEC-secretstore). An unknown version byte is `Format`: krypto does not
  know how a version it has never seen authenticates itself. A version 1 file has nothing that
  covers the file as a whole, so a cut or malformed version 1 file is `Format`. In a version 2
  file the key check and the MAC come first, giving `WrongKey` and `Auth`; a structure that is
  invalid under a MAC that holds was written that way, and is `Format`.
- **A stored password hash** (SPEC-keys). `Format` when it cannot be read, is of another kind,
  or lies outside the accepted range, so that a hash krypto cannot check is not reported as a
  wrong password. `Auth` when it can be read and does not match: the string carries no check
  of its own, so an altered hash that still reads looks like a wrong password. A hash that was
  cut or altered can therefore land on either side, depending on whether what is left reads.

**Where a writer can choose.** These are the places where a writer of stored data can turn
what would be `Auth` into another answer:

| Change | Answer |
|---|---|
| a blob made larger than its size limit, with a changed magic, or cut to less than its magic | `Format` |
| a store file with a changed magic, cut to less than its magic and version, of an unknown version or another version than the open names, over its size limit, or replaced by a directory, a named pipe or a device | `Format` |
| a broken version 1 store file, an entry that is no longer a blob included | `Format` |
| a password hash changed until it no longer reads | `Format` |
| a changed salt or key check of a version 2 store file | `WrongKey` |
| a store file that can no longer be opened: removed under an anchored open, made unreadable, or replaced by a socket; something other than a regular file at the lock file's name | `Io` |

A caller that stores krypto's data where others can write treats an unexpected `Format`,
`WrongKey` or `Io` on data it wrote itself as a warning too.

**The environment against the data.** `Hardening` and `Io` say that krypto could not do its
work, apart from the `Io` after a store write in section 3. Neither says whether data is
genuine.

## 5. The limits

Everything a caller hands in has an upper bound, checked before the input is used, so whoever
supplies it does not choose what a call costs. Inputs that are secrets, such as a password,
are already in protected memory, up to 64 MiB, when their own limit is checked.

| What | Limit | Why this size |
|---|---|---|
| A master key | 32 to 4096 bytes | A key is 32 to 64 bytes; the ceiling leaves room and keeps an oversized file, or an endless device, from taking memory without bound |
| A context, and a salt, for key derivation | at most 1024 bytes each; a context is never empty | They come from command lines and configuration, and an unbounded one is work an attacker sizes. krypto's longest context is 16 + 512 bytes. An empty context would give two purposes one key |
| A salt for a key from a password | 16 to 1024 bytes | |
| Associated data for a blob | at most 1024 bytes | The same as for a context; to bind something larger, bind its hash |
| An amount of data: a plaintext, a message, data for a keyed hash, bytes to encode or decoded, the contents of a secret | at most 64 MiB | Large enough for any secret, message or record krypto is meant for, small enough that one call cannot take the machine's memory; larger data is hashed and the hash is used |
| A blob | at most 64 MiB plus 86 bytes | The largest plaintext with its header and the longest tag, so every blob krypto seals opens |
| A store file | at most 16 MiB, header included, read and written | A store holds small secrets; the limit keeps a bloated file from taking memory, and a write past it would make the file unreadable |
| A name in a store | 1 to 512 bytes of printable ASCII | Names are listed back out and may end in a log, where a control character could shift lines; an empty name cannot be looked up |
| Random bytes in one call | at most 1 MiB, or the limit the caller states for that call | A large request could otherwise end the process for want of memory |
| A password; a stored password hash | at most 1024; at most 512 bytes | |
| An ECDSA P-256 public key, signature, private key | at most 65, 72 and 512 bytes | The uncompressed point and the largest DER signature |
| An Ed25519 seed, public key, signature; an X25519 key; a key id field | exactly 32, 32, 64; 32; 16 bytes | The sizes the standards and the blob layout give |

Over a limit is `Format`. Two lookups in a store answer with their result instead: listing
names with a prefix that no name can start with gives an empty list, while the empty prefix
lists every name; asking whether an invalid name is present gives "no".

**The inputs without a limit** of their own are these: the plain hash and the constant-time
comparison, which cannot fail and reserve no memory; paths, which the operating system bounds;
random bytes where the caller states its own limit; and the total a store holds, which the
file limit bounds.

**Validation.** Beyond size, input is checked for type, range and character set before it is
used, whatever its source, a file krypto wrote itself included. A format version or algorithm
krypto does not know is refused, not ignored.

## 6. References

Inside krypto:

- `spec/SPEC-krypto.md` — the principles behind the rules, and their exceptions
- `spec/SPEC-blob.md`, `spec/SPEC-secretstore.md`, `spec/SPEC-keys.md`,
  `spec/SPEC-primitives.md`, `spec/SPEC-memory.md` — where each answer arises
- `spec/SPEC-interfaces.md` — how the answers appear in Python and on the command line
- `spec/THREAT-MODEL.md` — what the answers mean against an attacker

Outside krypto: none.

## 7. Revision history

| Spec version | Date | What changed |
|---|---|---|
| 0.1 | 2026-11-18 | First draft |
