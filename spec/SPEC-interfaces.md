# SPEC-interfaces — the library, the Python binding and the command-line tool

**Spec version:** 0.1 (2026-11-18) · **Applies from:** krypto 0.9.0

This document specifies the three ways into krypto: what they share, how far each reaches,
where they differ, and why there are three.

It stands on krypto alone: it points only to other documents of this specification and to
public sources, which are listed under References.

## 1. Three ways in, one krypto

| Way in | For | Reach |
|---|---|---|
| The library | programs written in Rust | the whole of krypto |
| The Python binding, krypto-py | programs written in Python | the library's surface, and a version attribute |
| The command-line tool, krypto-cli | a person at a shell, testing | a part |

There is one implementation. The binding and the tool are built from the library, so there is
no second set of algorithms to keep in step. All three share the formats, the algorithms, the
classes of answer and the limits, and what the library or the binding writes, the other reads.

The reason for the binding is the reason for krypto itself. A program in another language
that could not reach krypto would write its own cryptography, and that is what krypto exists
to prevent.

## 2. The library

The library is the whole of krypto; the binding and the tool are views of it. Three rules
shape its surface:

- **A secret goes in and out only as a secret.** What must be secret, such as a plaintext to
  seal, a password or a private key, is taken as a secret type and given back as one
  (SPEC-memory); neither a master key nor a working key hands its bytes out (SPEC-keys).
- **An operation that takes over a value uses it up.** Making a master key from a secret,
  rotating a store and upgrading it take the value or the handle over, also when they fail,
  so that no stale copy stays usable.
- **Everything that can fail answers with a class** (SPEC-answers), never with a partial
  result.

The classes of answer and the ciphers are open sets: krypto can add one without breaking a
caller, and a caller is written to meet a class or a cipher it does not know.

## 3. The Python binding

**What it is.** The library's surface, reached from Python and built from the same code, with
a version attribute added. A secret, a key, and a plaintext given out by opening or reading are
krypto objects that hold protected memory, in Python as in the library, and are wiped and
released when Python frees the object.

**What it needs.** Python 3.11 or later, with the global interpreter lock, on Linux. It is not
made for a Python without the lock.

**Where it differs in kind** is at the edge between the interpreter and krypto:

- What the interpreter's own objects carry in or out, such as bytes and text, lies in ordinary
  memory that krypto neither locks nor wipes; the one exception is a mutable byte array a
  secret is made from, which is overwritten as in the library. Taking the contents out of a
  secret gives a copy in ordinary memory; until then the secret stays protected.
- A value that an operation takes over is used up, as in the library; using it afterwards is
  an error of the interpreter, not one of krypto's classes.
- Each class of answer is an exception of its own, under one common parent.

Hashing and checking a password, and deriving a key from one, let other Python threads run
meanwhile, so threads that run them at once each take the preset's memory.

## 4. The command-line tool

krypto-cli lets a person see what a piece of data is, check that a blob opens, compute a value
by hand, and measure how long the presets, sealing and opening take. It does a part of what the
library does: no command for store files beyond describing them, none for password hashes, and
no associated data. It is a tool for testing, not a contract: no program should be built on it.
It stands outside the promises about memory: it takes only turning off dumps, goes on if that
fails, and passes what it reads and writes through ordinary memory. It reads its master key
from a file, never from the command line, where the key would show in the list of processes.
Its exit status tells the main kinds of failure apart: a wrong call, an authentication failure,
another key, and everything else.

One design point is its own. Before it opens a blob, the tool compares the key id field with
its master key's id, and answers a difference as another key. The field is not authenticated
until the blob is opened, so a changed field gives "another key", not "tampering"; so does a
blob sealed with any other value in the field, such as a store's key id.

## 5. What holds for all three

- The formats: SPEC-blob, SPEC-secretstore, and the forms of keys, hashes and signatures in
  SPEC-keys and SPEC-primitives.
- The classes of answer and the limits: SPEC-answers.
- The platform: Linux on x86_64.

## 6. References

Inside krypto:

- `spec/SPEC-memory.md` — protected memory, and hardening
- `spec/SPEC-keys.md` — the master key, contexts, salts and presets
- `spec/SPEC-blob.md` — the blob and its key id field
- `spec/SPEC-secretstore.md` — the store file
- `spec/SPEC-primitives.md` — signatures and encodings
- `spec/SPEC-answers.md` — the classes of answer and the limits

Outside krypto: none.

## 7. Revision history

| Spec version | Date | What changed |
|---|---|---|
| 0.1 | 2026-11-18 | First version |
