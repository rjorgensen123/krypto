# SPEC-memory — secrets in memory, and hardening of the process

**Status:** draft · **Spec version:** 0.1 (2026-11-18) · **Applies from:** krypto 0.9.0

This document specifies how krypto holds a secret while a program runs, what that costs,
where a secret is at each moment, what the protection does not reach, and the steps krypto
offers for closing the process off from the rest of the machine.

It stands on krypto alone: it points only to other documents of this specification and to
public sources, which are listed under References.

## 1. Scope and definitions

- A **secret** is a value whose disclosure matters: a key, a password, a plaintext.
- **Protected memory** is memory with the four properties in section 3. **Ordinary memory**
  is all other memory of the process: it can be swapped, dumped and left behind.
- The **locked-memory limit** is the amount of memory the operating system lets one process
  lock. It is set outside krypto.
- **Hardening** is the four steps in section 8: turning off dumps, forbidding new privileges,
  closing inherited descriptors, and leaving the file system. They act on the whole process.

## 2. A secret as a value

A secret is held as one of two types: a buffer of bytes, or a text that is known to be valid
UTF-8. A master key and a working key are types of their own that hold a byte secret inside;
neither gives its bytes back (SPEC-keys). What must come in as a secret is a plaintext to
seal, a password, a private key, and the bytes of a master key that is not read from a file.
Blobs, associated data, salts, names, public keys and signatures are ordinary bytes.

The types are built so that the ordinary ways a value leaks are not available:

- **It cannot be copied.** There is one instance, and it is moved, not duplicated.
- **It cannot be compared or serialized.** Nothing turns it into another form by accident.
- **It prints as a placeholder:** a fixed word and the length, never the contents. The length
  is the one thing the printed form gives away.
- **Its contents are reached through a view that ends.** The work sees the bytes where they
  lie, and the reference cannot be kept afterwards.
- **What it was made from is wiped,** also when making it fails. A failure, such as a used-up
  locked-memory limit, is exactly the moment a secret would otherwise be left behind.

An ability that does not exist cannot be used by mistake. A secret can be handed between
threads and read from several at once; it never changes after it is made.

## 3. Protected memory

Each secret that is not empty has whole memory pages of its own, shared with nothing else.

- **Locked,** so the pages are never written to swap.
- **Kept out of dumps:** on Linux the pages are marked so that a core dump leaves them out.
- **Fenced:** an inaccessible guard page lies on each side.
- **Wiped:** the pages are overwritten before they are given back.

A secret sits at the end of its pages. Reading or writing past its end reaches the guard page
at once and stops the process; going before its start stops the process only when it leaves
the first page.

Locking and keeping out of dumps act on whole pages. When secrets shared pages with other
memory, the kernel refused to keep that memory out of dumps, and releasing one secret
unlocked its neighbours. So no page is shared.

If the pages cannot be obtained, fenced, locked or kept out of dumps, the secret is not made
and the answer is `Hardening`. A secret is never placed in ordinary memory instead.

## 4. What it costs

Each secret counts against the locked-memory limit with its length rounded up to whole pages,
at least one page (usually 4 KiB); the guard pages do not count, and an empty secret takes
none. Everything that holds a secret counts while it lives: the master key, each working key,
passwords, and every plaintext given out by opening a blob or reading from a store. A limit
of 64 KiB, a common default, holds about 16 secrets; 8 MiB holds about 2000.

Rotating a store (SPEC-secretstore) holds every value of the store in protected memory at
once, so the limit bounds how many entries a store can rotate; upgrading a store takes the
values one at a time. When the limit is used up, every call that makes a secret fails with
`Hardening`; nothing is weakened. Large values, many secrets alive at once and large stores
can use it up, so how much the caller accepts from outside is the caller's to bound.

## 5. Where a secret is

Working keys, keys derived from passwords and random secrets are written straight into
protected memory. An opened plaintext, an agreed secret, a newly generated ECDSA private key
and a master key read from a file exist first in ordinary memory for the length of the
operation, are copied into protected memory, and the ordinary buffer is wiped.

While a secret is used, the implementation of the primitive keeps working copies of it: on
the stack, in its own objects, and, for the password function, in a large block of ordinary
memory (section 6). When a plaintext is sealed with XChaCha20-Poly1305 or AES-256-GCM, it is
copied into an ordinary buffer and encrypted there, so that the buffer holds ciphertext when
sealing ends.

## 6. What a computation leaves behind

**Wiping in the implementations** is turned on where an implementation offers it: the two
ciphers other than AEGIS-256, the keyed hash and SHA-256 wipe the keys and state their objects
hold. AEGIS-256 offers none, and the password function wipes only its first and last hash.

**The stack is overwritten** after sealing, opening, deriving a key, computing a keyed hash,
and hashing or checking a password or deriving a key from one. This is a measure, not a
guarantee: the amount overwritten was measured on Linux on x86_64, and another compiler, build
or processor may leave copies beyond it. Signing and key agreement are not followed by an
overwrite.

**The working memory of the password function** is 64 to 320 MiB of ordinary memory per call:
not locked, not kept out of dumps, and not wiped when released. While a call runs, and for as
long as the released memory is not reused, an image of it helps recover the password or the
key derived from it. This is a known limit (THREAT-MODEL).

## 7. What the protection does not reach

- **Copies the caller makes** once it takes the bytes out of the view, and, from Python, the
  interpreter's objects passed in and taken out, which are ordinary memory (SPEC-interfaces).
- **A forked child,** whose copies of locked pages are not locked.
- **Suspend to disk, processor registers and the hardware.** Locking keeps memory out of
  swap, not out of an image of the whole machine.
- **Other processes before turning off dumps:** until that step, another process of the same
  user can read the process's memory as far as the kernel's settings allow.
- **The ordinary memory** of sections 5 and 6; text encodings, which are for public values
  (SPEC-primitives); and names, blobs and associated data, which are not secret.
- **The command-line tool,** which stands outside these promises (SPEC-interfaces).

## 8. Hardening the process

Four steps, each its own call, because each has consequences only the program can weigh. They
limit what code that has got into the process can reach, and what a crash or another process
can take from it. Code inside the process is outside what krypto is meant to withstand
(THREAT-MODEL), so the steps are defence in depth.

| Step | What it does, and why | What it leaves open |
|---|---|---|
| Turning off dumps | sets both limits on the size of a core dump to zero and marks the process as not dumpable, so its memory goes to no dump and other unprivileged processes cannot read it | a later change of user or group id resets the mark to the machine's setting, so the step is taken again after that; crash handlers inside the process. A machine that pipes dumps to a handler ignores the size limit but honours the mark. Where a dump is made, the secrets' pages stay out of it and the rest does not |
| Forbidding new privileges | the process, and every program it starts, can never gain privileges by running a program; it costs nothing for a program that never means to gain any. Cannot be undone | the privileges the process already has |
| Closing inherited descriptors | closes every file descriptor above the three standard ones, because a descriptor left by the parent is a leak and a way in. Needs Linux 5.9 | it also closes what the program was handed on purpose, such as a listening socket, descriptors libraries hold, the lock of an open store, and the random device where krypto has fallen back to it (SPEC-primitives) |
| Leaving the file system | a change of root: makes an empty directory the root, with the process inside, so that code in the process finds no key file to read. Needs the privilege to change the root. Cannot be undone | a process that keeps that privilege can leave again, so giving it up is the caller's; descriptors opened before stay usable |

**Leaving the file system** checks the directory and changes the root on the same directory,
so a directory swapped in between cannot pass the check; if the step fails, the root is
unchanged. Afterwards krypto's operations need no file, with two exceptions: an open store can
no longer write its file, since writes go by path, and random bytes cannot be had where krypto
has fallen back to the random device and has not opened it yet (SPEC-primitives).

**On Linux all four fail closed.** A step that cannot do what it promises is an error, never a
quiet success: a program that believed in a protection it did not get would be worse off than
one that knew.

**Order.** Turning off dumps first, forbidding new privileges right after. Closing inherited
descriptors early, before the program opens its own files or a store. Leaving the file system
last, after key material has been read.

**Outside Linux** a secret is made locked, fenced and wiped but not kept out of dumps, and no
error says so. Turning off dumps only sets the limits on the size of a core dump to zero and
reports success; the three other steps fail with `Hardening`, because each promises one
concrete effect, and success without it would be untrue. krypto makes its promises on Linux on
x86_64.

## 9. Answers

| Class | Meaning |
|---|---|
| `Hardening` | a protection could not be put in place: memory that cannot be obtained or locked, random bytes that cannot be had, a hardening step that failed. Never a statement about data |
| `Format` | a secret made from more than the largest amount krypto takes, or a random secret over the limit of its call (SPEC-answers) |
| `Io` | the directory for leaving the file system cannot be found, read or opened |

## 10. References

Inside krypto:

- `spec/SPEC-keys.md` — master keys and working keys
- `spec/SPEC-secretstore.md` — rotating and upgrading a store
- `spec/SPEC-primitives.md` — random bytes, signing, key agreement, encodings
- `spec/SPEC-interfaces.md` — where Python and the command-line tool differ
- `spec/SPEC-answers.md` — the answers and the limits
- `spec/THREAT-MODEL.md` — what the protection is meant to withstand

Outside krypto, in the Linux manual pages: `mmap(2)`, `mprotect(2)`, `mlock(2)`,
`madvise(2)`, `setrlimit(2)`, `prctl(2)`, `close_range(2)`, `chroot(2)`, `core(5)`.

## 11. Revision history

| Spec version | Date | What changed |
|---|---|---|
| 0.1 | 2026-11-18 | First draft |
