# SPEC-blob — the sealed blob (`FAFN`)

**Status:** draft · **Spec version:** 0.1 (2026-11-18) · **Applies from:** krypto 0.9.0

This document specifies krypto's sealed blob: the bytes that authenticated encryption of one
plaintext produces, what in them is authenticated, and how a blob is read. It is exact enough
to make and read a blob without krypto.

It stands on krypto alone: it points only to other documents of this specification and to
public sources, which are listed under References.

## 1. Scope and definitions

- A **blob** is one plaintext sealed under one key: a header that describes it, followed by
  the ciphertext and its authentication tag.
- **Sealing** makes a blob from a plaintext. **Opening** gives the plaintext back, or fails.
  **Re-sealing** opens a blob under one key and seals the plaintext under another.
- The **key** is a 256-bit working key (SPEC-keys). The master key is never used to seal.
- The **key id field** is 16 bytes of the header that the sealer fills (section 7).
- **Associated data** is data the caller gives when it seals and again when it opens; it is
  authenticated with the blob and not stored in it (section 5).

## 2. Why the blob looks like this

A reader must be able to open a blob without being told how it was made, so the blob says
which format and which cipher it uses. Keys are replaced over time, so it carries a field
that says which key it is under. And nothing it says about itself may be open to change, so
all of it is authenticated together with the ciphertext. The algorithm id lets a cipher be
added or left without a new format; the nonce field fits the largest nonce of the three
ciphers; the key id field fits any identifier a caller uses.

A blob carries neither the context nor the salt of its working key, nor the associated data:
a reader derives the working key again from what it used, and gives the same associated data.

## 3. Layout

| Offset | Size | Field | Content |
|---|---|---|---|
| 0 | 4 | magic | the ASCII bytes `FAFN` |
| 4 | 1 | format version | the byte 0x01 |
| 5 | 1 | algorithm id | the byte 0x01, 0x02 or 0x03 |
| 6 | 16 | key id field | what the sealer chooses |
| 22 | 32 | nonce field | the cipher's nonce in its first bytes; the rest zero when krypto seals |
| 54 | … | ciphertext | as long as the plaintext |
| end | 32 or 16 | tag | the cipher's tag |

The first 54 bytes are the **header**. A blob is the plaintext's length plus 54 bytes plus the
tag; there are no length fields.

## 4. The ciphers

| Id | Cipher | Nonce bytes used | Tag | What it is for |
|---|---|---|---|---|
| 1 | AEGIS-256 | 32 | 32 bytes | the first choice: fast, and its 256-bit nonce puts no practical limit on random nonces |
| 2 | XChaCha20-Poly1305 | 24 | 16 bytes | the way out, should AEGIS-256 have to be left: it shares the format, so leaving strands nothing |
| 3 | AES-256-GCM | 12 | 16 bytes | a peer that reads or writes blobs with its own code and can use only AES-256-GCM |

All three are authenticated encryption with associated data, take a 32-byte key, and are not
implemented by krypto itself. Algorithm id 1 means AEGIS-256 with a 256-bit tag as RFC 10032
specifies it.

**The library has no default cipher.** Every seal names one; why, and what the first choice
costs, is weighed in SPEC-krypto. The store always seals with AEGIS-256 (SPEC-secretstore).

**Nonces are random,** drawn from the operating system for each blob; krypto keeps no counter.
With 32 or 24 random bytes a repeat is not a practical concern. With the 12 of AES-256-GCM,
one key seals at most 2³² blobs: beyond that a repeat becomes too likely, and a repeated nonce
lets an attacker read the XOR of the two plaintexts and forge blobs under that key. krypto
keeps no count; for large volumes the caller uses AEGIS-256 or derives a new key in time.

**No binding to one key is promised.** AES-256-GCM and XChaCha20-Poly1305 do not bind a blob
to one key: someone who knows two keys can make one blob that opens under both. For AEGIS-256
with the 256-bit tag krypto uses, RFC 10032 assumes such a binding where the attacker cannot
choose the associated data, at a cost of about 2¹²⁸ attempts to break. krypto adds nothing of
its own and promises no binding for any cipher. A caller that opens blobs submitted by others
under a key derived from a password, and reveals whether it worked, must take that into
account.

## 5. Sealing, and what is authenticated

The plaintext is a byte secret in protected memory, at most 64 MiB, and may be empty. Sealing
checks the associated data and then the plaintext against their limits, before a nonce is
drawn or the key is used; either over its limit is `Format`. A nonce that cannot be drawn is
`Hardening`.

The cipher's associated data is the 54-byte header exactly as written, unused nonce bytes
included, followed by the caller's associated data, with nothing between them. The header has
a fixed length, so the two cannot be confused, and empty associated data gives the same
authenticated data as none. The cipher's nonce is the first bytes of the nonce field, as many
as it uses.

**Associated data** binds a blob to a value the caller gives at each call, such as a record id,
without putting it in the blob.

- It is not stored, and the blob does not record whether any was used. So a reader needs the
  key and, if associated data was used, the same associated data; a missing, added or
  different one gives `Auth`.
- It is public: krypto holds it in ordinary memory, so nothing secret belongs in it.
- It is at most 1024 bytes, the limit on a context and a salt. Something larger is bound by
  its hash.
- It binds one blob to a value under one key. A blob sealed without it can be moved to another
  record that uses the same key, and opens there.

## 6. Opening

Opening checks, in this order:

1. Associated data over 1024 bytes, or a blob over 64 MiB plus 86 bytes (the header and the
   longest tag) → `Format`.
2. Fewer than 4 bytes, or not `FAFN` → `Format`. It is not a blob.
3. Fewer than 54 bytes, a format version other than 1, or an algorithm id not in the table →
   `Auth`.
4. The ciphertext and tag do not verify against the key, the header and the associated data
   → `Auth`.

So past the magic every change gives `Auth`, a blob made larger than the size limit excepted;
SPEC-answers says why a change is `Auth` and not `Format`. Size comes first because "too
large" is true whatever the content, and checking it first keeps oversized input from costing
anything. A wrong key, context or salt also gives `Auth`: for a single blob it cannot be told
from a change.

The plaintext is given out in protected memory. Opening can still fail after the blob
verified, with `Hardening`, when protected memory cannot be had.

**The unused bytes of the nonce field** are zero when krypto seals. They are authenticated as
part of the header, and not otherwise checked when a blob is opened.

## 7. The key id field

The sealer fills the key id field; krypto takes any 16 bytes. A caller normally writes the
master key's id (SPEC-keys); the store writes the store's key id (SPEC-secretstore). The field
is 16 bytes so that any identifier fits.

The field can be read without a key, so that a caller holding several key generations picks a
key before it opens, instead of trying them all and reading every failure as tampering. That
reading runs the checks of opening up to the algorithm id and verifies nothing else, so the
field chooses a key and never decides trust. A caller that routes on it treats a key id field
it does not know as suspect, not as another key generation: otherwise whoever changes the
field turns an alarm into a search for a key.

## 8. Re-sealing

Re-sealing opens the blob under the old key, with the old associated data, and seals the
plaintext under the new key, with the key id field and the associated data the caller gives
for it. The nonce is new. Nothing is produced unless the open succeeds, and between the two the
plaintext is only in protected memory.

The cipher is kept, because replacing a key is not a change of the choice made at sealing: a
peer that reads only that cipher keeps reading the blob. Leaving a cipher is a step of its
own, by opening and sealing again under the new one. That is also how blobs leave AEGIS-256.

## 9. Memory

Sealing and opening need ordinary memory of about the size of the data, beside the protected
memory for the plaintext, and the plaintext passes through ordinary memory (SPEC-memory). If
the system cannot give that ordinary memory, the process is ended, not answered with an error.
How many large operations run at once is the caller's to limit.

## 10. What is frozen

The magic, format version 1, the layout in section 3, the algorithm ids, and what each cipher
authenticates are frozen: stored blobs depend on them. A new need gets a new format version or
algorithm id beside the old ones. Readers are updated before writers: a reader that does not
know a format version or cipher answers `Auth`, so a newer blob looks like tampering to an
older reader.

The layout and the meaning of every field are those of earlier krypto. Two kinds of blob made
earlier do not open: a blob over the size limit, also one an earlier krypto sealed; and blobs
made by an implementation that swapped the key and the nonce of AEGIS-256, the entries of
store files it wrote included, which are not AEGIS-256 blobs.

## 11. References

Inside krypto:

- `spec/SPEC-keys.md` — the working key, and the master key's id
- `spec/SPEC-secretstore.md` — the store, whose entries are blobs
- `spec/SPEC-memory.md` — protected memory, and where the plaintext is
- `spec/SPEC-answers.md` — the classes of answer, the line between them, and the limits
- `spec/SPEC-krypto.md` — why three ciphers, and why AEGIS-256 first
- `spec/THREAT-MODEL.md` — what the blob is meant to withstand

Outside krypto:

- RFC 10032 — AEGIS-256, and its test vectors with a 256-bit tag (Appendix A.3)
- draft-irtf-cfrg-xchacha (earlier draft-arciszewski-xchacha), with RFC 8439 for the
  underlying construction — XChaCha20-Poly1305
- NIST SP 800-38D — AES-256-GCM, and the limit on blobs per key (section 8.3)

## 12. Revision history

| Spec version | Date | What changed |
|---|---|---|
| 0.1 | 2026-11-18 | First draft |
