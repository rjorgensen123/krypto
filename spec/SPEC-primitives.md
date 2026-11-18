# SPEC-primitives — signatures, key agreement, hash, keyed hash, encodings and random bytes

**Status:** draft · **Spec version:** 0.1 (2026-11-18) · **Applies from:** krypto 0.9.0

This document specifies the parts of krypto that stand beside sealing and storing:
signatures, key agreement, the hash, the keyed hash and constant-time comparison, the text
encodings, and random bytes, and which check each algorithm has against its definition.

It stands on krypto alone: it points only to other documents of this specification and to
public sources, which are listed under References.

## 1. Why these are here

A program that seals its secrets usually also needs to sign, compare, write a key as text, or
draw a random identifier. Without these in krypto, each program would take them from elsewhere,
and "no program writes its own cryptography" would hold only for part of what it does.

None of them defines a format of krypto's own: keys, signatures and encodings are those of the
standards, so that anything that follows them can read what krypto makes. An alternative
exists only because a format or a peer needs it: ECDSA beside Ed25519, a relaxed Ed25519
check, base64 beside hex.

## 2. Signatures

| Scheme | Private key | Public key | Signature |
|---|---|---|---|
| Ed25519 | a 32-byte seed | 32 bytes | 64 bytes |
| ECDSA over P-256 with SHA-256 | PKCS#8 in DER, at most 512 bytes | a SEC 1 point: 65 bytes uncompressed; 33 bytes compressed is also taken when verifying | ASN.1 DER, at most 72 bytes |

**Why these forms.** For Ed25519, raw keys are the form public keys are usually handed out in.
For P-256, these are the forms a widely used library puts on the wire, so a program can move
to krypto without changing what it sends.

A private key is a byte secret in protected memory (SPEC-memory). Signing is deterministic in
both schemes; ECDSA signing follows RFC 6979, and verification accepts randomized signatures.

**ECDSA signatures have two valid forms.** Signing gives the signature as RFC 6979 computes
it, and verification accepts both (r, s) and (r, n − s), as other implementations of the
standard produce and accept them; krypto adds no rule of its own. So anyone can make a second
valid signature from a first, and the bytes of a signature cannot serve as its identity.

**A key is for one purpose.** Neither scheme separates one use of a key from another: both sign
the message as given. A signature made in one protocol counts in another that uses the same
key wherever the signed bytes coincide.

**Ed25519 verification is strict.** It refuses, with `Auth`, a public key of small order, a
signature whose first half (R) is of small order or is not a point, and a second half (S) that
is not below the group order; and, with `Format`, a public key that is not a point or not the
one canonical encoding of its point. With that, a signature that verifies was made with the
private key belonging to the public key. Without it, there are keys for which anyone can make
a signature that verifies.

**The relaxed check** exists for places where such keys must be accepted because they are
already in use. It accepts keys and an R of small order, and keys that are not canonically
encoded. It still refuses an R that is not a point and an S that is not below the group order
(`Auth`), and a key that is not a point (`Format`). The refusal of such an S, in both checks,
holds as krypto itself is built; a program's own build can change how the signature
implementation behaves (THREAT-MODEL, assumptions). The relaxed check is never the way to decide
who signed something with a key from someone else. Otherwise, for Ed25519 and ECDSA alike, a signature
that does not hold is `Auth`; a key of the wrong form, a signature of the wrong length or
encoding, and anything over its limit are `Format`.

## 3. Key agreement

X25519: each side has a 32-byte private key and a 32-byte public key, and the two sides arrive
at the same 32 bytes.

- **The result is key material, not a key.** It is taken as a master key, from which working
  keys are derived before anything is done with it (SPEC-keys).
- **An all-zero result is refused with `Auth`.** A peer forces it by sending a key of small
  order, to fix the outcome whatever the private key.

**Key agreement authenticates no one.** The caller authenticates the peer's public key by its
own means, and binds both public keys into the derivation, in the context or the salt. krypto
gives the agreement and nothing on top of it; the format of a message sealed to a public key
is the caller's.

## 4. Hash, keyed hash and comparison

- **SHA-256** gives a fingerprint of data. It authenticates nothing, since anyone can compute
  it, and it is not for passwords. It has no limit (SPEC-answers); its time grows with the
  input, which the caller bounds.
- **HMAC-SHA256** gives a 32-byte value that only a holder of the key can compute. The key is a
  working key (SPEC-keys). It is for a value only the key holder can check, such as a chain
  over records that whoever can edit them must not recompute.
- **Comparison in constant time** says whether two byte strings are equal, in a time that does
  not depend on where they differ. Their length is public: different lengths are unequal at
  once. It is for comparing anything secret or derived from a secret, such as a MAC; a plain
  comparison shows through its time how many leading bytes matched. It has no limit either.

## 5. Text encodings

Hex and base64, each with one spelling. A value that could be written in two ways would make a
fingerprint comparison or a signed text depend on who wrote it, so a second spelling is
refused, not tolerated.

- **Hex** is written with 0–9 and a–f. Decoding takes only those characters and an even
  length.
- **Base64** uses the standard alphabet, in a padded form and an unpadded form. Each form
  decodes only itself. White space, wrong padding and leftover bits that are not zero are
  refused.

By krypto's convention keys and signatures are written in hex. Base64 is for formats that are
base64 by nature, such as PEM bodies and SSH fingerprints.

**They are for public values.** Encoding and decoding take time that depends on the data, and
work in ordinary memory, which is not wiped when decoding fails.

The limit is on the bytes: at most 64 MiB is encoded, and a text is decoded only if it decodes
to at most that, so decoding always takes what encoding makes. A refused text is `Format`, with
a message that never names the offending character or its place (SPEC-answers); memory that
cannot be had for the result is `Hardening`.

## 6. Random bytes

All randomness comes from the operating system; krypto has no generator of its own. Two kinds
are given: bytes for things that are not secret, such as salts and identifiers, in ordinary
memory; and a secret of random bytes, made directly in protected memory. They are separate
because a salt is meant to be stored in the open, and a locked type that prints as a
placeholder would only hide that.

One call gives at most 1 MiB, or a limit the program states for that call; there is no setting
for the whole process. A request for a very large amount once ended the process instead of
failing, so every call has a limit, and a larger one is a deliberate choice. More is `Format`;
memory or randomness that cannot be had is `Hardening`.

krypto takes the bytes through the kernel's call for random bytes. Where that call is
unavailable or blocked, the kernel's non-blocking random device is read instead, through a
descriptor that stays open. Closing inherited descriptors then closes it, and later random
bytes can be read from whatever the process opens next under that number; after leaving the
file system, a device not yet opened cannot be opened (SPEC-memory). A program that runs where
the kernel's call is unavailable, and takes either step, must know this.

## 7. Checked against the definitions

This table gives the check each algorithm has; SPEC-krypto says how correctness is established.

| What | Published test vectors | Independent implementation |
|---|---|---|
| AEGIS-256 | those of RFC 10032 | none |
| XChaCha20-Poly1305 | those of draft-irtf-cfrg-xchacha (earlier draft-arciszewski-xchacha) | none |
| AES-256-GCM | a NIST vector | blobs, both ways, with and without associated data |
| HKDF, HMAC-SHA256, the master key's id | none | compared |
| SHA-256 | FIPS 180-4 | compared |
| Argon2id | none | keys under the two lighter presets; krypto's hashes under all three presets verify there, and one parameter set is checked the other way |
| Ed25519, ECDSA P-256 | RFC 8032, RFC 6979 | both ways, with their key forms |
| X25519 | RFC 7748 | the agreed secret |
| base64 | RFC 4648 | both ways |
| hex | none | none; fixed values in krypto's own tests |

## 8. References

Inside krypto:

- `spec/SPEC-krypto.md` — how correctness is established
- `spec/SPEC-keys.md` — working keys, and key material taken as a master key
- `spec/SPEC-memory.md` — protected memory, and the hardening steps
- `spec/SPEC-answers.md` — the classes of answer, and the limits
- `spec/THREAT-MODEL.md` — what these are meant to withstand

Outside krypto:

- RFC 8032 — Ed25519; RFC 7748 — X25519
- FIPS 186-5 — ECDSA; RFC 6979 — deterministic signing; RFC 5208 — PKCS#8; SEC 1 — the
  encoding of a point
- FIPS 180-4 — SHA-256; RFC 2104 — HMAC; RFC 5869 — HKDF; RFC 4648 — base64 and hex
- RFC 10032 — AEGIS-256
- draft-irtf-cfrg-xchacha (earlier draft-arciszewski-xchacha), with RFC 8439 for the
  underlying construction — XChaCha20-Poly1305
- The Linux manual pages `getrandom(2)` and `random(4)`

## 9. Revision history

| Spec version | Date | What changed |
|---|---|---|
| 0.1 | 2026-11-18 | First draft |
