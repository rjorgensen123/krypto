# What `krypto-cli inspect` recognizes

`krypto-cli inspect` takes a file or a dump on stdin and tells what it is and how it was made,
without a key. It never shows a key, a plaintext or a hash value. *(0.8.0)*

```bash
krypto-cli inspect < something
```

It recognizes what krypto makes first: part 1 below. Part 2 lists the common formats other tools
make, which it does not recognize yet. Anything it cannot place is reported as `not recognized`,
with its length and whether it looks like text, random bytes or other binary data. Random bytes
cannot be told apart: encrypted data, compressed data and key material all look the same.

The exit code is `0` when it has said what something is, also `not recognized`; `3` for a krypto
blob whose header was changed, as for `open`; and `1` when stdin cannot be read.

---

## Part 1: what krypto makes

| Format | Recognized by | What `inspect` tells |
|---|---|---|
| krypto blob, from `seal` | starts with `FAFN` | the format version, the algorithm (AEGIS-256, XChaCha20-Poly1305 or AES-256-GCM), the key id and the length |
| Store file, from `SecretStore` | starts with `FST1` | the format version, the key id, the number of entries, their names and the algorithm of their blobs |
| Password hash, from `password::hash` | starts with `$argon2id$` | the Argon2id version, memory, iterations and lanes, and which krypto preset they are |
| ECDSA P-256 private key | PKCS#8 DER with the OIDs for EC and P-256 | that it is one; the key is not shown |
| ECDSA P-256 public key | 65 bytes starting with `04` (SEC1, uncompressed) | that it is one, by its length and first byte only |
| ECDSA signature | DER: a SEQUENCE of two INTEGERs | that it is one, and that r and s fit P-256 |
| 32 bytes | the length | that it can be an Ed25519 or X25519 public key, an Ed25519 seed, an X25519 private key or a krypto master key; the length alone cannot tell them apart |
| 64 bytes | the length | that it can be an Ed25519 signature |
| Any of these in hex or base64 | lowercase hex; standard base64 | it is unwrapped, and what is inside is told, with the wrapping |

The names in a store file are shown because they are not secret; anything in them that is not
printable ASCII is shown as `?`.

---

## Part 2: what others make — not recognized yet

| Family | What | Recognized by |
|---|---|---|
| OpenPGP (GnuPG) | encrypted messages and files, keys, signatures; binary or armored | the armor (`BEGIN PGP MESSAGE`, …), or the packet tag in the first byte |
| X.509 and PKCS | certificates, CSRs, CRLs, CMS/PKCS#7 (S/MIME), PKCS#12/PFX, OCSP responses | the PEM label, or the DER structure and its OIDs |
| Key formats | PKCS#8 (also encrypted), PKCS#1 (RSA), SEC1 (EC), SPKI, OpenSSH private and public, SSH2 (RFC 4716), PuTTY, JWK/JWKS, age, minisign and signify keys, WireGuard | the label, the prefix or fixed text; raw keys by their length only |
| Key collections | Java keystores (JKS, JCEKS), KeePass (KDBX), PKCS#12, macOS keychains | magic bytes |
| Encrypted files | age, OpenSSL `enc` (`Salted__`), Ansible Vault, SOPS, git-crypt, AES Crypt, encrypted zip and 7z | fixed text or magic bytes at the start |
| Encrypted disks and containers | LUKS, BitLocker; VeraCrypt has no magic | magic bytes; VeraCrypt only looks random |
| Tokens | JWT/JWS, JWE, PASETO, Fernet, Branca | the shape and the header |
| Password hashes | PHC (argon2, scrypt, pbkdf2), bcrypt, Unix crypt, Django, LDAP, htpasswd, MySQL, NTLM | the prefix; NTLM by its length only |
| Hashes and fingerprints | MD5, SHA-1, SHA-2 in hex or base64; SSH and GPG fingerprints | the length, which is a guess, or the prefix |
| Detached signatures | SSH signatures, minisign, signify, sigstore bundles, PGP `.sig`/`.asc` | the label, fixed text or JSON |
| Not cryptography, but common | gzip, zip, tar, zstd, xz | magic bytes |

---

## Further

- **[API](API.md#krypto-cli--the-helper-tool)** — all of `krypto-cli`'s commands
- **[How to use krypto](Usage.md#krypto-cli--the-helper-tool)** — `krypto-cli` with examples
