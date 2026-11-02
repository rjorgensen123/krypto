# What `krypto-cli inspect` recognizes

`krypto-cli inspect` takes a file or a dump on stdin and tells what it is and how it was made,
without a key: the format, and the algorithms used. It never shows a key, a plaintext or a hash
value. *(0.8.0)*

```bash
krypto-cli inspect < something
```

Part 1 is what krypto makes; part 2 is what other tools make. Anything wrapped in PEM, hex or
base64 is unwrapped, and what is inside is told, with the wrapping. Anything it cannot place is
`not recognized`, with its length and whether it looks like text, random bytes or other binary
data. Random bytes cannot be told apart: encrypted data, compressed data and key material all look
the same.

The exit code is `0` when it has said what something is, also `not recognized`; `3` for a krypto
blob whose header was changed, as for `open`; and `1` when stdin cannot be read.

**Tested** means that `inspect` recognizes the format in a real file made by the tool that makes it
(`tests/fixtures/inspect`, and the test `inspect_tells_what_others_made`). **Untested** means built
from the format's description, and not yet checked against a real file. The files are test data:
the private keys in them are made only for the tests, protect nothing and must never be used; see
[their README](../tests/fixtures/inspect/README.md).

---

## Part 1: what krypto makes

All tested, against what the crate makes.

| Format | Recognized by | What `inspect` tells |
|---|---|---|
| krypto blob, from `seal` | `FAFN` | the format version, the algorithm (AEGIS-256, XChaCha20-Poly1305 or AES-256-GCM), the key id and the length |
| Store file, from `SecretStore` | `FST1` | the format version, the key id, the number of entries, their names and the algorithm of their blobs |
| Password hash, from `password::hash` | `$argon2id$` | the Argon2id version, memory, iterations and lanes, and which krypto preset they are |
| ECDSA P-256 private key | PKCS#8 DER with the OIDs for EC and P-256 | that it is one; the key is not shown |
| ECDSA P-256 public key | 65 bytes starting with `04` | that it is one, by its length and first byte only |
| ECDSA signature | DER: a SEQUENCE of two INTEGERs | that it is one, and that r and s fit P-256 |
| 32 bytes | the length | that it can be an Ed25519 or X25519 public key, an Ed25519 seed, an X25519 private key, a krypto master key or a SHA-256 hash |
| 64 bytes | the length | that it can be an Ed25519 signature or a SHA-512 hash |

The names in a store file are shown because they are not secret; anything in them that is not
printable ASCII is shown as `?`.

---

## Part 2: what others make

| Family | Format | What `inspect` tells | Tested |
|---|---|---|---|
| OpenPGP (GnuPG) | encrypted messages, binary and armored | the recipients' algorithms and key ids, a passphrase's cipher and key derivation, and the cipher of the data | yes, `gpg` |
| | public and private keys | the primary key's and subkeys' algorithms, curves or sizes, and the number of user ids | public yes, `gpg`; private untested |
| | signatures | the signature and hash algorithms | yes, `gpg` |
| X.509 and PKCS | certificates, PEM and DER | the signature algorithm, the public key, and the validity dates | yes, `openssl` |
| | certificate signing requests (PKCS#10) | the signature algorithm and the public key | yes, `openssl` |
| | revocation lists (CRL) | the signature algorithm | untested |
| | CMS / PKCS#7 (S/MIME) | enveloped: the cipher and the recipients' key transport; signed: the digest and signature algorithms | yes, `openssl cms` |
| | PKCS#12 / PFX bundles | the integrity MAC, and how certificates and keys are encrypted | yes, `openssl pkcs12` |
| Key formats | PKCS#8 private keys, plain and encrypted | the algorithm and size or curve; for encrypted, the key derivation and cipher | yes, `openssl` |
| | PKCS#1 RSA private and public keys, also legacy-encrypted PEM | the size; for encrypted, the cipher | yes, `openssl` |
| | SEC1 EC private keys | the curve | yes, `openssl` |
| | SubjectPublicKeyInfo public keys | the algorithm and size or curve | yes, `openssl` |
| | OpenSSH private keys | the key type, whether and how it is encrypted | yes, `ssh-keygen` |
| | OpenSSH public keys, one line and RFC 4716 | the key type and size, and the SHA-256 fingerprint | yes, `ssh-keygen` |
| | PuTTY keys (`.ppk`) | the key type, the encryption and key derivation | untested |
| | JSON Web Keys and key sets | the key type, curve and algorithm, and whether it is private | untested |
| | age identities and recipients | that they are, X25519 | untested |
| | minisign and signify keys | the algorithm | untested |
| Key collections | Java keystores (JKS, JCEKS) | the version, the number of entries and the protection | untested |
| | KeePass databases (KDBX) | the version, the cipher and the key derivation | untested |
| | macOS keychains | that it is one | untested |
| Encrypted files | age | the recipients' types, and the cipher | untested |
| | OpenSSL `enc` (`Salted__`) | that it is one; the file does not record its cipher | yes, `openssl enc` |
| | Ansible Vault | the version and cipher | untested |
| | SOPS | the cipher, and what holds the data key | untested |
| | git-crypt, AES Crypt | the cipher | untested |
| | zip | whether it is encrypted, and how (ZipCrypto or AES) | not encrypted yes, Python; encrypted untested |
| | 7-Zip | that it is one, and the cipher it uses when encrypted | untested |
| Encrypted disks | LUKS 1 and 2 | the cipher, hash or key derivation | untested |
| | BitLocker | that it is one | untested |
| Tokens | JWT / JWS, JWE | the algorithms in the header, and the key id | untested |
| | PASETO | the version and purpose, and so the algorithm | untested |
| | Fernet | the algorithm, and when it was made | yes, Python `cryptography` |
| Password hashes | Argon2i and Argon2d, scrypt, PBKDF2, bcrypt, Unix crypt, Django, LDAP, MySQL | the scheme, and its cost or iterations where it says | untested |
| Hashes and fingerprints | MD5, SHA-1 and SHA-2 in hex or base64; SSH and OpenPGP fingerprints | a guess by the length, or the scheme by the form | untested |
| Signatures | SSH signatures (`ssh-keygen -Y sign`) | the key type, hash and namespace | yes, `ssh-keygen` |
| | minisign and signify signatures | the algorithm | untested |
| | Sigstore bundles | the media type | untested |
| Not cryptography | gzip, zstd, xz, bzip2, tar | that it is compressed or archived, not encrypted | yes, `gzip`, `zstd`, Python |

Not recognized yet: Branca tokens, VeraCrypt volumes (which have no header to recognize), and
anything else without a header of its own, such as NaCl or libsodium output.

---

## Further

- **[krypto-cli](Cli.md)** — all of the tool's commands
