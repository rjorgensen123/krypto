# What `krypto-cli inspect` recognizes

`krypto-cli inspect` takes a file or a dump on stdin and tells what it is and how it was made,
without a key: the format, and the algorithms used. It never shows a key, a plaintext or a hash
value, except the SHA-256 fingerprint of an SSH public key. *(0.8.0)*

```bash
krypto-cli inspect < something
```

Part 1 is what krypto makes; part 2 is what other tools make. Anything wrapped in PEM or hex is
unwrapped, hex in upper, lower or mixed case, and base64 when what it holds is recognized. Hex is an
even number of hex digits and nothing else: white space around the text is removed, but white space
inside it, or a leading `0x`, means it is not hex. PEM, hex and base64 are unwrapped at most two
levels deep, counted together. Below that, a PEM block is told by its label, and read only where the
label names a format of its own: OpenSSH private keys, SSH signatures, RSA public keys and PGP
armor. Where the limit stops the unwrapping, the report ends with a `note` that says so *(0.8.2)*.
`inspect` reads at most 4096 elements in one structure: the DER elements inside one value, the
OpenPGP packets of one input, and the arcs of one OID. A DER structure it reads or an OpenPGP input
with more is refused with exit `1`, a message on stderr and no report, and an OID with more arcs is
shown as `OID too long to show`. *(0.9.0)*
What is inside is told, with the wrapping. Anything it cannot place is `not recognized`, with its
length and whether it looks like text, random bytes or other binary data. Random bytes cannot be
told apart: encrypted data, compressed data and key material all look the same.

The exit code is `0` when it has said what something is, also `not recognized`; `3` for a krypto
blob whose header names a format version or an algorithm krypto does not know, *(0.9.0)* for one
that starts with `FAFN` but is cut short of its 54-byte header, as for `open`, and *(0.9.0)* for a
version 2 store file cut short of its 109-byte header; `1` when stdin cannot be read or stdout
cannot be written, as when the reader of a pipe is gone, or *(0.9.0)* when a DER structure it reads
or an OpenPGP input holds more than 4096 elements; and `2` when stdin is more than 64 MiB, or
for a wrong call: `inspect` takes no arguments, apart from `--help` and `-h`, which print the help.
Other changes to a blob still give a report and exit `0`; it takes `open`, with the key, to find
them. A store file of a version krypto does not know, and a version 1 store file cut short of its
37-byte header, are reported with exit `0`: `SecretStore::open` answers `Format` for them, not
`Auth`. `inspect` reads a store file with its own reader, not the library's.

The report shows only printable ASCII. Any other character, such as a control character or a letter
outside ASCII in a label or a name taken from the input, is left out, and the line ends with how
many were, for example `[2 characters not shown]`. So a file cannot drive the terminal or add a
line to the report. *(0.8.2)*

**Tested** means that `inspect` recognizes the format in a real file made by the tool that makes it
(`tests/fixtures/inspect`, and the test `inspect_tells_what_others_made`). **Untested** means built
from the format's description, and not checked against a real file. The files are test data:
the private keys in them are made only for the tests, protect nothing and must never be used; see
[their README](../tests/fixtures/inspect/README.md).

---

## Part 1: what krypto makes

Tested, against what the crate makes: the krypto blob, the store file and the password hash. The
ECDSA P-256 private key is tested with a key made by `openssl`. The blob and the store file are
specified in [SPEC-blob](../spec/SPEC-blob.md) and [SPEC-secretstore](../spec/SPEC-secretstore.md).

| Format | Recognized by | What `inspect` tells |
|---|---|---|
| krypto blob, from `seal` | `FAFN` | the format version, the algorithm (AEGIS-256, XChaCha20-Poly1305 or AES-256-GCM), the key id and the length |
| Store file, from `SecretStore` | `FST1` | the format version (1 or 2), the key id, the number of entries, their names (at most 20, then how many more) and the algorithm of their blobs; *(0.9.0)* in a version 2 file also the write counter. The key-check and the container MAC of a v2 file are not verified, and the MAC is shown as present, not verified — verifying them needs the master key, which `inspect` never takes |
| Password hash, from `password::hash` | `$argon2id$` | the Argon2id version, memory, iterations and lanes, and which krypto preset they are |
| ECDSA P-256 private key | PKCS#8 DER with the OIDs for EC and P-256 | that it is one; the key is not shown |
| ECDSA P-256 public key | 65 bytes starting with `04` | that it is one, by its length and first byte only |
| ECDSA signature | DER: a SEQUENCE of two INTEGERs | that it is one, and that r and s fit P-256 |
| 32 bytes | the length | that it can be an Ed25519 or X25519 public key, an Ed25519 seed, an X25519 private key, a krypto master key or a SHA-256 hash |
| 64 bytes | the length | that it can be an Ed25519 signature or a SHA-512 hash |

The names in a store file are shown because they are not secret; anything in them that is not
printable ASCII is left out and counted, as everywhere in the report. *(0.8.2)*

In an Argon2id password hash the parameters may come in any order, and those other than `m`, `t` and
`p`, such as `keyid` or `data`, are skipped and not shown. Without a `v=` field, without `m`, `t` or
`p`, with a value for one of them that is not a number that fits in 32 bits, or with a parameter
that has no `=`, the string is not recognized as a password hash; where a parameter comes twice, the
last one counts. The version is shown as it stands; the salt and the hash are not read, so a string
without them is still told. A string `inspect` tells may still be refused by `password::verify`, for
example for a `keyid`, a version other than 19 or parameters outside its range, and one it does not
tell may be accepted: `verify` reads a string without `t` or `p` with Argon2's defaults. See
[API](API.md#password--passwords).

---

## Part 2: what others make

| Family | Format | What `inspect` tells | Tested |
|---|---|---|---|
| OpenPGP (GnuPG) | encrypted messages, binary and armored | the recipients' algorithms and key ids, a passphrase's cipher and key derivation, and the cipher of the data where the message records it (SEIPD v1 keeps it in the encrypted session key) | yes, `gpg` |
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

Not recognized: Branca tokens, VeraCrypt volumes (which have no header to recognize), and
anything else without a header of its own, such as NaCl or libsodium output.

---

## Further

- **[krypto-cli](Cli.md)** — all of the tool's commands
