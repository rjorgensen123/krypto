# Test data for `krypto-cli inspect`

These files are test data. The test `inspect_tells_what_others_made` in `tests/cli.rs` runs
`krypto-cli inspect` on each of them and checks that it recognizes the format. **[Inspect](../../../docs/Inspect.md)**
lists what `inspect` recognizes, and which of it these files test.

They were made with the tools that make each format, so `inspect` is checked against real files,
not against what the formats are thought to look like:

| Files | Made with |
|---|---|
| `cert-*`, `csr-*`, `*.pkcs8.pem`, `*.pkcs1*.pem`, `*.sec1.pem`, `*.spki.pem`, `*.enc-pkcs8.pem`, `bundle.p12`, `cms-*`, `openssl-enc.bin` | `openssl` |
| `pgp-*` | `gpg` (GnuPG) |
| `ssh-*`, `ssh2-*` | `ssh-keygen` |
| `data.gz`, `data.zst` | `gzip`, `zstd` |
| `data.tar`, `data.xz`, `data.bz2`, `data.zip`, `fernet.txt` | Python's standard library and `cryptography` |

**The private keys here are made only for these tests.** They protect nothing, they are public
with the source, and they must never be used for anything else. The encrypted ones use the
passphrase `test` or `secret`. A scanner that finds private keys here has found test data.

To add a file, make it with the tool that makes the format, and add the format `inspect` should
name to the test. The test fails for a file it has no expectation for.
