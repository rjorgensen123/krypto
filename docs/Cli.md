# `krypto-cli` — a tool for testing

The crate builds `krypto-cli`, a small tool for those who use krypto: from a shell it shows what
krypto, `krypto-py` and other tools made, checks that a blob opens, checks values and measures how
fast Argon2 is on the machine. *(0.8.0)*

It is a tool for testing, not for production, and not a contract: no program should build on it,
and its commands change as the need does. In code, use the crate, or `krypto-py` from Python; that
is what **[API](API.md)** describes.

```bash
krypto-cli version                                                         # the krypto version
krypto-cli inspect < file                                                  # what it is and how it was made; no key
krypto-cli keyid  --key-file <file>                                        # which key generation
krypto-cli seal   --key-file <file> --context <str> --salt <str> [--alg <name>] < plaintext > blob
krypto-cli open   --key-file <file> --context <str> --salt <str> < blob     # → plaintext
krypto-cli mac    --key-file <file> --context <str> --salt <str> < data     # → hex
krypto-cli sha256 < file                                                   # → hex
krypto-cli verify --alg ed25519 --public <hex> --signature <hex> < message  # exit 0 = holds, 3 = does not
krypto-cli bench                                                           # Argon2 per preset, seal and open
```

| Command | In → out |
|---|---|
| `version` | → the krypto version |
| `inspect` | a file or dump on stdin → what it is and how it was made, without a key; **[Inspect](Inspect.md)** lists what it recognizes |
| `keyid --key-file <f>` | → the key id of a master key (hex) |
| `seal --key-file <f> --context <s> --salt <s> [--alg aegis256\|xchacha20\|aes256gcm]` | plaintext → blob; `aegis256` when `--alg` is left out |
| `open --key-file <f> --context <s> --salt <s>` | blob → plaintext |
| `mac --key-file <f> --context <s> --salt <s>` | data → HMAC-SHA256 (hex) |
| `sha256` | data → SHA-256 (hex) |
| `verify --alg ed25519\|p256 --public <hex> --signature <hex>` | message → exit 0, or 3 if it does not hold |
| `bench` | → the time per Argon2id preset, and per seal and open, on this machine |

`krypto-cli --help` lists the commands and the exit codes, and `krypto-cli <command> --help`
explains one command and its flags. Data goes in on stdin and out on stdout, and stdin is bounded
at 64 MiB; more is a wrong call, exit `2`. `--context` and `--salt` are the values you would give
`derive`. Each command takes only its own flags, and hex in a flag must be lowercase. *(0.9.0)*
`verify` takes `--public` of at most 130 characters and `--signature` of at most 144, the hex of
the largest P-256 public key (65 bytes) and signature (72 bytes); a longer one is a wrong call,
exit `2`, and the message names the flag and the limit.

The exit code tells the kinds of failure apart:

| Code | Means | What to do |
|---|---|---|
| `0` | ok | |
| `1` | I/O, input the command cannot take (a krypto `Format` error, such as data that is not a blob or a key file that is too short), or an internal error | look at the message |
| `2` | the call is wrong: also stdin over 64 MiB, and a value on the command line that krypto refuses, such as an empty `--context`, a `--context` or `--salt` over 1024 bytes, or a `--public` or `--signature` that is not a key or signature of its kind | fix the call |
| **`3`** | **authentication failure** | **someone tampered with the data, or the context or salt is wrong; for `verify`, the signature does not hold** · *(0.9.0)* a blob cut short of its 54-byte header — `FAFN` magic intact — is `3` too, for `open` (it was `1`) and for `inspect` (it was `0`), and so is a version 2 store file cut short of its 109-byte header, for `inspect` |
| `4` | the blob names another key generation | find the right key (see `keyid` and `inspect`); a changed key id is `4` too |

`open` compares the key id in the blob with the key's before it opens, so another key generation
is `4`, not `3`. The key id is not authenticated until the blob is opened, so a blob whose key id
was changed is `4` too, and so is a blob sealed with any other value in its key id field, such as
a store entry, which carries the store's key id. Messages go to stderr in English, and never carry
key material or plaintext.

At start `krypto-cli` hardens its process with `harden_process`. If that fails, it writes a
warning to stderr and goes on. It takes none of the other hardening steps, and stands outside
krypto's promises about memory: an opened plaintext is written through the buffer of stdout, and
`inspect` reads what it describes, private keys included, into ordinary memory.

Until 0.7.3 the tool had 21 commands, and its exit codes were a contract; the commands that went
are done with the crate or `krypto-py`.

---

## Further

- **[Inspect](Inspect.md)** — what `inspect` recognizes
- **[Usage](Usage.md)** and **[Python](Python.md)** — krypto in code
