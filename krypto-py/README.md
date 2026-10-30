# krypto-py

The Python module of [krypto](https://github.com/rjorgensen123/krypto): secrets in locked memory,
authenticated encryption at rest, key derivation, signatures, key agreement and password hashing.
It is the same API as the Rust crate `krypto`, with the same names, and the same Rust code runs
inside it — so what one seals, the other opens.

```sh
pip install krypto-py
```

```python
import krypto_py as krypto

krypto.harden_process()
master = krypto.MasterKey.from_secret_file("/run/secrets/master_key")
key = master.derive(b"my-app/tokens/v1", b"per-store-salt")

secret = krypto.SecretBuf.from_vec(bytearray(b"api-token"))   # the bytearray is zeroed
blob = krypto.seal(key, master.key_id(), secret, krypto.Alg.Aegis256)
back = krypto.open(key, blob)                                 # a SecretBuf: the plaintext stays locked
```

Errors are exceptions, one per kind, all under `krypto_py.Error`. `AuthError` means tampering or
the wrong key, and is the one to alert on.

The secrets live in krypto's locked memory, kept out of core dumps and wiped when dropped. What
Python itself holds — the `bytes` you pass in, and the copies `expose` hands out — is ordinary
Python memory, neither locked nor wiped.

- **[How to use it](https://github.com/rjorgensen123/krypto/blob/main/docs/Python.md)**, with
  examples
- **[The API](https://github.com/rjorgensen123/krypto/blob/main/docs/API.md)**, one for Rust and
  Python, and what Python cannot guarantee
- **[Changes](https://github.com/rjorgensen123/krypto/blob/main/CHANGELOG.md)**

License: MIT or Apache-2.0, at your option.
