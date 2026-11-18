# The specification of krypto

These documents say what krypto is, how it is built and why. They are written to be read
without the code: a reader should be able to judge the design from them, and to tell whether
the code does what they say. They give the direction, the important lines, the formats and the
architecture, with the reasons; stored formats are exact, and elsewhere whoever writes the code
chooses within the frame. They hold no code, and stand on krypto alone: a document points only
to the others here and to public sources, which each one lists under References.

## Where to start

Read **SPEC-krypto** first. It gives the purpose, the principles, the structure and the words
the other documents share. Then read **THREAT-MODEL** to judge what krypto protects, against
whom and under which conditions; **SPEC-blob** and **SPEC-secretstore**, with **SPEC-keys**,
to understand a stored format; and **SPEC-answers** to know what an answer means.

## The documents

| Document | What it specifies | Status |
|---|---|---|
| [SPEC-krypto](SPEC-krypto.md) | what krypto is, its principles, how the parts fit, the main choices and why, how correctness is established | draft |
| [THREAT-MODEL](THREAT-MODEL.md) | what is protected, against whom, what is promised and under which conditions, what is the caller's | draft |
| [SPEC-memory](SPEC-memory.md) | secrets in memory, and hardening of the process | draft |
| [SPEC-keys](SPEC-keys.md) | the master key, working keys, the master key's id, replacing a key, passwords | draft |
| [SPEC-blob](SPEC-blob.md) | the sealed blob: layout, ciphers, what is authenticated | draft |
| [SPEC-secretstore](SPEC-secretstore.md) | the store file: its two format versions, reading, writing, rollback detection | normative |
| [SPEC-primitives](SPEC-primitives.md) | signatures, key agreement, hash, keyed hash, encodings, random bytes | draft |
| [SPEC-answers](SPEC-answers.md) | the answers krypto gives, and the limits on what it takes | draft |
| [SPEC-interfaces](SPEC-interfaces.md) | the library, the Python binding and the command-line tool | draft |

## How the documents fit together

SPEC-krypto is the top. SPEC-memory is the ground the rest stands on: every key and every
secret is held as it describes. SPEC-keys says how keys come to be; SPEC-blob seals one value
under a key; SPEC-secretstore keeps many sealed values in one file. SPEC-primitives covers
what stands beside sealing and storing. SPEC-answers and SPEC-interfaces run across all of
them. THREAT-MODEL says what all of it is for, and where its promises stop.

## Conventions

- **Status.** A *normative* document is settled: it is the authority for what it specifies, and
  the code follows it. A *draft* is a document that has not been settled yet; where a draft
  and the code disagree on a fact, the draft is corrected.
- **Versions.** A document's *spec version* is its own and changes with the design. It is not
  the version of krypto, nor a *format version*, which is a number inside stored data.
  **Applies from** names the first version of krypto a document describes.
- **Frozen** means that stored data depends on it, so it does not change; a new need gets a
  new version beside the old. A **public contract**, such as a password preset, is relied on by
  name and not frozen, but changing it has consequences the specifying document states.
- **Names.** The classes of answer are written as krypto names them, such as `Auth`. krypto is
  the library, krypto-py the Python binding, krypto-cli the tool. *Upgrade* means only the
  store's move from version 1 to version 2; software is *updated*.
- **Key id** always says which of four things it is: the master key's id, the key id field of
  a blob, the store's key id, or the key identifier parameter of a stored password hash. A
  *key generation* is one master key; a *store generation* is one salt and one value of the
  store's key id.

## References

Inside krypto: the documents in the table above. Outside krypto: each document lists its own.
