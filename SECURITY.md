# Security Policy

## Supported versions

The latest release. Older versions get no fixes — if you are on one, the answer to
a vulnerability is to upgrade.

| Version | Supported |
|---------|-----------|
| 0.7.x   | yes       |
| < 0.7   | no        |

## Reporting a vulnerability

**Please do not open a public issue.**

Use GitHub's **private vulnerability reporting** on this repository — the *Report a
vulnerability* button under the Security tab. It opens a thread only you and the
maintainer can see.

If that is not available to you, email **rogerj@gmail.com** with `krypto` in the
subject line.

Include what someone needs to reproduce it: the version, what you did, what
happened, and what you expected instead. A proof of concept helps; it is not
required, and a clear description of the flaw is worth more than a broken one.

## What to expect

This is a small project with a single maintainer. You should have an
acknowledgement within a few days.

What follows depends on what you found: a fix, a documented limitation, or an
explanation of why it is not what it appears to be. You will be told which, and
why.

A fix will not be published without telling you first, and you will be credited
unless you ask not to be.

## Scope

This crate is a thin wrapper around established primitives — RustCrypto, *ring*,
argon2, aegis. A flaw in one of those belongs upstream; if you find one through
this crate, say so and it will be routed there.

What is in scope here is how the crate uses them:

- key derivation and purpose separation (HKDF `info`, salts, the store's per-name keys)
- the sealed blob format and what it authenticates
- how secrets are held in memory, and whether they are wiped when they should be
- the process hardening calls and their failure behaviour
- `krypto-cli`: how key material enters and leaves the process

Reports that a chosen algorithm is not the one you would have chosen are welcome
as issues, not as vulnerabilities.
