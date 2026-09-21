// SPDX-License-Identifier: MIT OR Apache-2.0
//! krypto-cli — the bridge for non-Rust consumers.
//!
//! A caller that is not Rust — Python, say — runs this binary as a subprocess
//! instead of implementing its own crypto, or reaching for bindings. ONE
//! crypto implementation. Since 0.5.0 the bridge mirrors the whole
//! Rust surface — AEAD, MAC, signatures, X25519, password derivation/hashing,
//! SHA-256 — with one rule throughout: **private key material never crosses
//! into the calling process.** It lives in files (created 0600, never
//! overwritten) and is referenced by path; only public keys, signatures,
//! hashes, blobs and requested plaintext go to stdout.
//!
//! ```text
//! # AEAD + MAC (master key file → derived keys; unchanged since 0.4)
//! krypto-cli seal   --key-file <f> --context <s> --salt <s> [--alg aegis256|xchacha20|aes256gcm]
//! krypto-cli open   --key-file <f> --context <s> --salt <s>
//! krypto-cli mac    --key-file <f> --context <s> --salt <s>
//! krypto-cli keyid  --key-file <f>
//! krypto-cli reseal --key-file <old> --new-key-file <new> --context <s> --salt <s>   # rotation (0.6.0)
//!
//! # Signatures + key agreement (new in 0.5.0)
//! krypto-cli keygen --alg ed25519|p256|x25519 --out <f>          → public key (hex)
//! krypto-cli public --alg ed25519|p256|x25519 --key-file <f>     → public key (hex)
//! krypto-cli sign   --alg ed25519|p256 --key-file <f>            stdin: msg → sig (hex)
//! krypto-cli verify --alg ed25519|p256 --public <hex> --signature <hex>   stdin: msg → exit 0/3
//! krypto-cli shared --key-file <f> --peer <hex> --out <f>        writes the 32-byte shared key
//!
//! # Passwords (new in 0.5.0; password on stdin, one trailing newline stripped)
//! krypto-cli derive-key      --salt <hex> --preset interactive|balanced|high --out <f>
//! krypto-cli password-hash   --preset interactive|balanced|high  → PHC string
//! krypto-cli password-verify --phc <string>                      → exit 0/3
//!
//! # Hash (new in 0.5.0)
//! krypto-cli sha256                                              stdin: data → hex
//! ```
//!
//! Files written by `keygen`/`shared`/`derive-key` are created with mode 0600
//! and **never overwrite an existing file** (fail-closed). The output of
//! `shared`/`derive-key` is a 32-byte key file usable directly as `--key-file`
//! for `seal`/`open`/`mac`. Errors → stderr + a non-zero exit code, never key
//! material.

use std::io::{Read, Write};
use std::process::ExitCode;

use krypto::{
    blob_key_id, exchange, hex, hmac_sha256, open, seal, sign, Alg, DerivedKey, MasterKey,
    SecretBuf, SecretString,
};

const KEY_ID_CONTEXT: &[u8] = b"krypto/key-id/v1";

fn main() -> ExitCode {
    // Best-effort process hardening; a CLI should not refuse to run in
    // environments without prctl privileges, but we do say so.
    if let Err(e) = krypto::harden_process() {
        eprintln!("krypto-cli: warning: process hardening failed: {e}");
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("krypto-cli: {}", e.msg);
            // Dedicated exit codes so a consumer can tell tampering/wrong key
            // (3, should be alarmed) from usage errors (2), I/O (1) and a
            // wrong key GENERATION (4, routing — not an alarm).
            ExitCode::from(e.code)
        }
    }
}

/// Exit-code categories: 1 = I/O/internal, 2 = usage error, 3 = auth
/// (tampering, wrong key or wrong password), 4 = wrong key generation.
struct CliError {
    code: u8,
    msg: String,
}

impl CliError {
    fn usage(msg: impl Into<String>) -> Self {
        CliError {
            code: 2,
            msg: msg.into(),
        }
    }
    fn io(msg: impl Into<String>) -> Self {
        CliError {
            code: 1,
            msg: msg.into(),
        }
    }
    /// Map a krypto error: `Auth` → 3 (tampering/wrong key/wrong password),
    /// `WrongKey` → 4 (wrong key generation — routing), the rest → 1.
    fn from_krypto(e: krypto::Error) -> Self {
        let code = match e {
            krypto::Error::Auth => 3,
            krypto::Error::WrongKey => 4,
            _ => 1,
        };
        CliError {
            code,
            msg: e.to_string(),
        }
    }
}

const COMMANDS: [&str; 21] = [
    "version",
    "rand",
    "seal",
    "reseal",
    "open",
    "mac",
    "keyid",
    "keygen",
    "public",
    "sign",
    "verify",
    "shared",
    "derive-key",
    "password-hash",
    "password-verify",
    "sha256",
    "blob-key-id",
    "b64-encode",
    "b64-encode-nopad",
    "b64-decode",
    "b64-decode-nopad",
];

struct Args {
    command: String,
    key_file: Option<String>,
    context: Option<String>,
    salt: Option<String>,
    alg: Option<String>,
    out: Option<String>,
    public: Option<String>,
    signature: Option<String>,
    peer: Option<String>,
    preset: Option<String>,
    phc: Option<String>,
    n: Option<String>,
    new_key_file: Option<String>,
}

fn parse_args() -> Result<Args, CliError> {
    let mut argv = std::env::args().skip(1);
    let command = argv.next().ok_or_else(|| CliError::usage(usage()))?;
    let mut args = Args {
        command,
        key_file: None,
        context: None,
        salt: None,
        alg: None,
        out: None,
        public: None,
        signature: None,
        peer: None,
        preset: None,
        phc: None,
        n: None,
        new_key_file: None,
    };
    while let Some(flag) = argv.next() {
        let mut value = || {
            argv.next()
                .ok_or_else(|| CliError::usage(format!("{flag} is missing its value")))
        };
        match flag.as_str() {
            "--key-file" => args.key_file = Some(value()?),
            "--context" => args.context = Some(value()?),
            "--salt" => args.salt = Some(value()?),
            "--alg" => args.alg = Some(value()?),
            "--out" => args.out = Some(value()?),
            "--public" => args.public = Some(value()?),
            "--signature" => args.signature = Some(value()?),
            "--peer" => args.peer = Some(value()?),
            "--preset" => args.preset = Some(value()?),
            "--phc" => args.phc = Some(value()?),
            "--n" => args.n = Some(value()?),
            "--new-key-file" => args.new_key_file = Some(value()?),
            other => {
                return Err(CliError::usage(format!(
                    "unknown flag {other}\n{}",
                    usage()
                )))
            }
        }
    }
    Ok(args)
}

fn usage() -> String {
    "usage: krypto-cli <command> [flags]\n\
     Version:     version (prints the crate version)\n\
     Random:      rand --n <bytes> (CSPRNG for NON-secrets: salts, seeds — hex out)\n\
     AEAD/MAC:    seal|open|mac --key-file <f> --context <s> --salt <s> [--alg aegis256|xchacha20|aes256gcm]\n\
     \x20            keyid --key-file <f>\n\
     Rotation:    reseal --key-file <old> --new-key-file <new> --context <s> --salt <s> (blob in -> blob out)\n\
     Signatures:  keygen|public --alg ed25519|p256|x25519 (--out <f> | --key-file <f>)\n\
     \x20            sign --alg ed25519|p256 --key-file <f>\n\
     \x20            verify --alg ed25519|p256 --public <hex> --signature <hex>\n\
     Agreement:   shared --key-file <f> --peer <hex> --out <f>\n\
     Passwords:   derive-key --salt <hex> --preset interactive|balanced|high --out <f>\n\
     \x20            password-hash --preset <p> · password-verify --phc <string>\n\
     Hash:        sha256\n\
     Base64:      b64-encode|b64-encode-nopad (stdin: bytes → stdout: base64)\n\
     \x20            b64-decode|b64-decode-nopad (stdin: base64 → stdout: hex)"
        .into()
}

fn run() -> Result<(), CliError> {
    let args = parse_args()?;

    if args.command == "-h" || args.command == "--help" {
        println!("{}", usage());
        return Ok(());
    }
    // Validate the command BEFORE any file is loaded and stdin is read.
    // Otherwise a typo like `krypto-cli sael …` hangs forever in `read_to_end`
    // against a TTY (and swallows all of a subprocess's stdin) before the
    // error is reported.
    if !COMMANDS.contains(&args.command.as_str()) {
        return Err(CliError::usage(format!(
            "unknown command {}\n{}",
            args.command,
            usage()
        )));
    }

    match args.command.as_str() {
        "version" => {
            println!("{}", krypto::VERSION);
            Ok(())
        }
        // CSPRNG for NON-secret values (salts, seeds, jitter) — hex out, the
        // canon. Secrets stay in Rust (`SecretBuf::random`); a secret
        // printed to stdout would defeat the point.
        "rand" => {
            let n: usize = args
                .n
                .as_deref()
                .ok_or_else(|| CliError::usage("rand requires --n <bytes>"))?
                .parse()
                .map_err(|_| CliError::usage("--n must be a positive integer"))?;
            if n == 0 || n > 1_048_576 {
                return Err(CliError::usage("--n must be between 1 and 1048576"));
            }
            let buf = krypto::random_bytes(n).map_err(CliError::from_krypto)?;
            println!("{}", hex::encode(&buf));
            Ok(())
        }
        "seal" | "open" | "mac" | "keyid" => run_aead(&args),
        "reseal" => run_reseal(&args),
        "keygen" => run_keygen(&args),
        "public" => run_public(&args),
        "sign" => run_sign(&args),
        "verify" => run_verify(&args),
        "shared" => run_shared(&args),
        "derive-key" => run_derive_key(&args),
        "password-hash" => run_password_hash(&args),
        "password-verify" => run_password_verify(&args),
        "sha256" => {
            let input = read_stdin()?;
            println!("{}", hex::encode(&krypto::sha256(&input)));
            Ok(())
        }
        // Canonical base64 (STANDARD alphabet) with the Python parity guarantee.
        // Decode prints HEX (the canon) so the output is always text.
        "b64-encode" => {
            let input = read_stdin()?;
            println!("{}", krypto::base64::encode(&input));
            Ok(())
        }
        "b64-encode-nopad" => {
            let input = read_stdin()?;
            println!("{}", krypto::base64::encode_nopad(&input));
            Ok(())
        }
        "b64-decode" | "b64-decode-nopad" => {
            let input = read_stdin()?;
            let text = String::from_utf8(input)
                .map_err(|_| CliError::usage("stdin is not UTF-8 base64 text"))?;
            let trimmed = text.trim_end_matches(['\n', '\r']);
            let bytes = if args.command == "b64-decode" {
                krypto::base64::decode(trimmed)
            } else {
                krypto::base64::decode_nopad(trimmed)
            }
            .map_err(CliError::from_krypto)?;
            println!("{}", hex::encode(&bytes));
            Ok(())
        }
        // Which key generation was this blob sealed under? The routing question
        // after exit 4 — the value is an unauthenticated hint (SPEC §8e), the
        // answer for WHERE to look, never a trust decision.
        "blob-key-id" => {
            let input = read_stdin()?;
            let id = blob_key_id(&input).map_err(CliError::from_krypto)?;
            println!("{}", hex::encode(&id));
            Ok(())
        }
        // Unreachable: the command is validated above.
        _ => unreachable!("command validated"),
    }
}

// --------------------------------------------------------------------------- //
// AEAD + MAC (the 0.4 surface, unchanged)
// --------------------------------------------------------------------------- //

fn run_aead(args: &Args) -> Result<(), CliError> {
    let key_file = require(&args.key_file, "--key-file")?;
    let master = MasterKey::from_secret_file(key_file).map_err(CliError::from_krypto)?;

    if args.command == "keyid" {
        let id = key_id(&master)?;
        println!("{}", hex::encode(&id));
        return Ok(());
    }

    // --alg only makes sense for seal here; do not let it be silently ignored.
    if args.alg.is_some() && args.command != "seal" {
        return Err(CliError::usage(format!(
            "--alg applies to `seal`, not `{}`",
            args.command
        )));
    }
    let aead_alg = match args.alg.as_deref() {
        None => Alg::Aegis256,
        Some("aegis256") => Alg::Aegis256,
        Some("xchacha20") => Alg::XChaCha20Poly1305,
        Some("aes256gcm") => Alg::Aes256Gcm,
        Some(other) => return Err(CliError::usage(format!("unknown --alg {other} for seal"))),
    };

    let context = require(&args.context, "--context")?;
    let salt = require(&args.salt, "--salt")?;
    let dk: DerivedKey = master
        .derive(context.as_bytes(), salt.as_bytes())
        .map_err(CliError::from_krypto)?;

    let input = read_stdin()?;
    match args.command.as_str() {
        "seal" => {
            let kid = key_id(&master)?;
            let pt = SecretBuf::from_vec(input).map_err(CliError::from_krypto)?;
            let blob = seal(&dk, &kid, &pt, aead_alg).map_err(CliError::from_krypto)?;
            write_stdout(&blob)
        }
        "open" => {
            // Compare the blob's key id against this master key's BEFORE opening:
            // an old-generation blob is exit 4 (find the right key), not exit 3
            // (tampering alarm). The id is an unauthenticated hint — a forged one
            // still fails `open` with Auth below.
            let expected = key_id(&master)?;
            let in_blob = blob_key_id(&input).map_err(CliError::from_krypto)?;
            if in_blob != expected {
                return Err(CliError::from_krypto(krypto::Error::WrongKey));
            }
            let pt = open(&dk, &input).map_err(CliError::from_krypto)?;
            pt.expose(write_stdout)
        }
        "mac" => {
            let mac = hmac_sha256(&dk, &input).map_err(CliError::from_krypto)?;
            println!("{}", hex::encode(&mac));
            Ok(())
        }
        _ => unreachable!("routed above"),
    }
}

/// `reseal` — the rotation action for blobs (0.6.0): open with the old master's
/// derived key, seal with the new master's, under the NEW master's key id. The
/// algorithm in the blob is preserved. Both keys come from the caller (krypto
/// is stateless). An old-generation mismatch against `--key-file` is exit 4
/// (routing — point `--key-file` at the key the blob was actually sealed
/// under), exactly like `open`.
fn run_reseal(args: &Args) -> Result<(), CliError> {
    let old_file = require(&args.key_file, "--key-file")?;
    let new_file = require(&args.new_key_file, "--new-key-file")?;
    let context = require(&args.context, "--context")?;
    let salt = require(&args.salt, "--salt")?;

    let old_master = MasterKey::from_secret_file(old_file).map_err(CliError::from_krypto)?;
    let new_master = MasterKey::from_secret_file(new_file).map_err(CliError::from_krypto)?;
    let old_dk = old_master
        .derive(context.as_bytes(), salt.as_bytes())
        .map_err(CliError::from_krypto)?;
    let new_dk = new_master
        .derive(context.as_bytes(), salt.as_bytes())
        .map_err(CliError::from_krypto)?;

    let input = read_stdin()?;
    let expected = key_id(&old_master)?;
    let in_blob = blob_key_id(&input).map_err(CliError::from_krypto)?;
    if in_blob != expected {
        return Err(CliError::from_krypto(krypto::Error::WrongKey));
    }
    let new_kid = key_id(&new_master)?;
    let blob = krypto::reseal(&old_dk, &new_dk, &new_kid, &input).map_err(CliError::from_krypto)?;
    write_stdout(&blob)
}

// --------------------------------------------------------------------------- //
// Signatures + key agreement (the 0.5.0 surface)
// --------------------------------------------------------------------------- //

fn run_keygen(args: &Args) -> Result<(), CliError> {
    let out = require(&args.out, "--out")?;
    let (private, public_hex) = match sig_alg(args)? {
        "ed25519" => {
            let (seed, public) = sign::ed25519_keypair().map_err(CliError::from_krypto)?;
            (seed, hex::encode(&public))
        }
        "p256" => {
            let (pkcs8, public) = sign::ecdsa_p256_keypair().map_err(CliError::from_krypto)?;
            (pkcs8, hex::encode(&public))
        }
        "x25519" => {
            let (secret, public) = exchange::x25519_keypair().map_err(CliError::from_krypto)?;
            (secret, hex::encode(&public))
        }
        _ => unreachable!("validated in sig_alg"),
    };
    write_key_file(out, &private)?;
    println!("{public_hex}");
    Ok(())
}

fn run_public(args: &Args) -> Result<(), CliError> {
    let key = read_key_file(require(&args.key_file, "--key-file")?)?;
    let public_hex = match sig_alg(args)? {
        "ed25519" => hex::encode(&sign::ed25519_public(&key).map_err(CliError::from_krypto)?),
        "p256" => hex::encode(&sign::ecdsa_p256_public(&key).map_err(CliError::from_krypto)?),
        "x25519" => hex::encode(&exchange::x25519_public(&key).map_err(CliError::from_krypto)?),
        _ => unreachable!("validated in sig_alg"),
    };
    println!("{public_hex}");
    Ok(())
}

fn run_sign(args: &Args) -> Result<(), CliError> {
    let key = read_key_file(require(&args.key_file, "--key-file")?)?;
    let alg = sig_alg(args)?;
    let message = read_stdin()?;
    let sig_hex = match alg {
        "ed25519" => {
            hex::encode(&sign::ed25519_sign(&key, &message).map_err(CliError::from_krypto)?)
        }
        "p256" => {
            hex::encode(&sign::ecdsa_p256_sign(&key, &message).map_err(CliError::from_krypto)?)
        }
        "x25519" => return Err(CliError::usage("x25519 does not sign — use `shared`")),
        _ => unreachable!("validated in sig_alg"),
    };
    println!("{sig_hex}");
    Ok(())
}

fn run_verify(args: &Args) -> Result<(), CliError> {
    let alg = sig_alg(args)?;
    let public = decode_hex_arg(&args.public, "--public")?;
    let signature = decode_hex_arg(&args.signature, "--signature")?;
    let message = read_stdin()?;
    match alg {
        "ed25519" => sign::ed25519_verify(&public, &message, &signature),
        "p256" => sign::ecdsa_p256_verify(&public, &message, &signature),
        "x25519" => return Err(CliError::usage("x25519 does not verify — use `shared`")),
        _ => unreachable!("validated in sig_alg"),
    }
    .map_err(CliError::from_krypto)
}

fn run_shared(args: &Args) -> Result<(), CliError> {
    let key = read_key_file(require(&args.key_file, "--key-file")?)?;
    let peer = decode_hex_arg(&args.peer, "--peer")?;
    let out = require(&args.out, "--out")?;
    let shared = exchange::x25519_shared(&key, &peer).map_err(CliError::from_krypto)?;
    // The shared secret is KEY MATERIAL: it goes to a 0600 file (usable
    // directly as --key-file for seal/open/mac), never to stdout.
    write_key_file(out, &shared)
}

// --------------------------------------------------------------------------- //
// Passwords
// --------------------------------------------------------------------------- //

fn run_derive_key(args: &Args) -> Result<(), CliError> {
    let salt_hex = require(&args.salt, "--salt")?;
    let salt = hex::decode(salt_hex)
        .map_err(|e| CliError::usage(format!("--salt must be canonical hex: {e}")))?;
    let preset = parse_preset(args)?;
    let out = require(&args.out, "--out")?;
    let password = read_stdin_password()?;
    let key =
        krypto::password::derive_key(&password, &salt, preset).map_err(CliError::from_krypto)?;
    write_key_file(out, &key)
}

fn run_password_hash(args: &Args) -> Result<(), CliError> {
    let preset = parse_preset(args)?;
    let password = read_stdin_password()?;
    let phc = krypto::password::hash(&password, preset).map_err(CliError::from_krypto)?;
    println!("{phc}");
    Ok(())
}

fn run_password_verify(args: &Args) -> Result<(), CliError> {
    let phc = require(&args.phc, "--phc")?;
    let password = read_stdin_password()?;
    krypto::password::verify(&password, phc).map_err(CliError::from_krypto)
}

// --------------------------------------------------------------------------- //
// Helpers
// --------------------------------------------------------------------------- //

fn require<'a>(value: &'a Option<String>, flag: &str) -> Result<&'a str, CliError> {
    value
        .as_deref()
        .ok_or_else(|| CliError::usage(format!("{flag} is required")))
}

fn sig_alg(args: &Args) -> Result<&'static str, CliError> {
    match args.alg.as_deref() {
        Some("ed25519") => Ok("ed25519"),
        Some("p256") => Ok("p256"),
        Some("x25519") => Ok("x25519"),
        Some(other) => Err(CliError::usage(format!(
            "unknown --alg {other} — expected ed25519, p256 or x25519"
        ))),
        None => Err(CliError::usage("--alg is required (ed25519|p256|x25519)")),
    }
}

fn parse_preset(args: &Args) -> Result<krypto::password::Preset, CliError> {
    use krypto::password::Preset;
    match require(&args.preset, "--preset")? {
        "interactive" => Ok(Preset::Interactive),
        "balanced" => Ok(Preset::Balanced),
        "high" => Ok(Preset::High),
        other => Err(CliError::usage(format!(
            "unknown --preset {other} — expected interactive, balanced or high"
        ))),
    }
}

fn decode_hex_arg(value: &Option<String>, flag: &str) -> Result<Vec<u8>, CliError> {
    let s = require(value, flag)?;
    hex::decode(s).map_err(|e| CliError::usage(format!("{flag} must be canonical hex: {e}")))
}

/// Bounded stdin read: an audit payload is small; 64 MiB is very generous
/// and prevents an endless stream from being buffered/mlocked unbounded.
fn read_stdin() -> Result<Vec<u8>, CliError> {
    const MAX_STDIN: u64 = 64 * 1024 * 1024;
    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_STDIN + 1)
        .read_to_end(&mut input)
        .map_err(|e| CliError::io(format!("reading stdin failed: {e}")))?;
    if input.len() as u64 > MAX_STDIN {
        return Err(CliError::usage(format!(
            "stdin exceeds the maximum ({MAX_STDIN} bytes)"
        )));
    }
    Ok(input)
}

/// A password from stdin: UTF-8, with ONE trailing newline stripped (`\n` or
/// `\r\n`) — that is what `echo`/pipes append. A password that genuinely ends
/// in a newline cannot be passed this way; that is a deliberate trade.
fn read_stdin_password() -> Result<SecretString, CliError> {
    let mut bytes = read_stdin()?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    let s = String::from_utf8(bytes)
        .map_err(|_| CliError::usage("the password on stdin is not valid UTF-8"))?;
    SecretString::from_string(s).map_err(CliError::from_krypto)
}

/// Read a private-key file into locked memory, with an upper cap (a raw seed
/// is 32 bytes, a PKCS#8 P-256 key ~138 — 4096 is generous slack).
fn read_key_file(path: &str) -> Result<SecretBuf, CliError> {
    use std::io::Read as _;
    const CAP: u64 = 4096;
    let f = std::fs::File::open(path)
        .map_err(|e| CliError::io(format!("cannot open key file {path}: {e}")))?;
    let mut bytes = Vec::new();
    f.take(CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| CliError::io(format!("cannot read key file {path}: {e}")))?;
    if bytes.len() as u64 > CAP {
        return Err(CliError::io(format!(
            "key file {path} is too big (> {CAP} bytes)"
        )));
    }
    SecretBuf::from_vec(bytes).map_err(CliError::from_krypto)
}

/// Write key material to a NEW file with mode 0600. Refuses to overwrite an
/// existing file (fail-closed — a key you overwrite is a key you lose).
fn write_key_file(path: &str, key: &SecretBuf) -> Result<(), CliError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| {
        CliError::io(format!(
            "cannot create {path}: {e} (an existing file is never overwritten)"
        ))
    })?;
    key.expose(|b| f.write_all(b).and_then(|()| f.sync_all()))
        .map_err(|e| CliError::io(format!("writing {path} failed: {e}")))
}

/// Deterministic, publishable id for the master-key generation: HKDF with its
/// own context (one-way, purpose-separated from all working keys), first 16 B.
fn key_id(master: &MasterKey) -> Result<[u8; 16], CliError> {
    let dk = master
        .derive(KEY_ID_CONTEXT, b"")
        .map_err(CliError::from_krypto)?;
    let mac = hmac_sha256(&dk, b"key-id").map_err(CliError::from_krypto)?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&mac[..16]);
    Ok(id)
}

fn write_stdout(bytes: &[u8]) -> Result<(), CliError> {
    let mut out = std::io::stdout().lock();
    out.write_all(bytes)
        .and_then(|()| out.flush())
        .map_err(|e| CliError::io(format!("writing to stdout failed: {e}")))
}
