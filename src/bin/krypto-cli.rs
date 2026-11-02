// SPDX-License-Identifier: MIT OR Apache-2.0
//! krypto-cli — a small helper for those who use krypto (0.8.0).
//!
//! It checks what krypto and `krypto-py` made, checks values and measures
//! speed, from a shell. It is not a product and not a contract: no program
//! should build on it, and its commands change as the need does. In code, use
//! the crate, or `krypto-py` from Python.
//!
//! ```text
//! krypto-cli version                                         → the krypto version
//! krypto-cli inspect                                         blob → format, algorithm, key id
//! krypto-cli keyid  --key-file <f>                           → the key id (hex)
//! krypto-cli seal   --key-file <f> --context <s> --salt <s> [--alg aegis256|xchacha20|aes256gcm]
//!                                                            plaintext → blob
//! krypto-cli open   --key-file <f> --context <s> --salt <s>  blob → plaintext
//! krypto-cli mac    --key-file <f> --context <s> --salt <s>  data → HMAC-SHA256 (hex)
//! krypto-cli sha256                                          data → SHA-256 (hex)
//! krypto-cli verify --alg ed25519|p256 --public <hex> --signature <hex>
//!                                                            message → exit 0, or 3
//! krypto-cli bench                                           → time per Argon2 preset, seal, open
//! ```
//!
//! Input comes on stdin, output goes to stdout. Each command takes only its own
//! flags. Exit codes: 0 ok · 1 I/O or internal · 2 the call is wrong · 3
//! authentication failed (tampering or the wrong key) · 4 the blob belongs to
//! another key generation. Messages go to stderr, never with key material or
//! plaintext.

use std::io::{Read, Write};
use std::process::ExitCode;
use std::time::Instant;

use krypto::password::{self, Preset};
use krypto::{blob_key_id, hex, hmac_sha256, open, seal, sign, Alg, MasterKey, SecretBuf};
use zeroize::Zeroizing;

/// The commands. `tests/docs.rs` reads this list and checks that `docs/API.md`
/// names each one.
const COMMANDS: [&str; 9] = [
    "version", "inspect", "keyid", "seal", "open", "mac", "sha256", "verify", "bench",
];

/// The flags each command takes; any other flag is a wrong call.
fn flags_of(command: &str) -> &'static [&'static str] {
    match command {
        "keyid" => &["--key-file"],
        "seal" => &["--key-file", "--context", "--salt", "--alg"],
        "open" | "mac" => &["--key-file", "--context", "--salt"],
        "verify" => &["--alg", "--public", "--signature"],
        _ => &[],
    }
}

fn main() -> ExitCode {
    // Best effort: the helper should run where prctl is not allowed, but says so.
    if let Err(e) = krypto::harden_process() {
        eprintln!("krypto-cli: warning: process hardening failed: {e}");
    }
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(fail) => {
            eprintln!("krypto-cli: {}", fail.msg);
            ExitCode::from(fail.code)
        }
    }
}

/// A failure: the exit code and the message for stderr.
struct Fail {
    code: u8,
    msg: String,
}

impl Fail {
    /// The call is wrong: exit 2.
    fn usage(msg: impl Into<String>) -> Self {
        Fail {
            code: 2,
            msg: msg.into(),
        }
    }

    /// I/O or internal: exit 1.
    fn io(msg: impl Into<String>) -> Self {
        Fail {
            code: 1,
            msg: msg.into(),
        }
    }

    /// A krypto error: `Auth` is 3, `WrongKey` 4, the rest 1.
    fn krypto(e: krypto::Error) -> Self {
        let code = match e {
            krypto::Error::Auth => 3,
            krypto::Error::WrongKey => 4,
            _ => 1,
        };
        Fail {
            code,
            msg: e.to_string(),
        }
    }

    /// A krypto error about something given on the command line: the call is
    /// wrong (2), unless it is `Auth` (3) or `WrongKey` (4).
    fn from_args(e: krypto::Error) -> Self {
        let mut fail = Fail::krypto(e);
        if fail.code == 1 {
            fail.code = 2;
        }
        fail
    }
}

/// The command and its flags, checked before anything is read. `help` is set
/// when `--help` or `-h` follows the command.
struct Args {
    command: String,
    flags: Vec<(String, String)>,
    help: bool,
}

impl Args {
    fn get(&self, flag: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(f, _)| f == flag)
            .map(|(_, v)| v.as_str())
    }

    fn need(&self, flag: &str) -> Result<&str, Fail> {
        self.get(flag)
            .ok_or_else(|| Fail::usage(format!("`{}` needs {flag}", self.command)))
    }
}

/// Parse the command line. An unknown command or flag is told by its position,
/// so a secret typed in the wrong place is never repeated back.
fn parse(argv: Vec<String>) -> Result<Args, Fail> {
    let mut argv = argv.into_iter();
    let Some(command) = argv.next() else {
        return Err(Fail::usage(overview()));
    };
    let is_help = |a: &str| a == "-h" || a == "--help";
    if is_help(&command) {
        return Ok(Args {
            command,
            flags: Vec::new(),
            help: true,
        });
    }
    if !COMMANDS.contains(&command.as_str()) {
        return Err(Fail::usage(format!(
            "argument 1 is not a command; the commands are {} (see --help)",
            COMMANDS.join(", ")
        )));
    }
    let rest: Vec<String> = argv.collect();
    if rest.iter().any(|a| is_help(a)) {
        return Ok(Args {
            command,
            flags: Vec::new(),
            help: true,
        });
    }
    let mut argv = rest.into_iter();
    let allowed = flags_of(&command);
    let mut flags: Vec<(String, String)> = Vec::new();
    let mut position = 1;
    while let Some(flag) = argv.next() {
        position += 1;
        if !allowed.contains(&flag.as_str()) {
            let takes = if allowed.is_empty() {
                "no flags".to_string()
            } else {
                allowed.join(" ")
            };
            return Err(Fail::usage(format!(
                "argument {position} is not a flag `{command}` takes; it takes {takes}"
            )));
        }
        let value = argv
            .next()
            .ok_or_else(|| Fail::usage(format!("{flag} needs a value")))?;
        position += 1;
        if flags.iter().any(|(f, _)| *f == flag) {
            return Err(Fail::usage(format!("{flag} is given twice")));
        }
        flags.push((flag, value));
    }
    Ok(Args {
        command,
        flags,
        help: false,
    })
}

/// `krypto-cli --help`: what the tool is, the commands, and the exit codes.
fn overview() -> String {
    format!(
        "krypto-cli {} — a small helper for those who use krypto\n\
         \n\
         usage: krypto-cli <command> [flags]\n\
         \x20      krypto-cli <command> --help    the flags of one command\n\
         \n\
         commands:\n\
         \x20 version   the krypto version\n\
         \x20 inspect   read the header of a blob on stdin, without a key\n\
         \x20 keyid     the key id of a master key\n\
         \x20 seal      encrypt stdin\n\
         \x20 open      decrypt a blob on stdin\n\
         \x20 mac       HMAC-SHA256 of stdin\n\
         \x20 sha256    SHA-256 of stdin\n\
         \x20 verify    check an Ed25519 or P-256 signature over stdin\n\
         \x20 bench     time Argon2 per preset, and seal and open, on this machine\n\
         \n\
         exit codes:\n\
         \x20 0  ok\n\
         \x20 1  I/O or internal error\n\
         \x20 2  the call is wrong\n\
         \x20 3  authentication failed: tampering, or the wrong key\n\
         \x20 4  the blob belongs to another key generation: find the right key\n\
         \n\
         A helper, not a product: in code, use the crate, or krypto-py from Python.",
        krypto::VERSION
    )
}

/// `krypto-cli <command> --help`: how to call it, and what each flag means.
fn help_of(command: &str) -> &'static str {
    match command {
        "version" => "usage: krypto-cli version\n\nPrints the krypto version.",
        "inspect" => {
            "usage: krypto-cli inspect < blob\n\
             \n\
             Reads the header of a krypto blob without a key, and prints the format\n\
             version, the algorithm, the key id and the length. The key id says which\n\
             key generation sealed it; compare it with `krypto-cli keyid`. Input that is\n\
             not a krypto blob is exit 1."
        }
        "keyid" => {
            "usage: krypto-cli keyid --key-file <file>\n\
             \n\
             Prints the key id of a master key, which says what key generation it is.\n\
             \n\
             \x20 --key-file <file>   the master key: a file of 32 to 4096 bytes"
        }
        "seal" => {
            "usage: krypto-cli seal --key-file <file> --context <text> --salt <text> \
             [--alg <name>] < plaintext > blob\n\
             \n\
             Encrypts stdin under the key derived from the master key, the context and\n\
             the salt, and writes the blob to stdout.\n\
             \n\
             \x20 --key-file <file>   the master key\n\
             \x20 --context <text>    what the key is for, as given to derive (my-app/tokens/v1)\n\
             \x20 --salt <text>       the salt given to derive\n\
             \x20 --alg <name>        aegis256 (the default), xchacha20 or aes256gcm"
        }
        "open" => {
            "usage: krypto-cli open --key-file <file> --context <text> --salt <text> < blob\n\
             \n\
             Decrypts a blob and writes the plaintext to stdout. A blob from another key\n\
             generation is exit 4; a changed blob, or the wrong key, context or salt, is\n\
             exit 3.\n\
             \n\
             \x20 --key-file <file>   the master key\n\
             \x20 --context <text>    the context the blob was sealed with\n\
             \x20 --salt <text>       the salt the blob was sealed with"
        }
        "mac" => {
            "usage: krypto-cli mac --key-file <file> --context <text> --salt <text> < data\n\
             \n\
             Prints the HMAC-SHA256 of stdin under the derived key, in hex.\n\
             \n\
             \x20 --key-file <file>   the master key\n\
             \x20 --context <text>    what the key is for, as given to derive\n\
             \x20 --salt <text>       the salt given to derive"
        }
        "sha256" => "usage: krypto-cli sha256 < data\n\nPrints the SHA-256 of stdin, in hex.",
        "verify" => {
            "usage: krypto-cli verify --alg <alg> --public <hex> --signature <hex> < message\n\
             \n\
             Checks a signature over stdin: exit 0 if it holds, 3 if it does not.\n\
             \n\
             \x20 --alg <alg>          ed25519, or p256 (ECDSA P-256 over SHA-256)\n\
             \x20 --public <hex>       the public key: 32 bytes for ed25519, SEC1 for p256\n\
             \x20 --signature <hex>    64 bytes for ed25519, DER for p256"
        }
        "bench" => {
            "usage: krypto-cli bench\n\
             \n\
             Times Argon2id for each preset (interactive, balanced, high), and seal and\n\
             open of 1 KiB, on this machine. It takes about a second; use it to choose a\n\
             preset."
        }
        _ => unreachable!("the command is checked in parse"),
    }
}

fn run(argv: Vec<String>) -> Result<(), Fail> {
    let args = parse(argv)?;
    if args.help {
        return match args.command.as_str() {
            "-h" | "--help" => line(&overview()),
            command => line(help_of(command)),
        };
    }
    match args.command.as_str() {
        "version" => line(krypto::VERSION),
        "inspect" => inspect(&read_stdin()?),
        "keyid" => line(&hex::encode(
            &master(&args)?.key_id().map_err(Fail::krypto)?,
        )),
        "seal" | "open" | "mac" => aead(&args),
        "sha256" => line(&hex::encode(&krypto::sha256(&read_stdin()?))),
        "verify" => verify(&args),
        "bench" => bench(),
        _ => unreachable!("the command is checked in parse"),
    }
}

fn master(args: &Args) -> Result<MasterKey, Fail> {
    MasterKey::from_secret_file(args.need("--key-file")?).map_err(Fail::krypto)
}

/// The header of a blob, read without a key: the format version, the
/// algorithm, the key id and the length.
fn inspect(blob: &[u8]) -> Result<(), Fail> {
    // `blob_key_id` checks the header as `open` does: `Format` if this is not a
    // krypto blob, `Auth` if a known field was changed.
    let id = blob_key_id(blob).map_err(Fail::krypto)?;
    let alg = match blob[5] {
        1 => "aegis256",
        2 => "xchacha20",
        3 => "aes256gcm",
        _ => "unknown",
    };
    line(&format!(
        "format {}\nalgorithm {alg}\nkey-id {}\nbytes {}",
        blob[4],
        hex::encode(&id),
        blob.len()
    ))
}

fn aead(args: &Args) -> Result<(), Fail> {
    let alg = match args.get("--alg") {
        None | Some("aegis256") => Alg::Aegis256,
        Some("xchacha20") => Alg::XChaCha20Poly1305,
        Some("aes256gcm") => Alg::Aes256Gcm,
        Some(_) => return Err(Fail::usage("--alg is aegis256, xchacha20 or aes256gcm")),
    };
    let master = master(args)?;
    let context = args.need("--context")?;
    let salt = args.need("--salt")?;
    let key = master
        .derive(context.as_bytes(), salt.as_bytes())
        .map_err(Fail::from_args)?;
    if args.command == "seal" {
        let id = master.key_id().map_err(Fail::krypto)?;
        let plaintext = read_stdin_secret()?;
        return out(&seal(&key, &id, &plaintext, alg).map_err(Fail::krypto)?);
    }
    let input = read_stdin()?;
    match args.command.as_str() {
        "open" => {
            // Another key generation is routing (4), not tampering (3), so the
            // key id in the blob is compared with this key's before opening. The
            // id is not authenticated: a forged one also gives 4 here, and `Auth`
            // only once the blob is opened with a key.
            let expected = master.key_id().map_err(Fail::krypto)?;
            if blob_key_id(&input).map_err(Fail::krypto)? != expected {
                return Err(Fail::krypto(krypto::Error::WrongKey));
            }
            open(&key, &input).map_err(Fail::krypto)?.expose(out)
        }
        _ => line(&hex::encode(
            &hmac_sha256(&key, &input).map_err(Fail::krypto)?,
        )),
    }
}

fn verify(args: &Args) -> Result<(), Fail> {
    type Check = fn(&[u8], &[u8], &[u8]) -> Result<(), krypto::Error>;
    let check: Check = match args.need("--alg")? {
        "ed25519" => sign::ed25519_verify,
        "p256" => sign::ecdsa_p256_verify,
        _ => return Err(Fail::usage("--alg for verify is ed25519 or p256")),
    };
    let public = hex_arg(args, "--public")?;
    let signature = hex_arg(args, "--signature")?;
    let message = read_stdin()?;
    check(&public, &message, &signature).map_err(Fail::from_args)?;
    line("the signature holds")
}

fn hex_arg(args: &Args, flag: &str) -> Result<Vec<u8>, Fail> {
    hex::decode(args.need(flag)?)
        .map_err(|e| Fail::usage(format!("{flag} must be lowercase hex: {e}")))
}

/// Time per Argon2id preset, and per seal and open of 1 KiB, on this machine.
/// A fixed test password and a random key; nothing is kept.
fn bench() -> Result<(), Fail> {
    let pw = krypto::SecretString::from_string("krypto-cli bench".into()).map_err(Fail::krypto)?;
    let mut report = String::new();
    for (name, preset) in [
        ("interactive", Preset::Interactive),
        ("balanced", Preset::Balanced),
        ("high", Preset::High),
    ] {
        let start = Instant::now();
        password::derive_key(&pw, &[0u8; 16], preset).map_err(Fail::krypto)?;
        let ms = start.elapsed().as_secs_f64() * 1e3;
        report += &format!("argon2id {name:<12} {ms:>9.1} ms\n");
    }

    const ROUNDS: u32 = 1000;
    let master = MasterKey::from_bytes(SecretBuf::random(32).map_err(Fail::krypto)?)
        .map_err(Fail::krypto)?;
    let key = master
        .derive(b"krypto-cli/bench", b"bench")
        .map_err(Fail::krypto)?;
    let id = master.key_id().map_err(Fail::krypto)?;
    let plaintext = SecretBuf::random(1024).map_err(Fail::krypto)?;
    let start = Instant::now();
    let mut blob = Vec::new();
    for _ in 0..ROUNDS {
        blob = seal(&key, &id, &plaintext, Alg::Aegis256).map_err(Fail::krypto)?;
    }
    let seal_us = start.elapsed().as_secs_f64() * 1e6 / f64::from(ROUNDS);
    let start = Instant::now();
    for _ in 0..ROUNDS {
        open(&key, &blob).map_err(Fail::krypto)?;
    }
    let open_us = start.elapsed().as_secs_f64() * 1e6 / f64::from(ROUNDS);
    report += &format!("seal aegis256 1 KiB {seal_us:>9.1} µs\n");
    report += &format!("open aegis256 1 KiB {open_us:>9.1} µs\n");
    out(report.as_bytes())
}

/// The most stdin may hold, so an endless stream is not buffered without end.
const MAX_STDIN: usize = 64 * 1024 * 1024;

/// The plaintext for `seal`, from stdin, without leaving copies of it behind
/// (FS-0014). It is read in chunks bigger than stdin's own buffer, which is then
/// passed by, into a buffer that is wiped whenever it grows (a `Vec` that grows
/// by itself frees the old buffer unwiped), and handed to locked memory at the
/// end, which wipes the last buffer too.
fn read_stdin_secret() -> Result<SecretBuf, Fail> {
    let mut chunk = Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut stdin = std::io::stdin().lock();
    loop {
        let n = match stdin.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Fail::io(format!("reading stdin failed: {e}"))),
        };
        if buf.len() + n > MAX_STDIN {
            return Err(Fail::usage(format!("stdin is more than {MAX_STDIN} bytes")));
        }
        if buf.len() + n > buf.capacity() {
            let size = (buf.len() + n).max(2 * buf.capacity());
            let mut bigger = Zeroizing::new(Vec::with_capacity(size));
            bigger.extend_from_slice(&buf);
            buf = bigger;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    SecretBuf::from_vec(std::mem::take(&mut *buf)).map_err(Fail::krypto)
}

/// Stdin that is not a secret: a blob, data to hash or MAC, a message.
fn read_stdin() -> Result<Vec<u8>, Fail> {
    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_STDIN as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|e| Fail::io(format!("reading stdin failed: {e}")))?;
    if input.len() > MAX_STDIN {
        return Err(Fail::usage(format!("stdin is more than {MAX_STDIN} bytes")));
    }
    Ok(input)
}

/// All output goes through here. A closed stdout, as when the reader is `head`,
/// is an I/O error (exit 1), never a panic.
fn out(bytes: &[u8]) -> Result<(), Fail> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|e| Fail::io(format!("writing to stdout failed: {e}")))
}

fn line(text: &str) -> Result<(), Fail> {
    out(format!("{text}\n").as_bytes())
}
