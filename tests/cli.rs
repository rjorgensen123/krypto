// SPDX-License-Identifier: MIT OR Apache-2.0
//! `krypto-cli`, the tool for testing (0.8.0): seal and open as the crate does,
//! with exit codes that tell the kinds of failure apart; inspect recognizes what
//! it is given; and a wrong call is exit 2.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use krypto::{hex, MasterKey, SecretBuf};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_krypto-cli"))
}

/// A master key file holding 32 bytes of `byte`.
fn key_file(tag: &str, byte: u8) -> PathBuf {
    let p = std::env::temp_dir().join(format!("krypto-cli-{}-{tag}.key", std::process::id()));
    std::fs::write(&p, [byte; 32]).unwrap();
    p
}

/// The same key as `key_file(_, byte)`, in the crate.
fn master(byte: u8) -> MasterKey {
    MasterKey::from_bytes(SecretBuf::from_vec(vec![byte; 32]).unwrap()).unwrap()
}

struct Out {
    code: i32,
    stdout: Vec<u8>,
    stderr: String,
}

/// Run with `args`, write `stdin` and close it. A command that fails before
/// reading stdin may be gone already; that is a broken pipe here, not a failure.
fn run(args: &[&str], stdin: &[u8]) -> Out {
    let mut child = cli()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut pipe = child.stdin.take().unwrap();
    match pipe.write_all(stdin) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
        Err(e) => panic!("writing to krypto-cli's stdin: {e}"),
    }
    drop(pipe);
    let out = child.wait_with_output().unwrap();
    Out {
        code: out.status.code().unwrap_or(-1),
        stdout: out.stdout,
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn text(out: &Out) -> String {
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .trim_end()
        .to_string()
}

/// The flags `seal`, `open` and `mac` need, for the key file `k`.
fn flags(k: &str) -> [&str; 6] {
    ["--key-file", k, "--context", "c", "--salt", "s"]
}

/// What `seal` makes, the crate and `open` open; a changed blob is exit 3, and
/// a blob from another key generation is exit 4. The plaintext is bigger than
/// the chunks `seal` reads in, so its buffer grows.
#[test]
fn seal_and_open_with_their_exit_codes() {
    let (key, other) = (key_file("key", 3), key_file("other", 4));
    let (k, o) = (key.to_str().unwrap(), other.to_str().unwrap());
    let open = |k, blob: &[u8]| run(&[&["open"][..], &flags(k)].concat(), blob);
    let derived = master(3).derive(b"c", b"s").unwrap();
    let plaintext: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    for alg in ["aegis256", "xchacha20", "aes256gcm"] {
        let sealed = run(
            &[&["seal", "--alg", alg][..], &flags(k)].concat(),
            &plaintext,
        );
        assert_eq!(sealed.code, 0, "seal {alg}: {}", sealed.stderr);
        krypto::open(&derived, &sealed.stdout)
            .unwrap()
            .expose(|b| assert!(b == plaintext, "the crate opens {alg}"));
        let opened = open(k, &sealed.stdout);
        assert_eq!(opened.code, 0, "open {alg}: {}", opened.stderr);
        assert!(opened.stdout == plaintext, "open {alg}");

        let mut changed = sealed.stdout.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert_eq!(open(k, &changed).code, 3, "changed: {alg}");
        assert_eq!(open(o, &sealed.stdout).code, 4, "other key: {alg}");
    }
}

/// `inspect` tells what krypto made without a key, and never shows a hash
/// value; random bytes are only a length (FS-0056).
#[test]
fn inspect_tells_what_krypto_made() {
    let report = |input: &[u8]| {
        let out = run(&["inspect"], input);
        (out.code, text(&out))
    };
    let m = master(3);
    let key = m.derive(b"c", b"s").unwrap();
    let id = hex::encode(&m.key_id().unwrap());
    let secret = SecretBuf::from_vec(b"x".to_vec()).unwrap();
    let blob = krypto::seal(&key, &m.key_id().unwrap(), &secret, krypto::Alg::Aes256Gcm).unwrap();

    // A blob, as it is, in hex and in base64; a changed header is exit 3.
    for input in [
        blob.clone(),
        hex::encode(&blob).into_bytes(),
        krypto::base64::encode(&blob).into_bytes(),
    ] {
        let (code, r) = report(&input);
        assert_eq!(code, 0, "{r}");
        assert!(
            r.starts_with("krypto blob") && r.contains("AES-256-GCM") && r.contains(&id),
            "{r}"
        );
    }
    let mut changed = blob.clone();
    changed[5] = 9;
    assert_eq!(
        report(&changed).0,
        3,
        "a changed header is exit 3, as for open"
    );

    // A store file.
    let dir = std::env::temp_dir().join(format!("krypto-cli-inspect-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s.store");
    {
        let mut store = krypto::SecretStore::open(&path, &m).unwrap();
        store.put("db/password", &secret).unwrap();
    }
    let file = std::fs::read(&path).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let (_, r) = report(&file);
    assert!(
        r.starts_with("krypto store file") && r.contains("db/password"),
        "{r}"
    );

    // A password hash and its preset; the hash value is not shown.
    let phc = krypto::password::hash(
        &krypto::SecretString::from_string("hunter2".into()).unwrap(),
        krypto::password::Preset::Interactive,
    )
    .unwrap();
    let (_, r) = report(phc.as_bytes());
    assert!(r.contains("Argon2id") && r.contains("interactive"), "{r}");
    assert!(
        !r.contains(phc.rsplit('$').next().unwrap()),
        "the hash value is shown: {r}"
    );

    // Bytes that only look like the start of an OpenPGP packet are not one.
    for start in [&b"\x87"[..], b"\x8f", b"\xa3", b"\xa7", b"\xd2\xe0"] {
        let mut input = start.to_vec();
        input.resize(32, 1);
        let (_, r) = report(&input);
        assert!(r.starts_with("32 bytes"), "{r}");
    }
    let (code, r) = report(b"hello world");
    assert_eq!((code, r.starts_with("not recognized")), (0, true), "{r}");
}

/// `inspect` recognizes the files the common tools made (`openssl`, `gpg`,
/// `ssh-keygen`, Python's standard library and `cryptography`), in
/// `tests/fixtures/inspect`, and repeats no line of a PEM body.
#[test]
fn inspect_tells_what_others_made() {
    const EXPECTED: &[(&str, &str)] = &[
        ("bundle.p12", "PKCS#12 bundle (PFX)"),
        ("cert-p256.der", "X.509 certificate"),
        ("cert-p256.pem", "X.509 certificate"),
        ("cert-rsa.pem", "X.509 certificate"),
        ("cms-enveloped.der", "CMS enveloped data (S/MIME, PKCS#7)"),
        ("cms-signed.der", "CMS signed data (S/MIME, PKCS#7)"),
        ("csr-p256.pem", "certificate signing request (PKCS#10)"),
        ("data.bz2", "bzip2 compressed data"),
        ("data.gz", "gzip compressed data"),
        ("data.tar", "tar archive"),
        ("data.xz", "xz compressed data"),
        ("data.zip", "zip archive"),
        ("data.zst", "zstd compressed data"),
        ("ec-p256.pkcs8.pem", "ECDSA P-256 private key (PKCS#8, DER)"),
        ("ec-p384.sec1.pem", "EC private key (SEC1)"),
        ("ed25519.pkcs8.pem", "private key (PKCS#8)"),
        ("fernet.txt", "Fernet token"),
        ("openssl-enc.bin", "OpenSSL enc file (salted)"),
        ("pgp-message.asc", "OpenPGP encrypted message"),
        ("pgp-message.bin", "OpenPGP encrypted message"),
        ("pgp-public.asc", "OpenPGP public key"),
        ("pgp-public.bin", "OpenPGP public key"),
        ("pgp-signature.asc", "OpenPGP signature"),
        ("pgp-signature.sig", "OpenPGP signature"),
        ("pgp-symmetric.bin", "OpenPGP encrypted message"),
        ("rsa-2048.enc-pkcs8.pem", "encrypted private key (PKCS#8)"),
        ("rsa-2048.pkcs1-encrypted.pem", "RSA private key (PKCS#1)"),
        ("rsa-2048.pkcs1-public.pem", "RSA public key (PKCS#1)"),
        ("rsa-2048.pkcs1.pem", "RSA private key (PKCS#1)"),
        ("rsa-2048.pkcs8.pem", "private key (PKCS#8)"),
        ("rsa-2048.spki.pem", "public key (SubjectPublicKeyInfo)"),
        ("ssh-ed25519", "OpenSSH private key"),
        ("ssh-ed25519-encrypted", "OpenSSH private key"),
        ("ssh-ed25519.pub", "OpenSSH public key"),
        ("ssh-rsa.pub", "OpenSSH public key"),
        ("ssh-signature.sig", "SSH signature (ssh-keygen -Y sign)"),
        ("ssh2-rsa.pub", "SSH2 public key (RFC 4716)"),
    ];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/inspect");
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "README.md")
        .collect();
    files.sort();
    let named: Vec<&str> = EXPECTED.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        files, named,
        "every fixture needs its expectation, and only those"
    );
    for (name, what) in EXPECTED {
        let input = std::fs::read(dir.join(name)).unwrap();
        let out = run(&["inspect"], &input);
        let report = text(&out);
        assert_eq!(out.code, 0, "{name}: {}", out.stderr);
        assert_eq!(report.lines().next(), Some(*what), "{name}");
        if let Ok(pem) = std::str::from_utf8(&input) {
            for line in pem.lines().filter(|l| l.len() >= 20 && !l.contains(' ')) {
                assert!(
                    !report.contains(line),
                    "{name}: a line of the input is repeated"
                );
            }
        }
    }
}

/// A wrong call is exit 2, reported before stdin is read: stdin is left open
/// here, so a command that waited for it would hang until the deadline. A
/// token in the wrong place is never repeated back. `--help` and `version` work.
#[test]
fn a_wrong_call_is_exit_2_and_help_works() {
    let key = key_file("wrong-call", 3);
    let k = key.to_str().unwrap();
    let calls: [&[&str]; 3] = [
        &["sael"],
        &["sha256", "hunter2-secret"],
        &["seal", "--key-file", k, "--context", "", "--salt", "s"],
    ];
    for args in calls {
        let mut child = cli()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                panic!("{args:?} waited for stdin instead of failing");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(status.code(), Some(2), "{args:?}: {stderr}");
        assert!(
            !stderr.contains("hunter2"),
            "{args:?} repeated a token: {stderr}"
        );
    }

    let help = run(&["--help"], b"");
    assert_eq!(help.code, 0);
    assert!(text(&help).contains("exit codes"), "{}", text(&help));
    let version = run(&["version"], b"");
    assert_eq!(
        (version.code, text(&version)),
        (0, krypto::VERSION.to_string())
    );
}
