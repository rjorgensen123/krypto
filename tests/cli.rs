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

/// A blob that starts with `FAFN` but is cut short of its 54-byte header is a
/// changed blob: `open` gives exit 3 (0.9.0).
#[test]
fn open_of_a_blob_cut_short_in_its_header_is_exit_3() {
    let key = key_file("cut-open", 3);
    let k = key.to_str().unwrap();
    let m = master(3);
    let secret = SecretBuf::from_vec(b"x".to_vec()).unwrap();
    let blob = krypto::seal(
        &m.derive(b"c", b"s").unwrap(),
        &m.key_id().unwrap(),
        &secret,
        krypto::Alg::Aegis256,
    )
    .unwrap();
    for keep in [10, 53] {
        let out = run(&[&["open"][..], &flags(k)].concat(), &blob[..keep]);
        assert_eq!(out.code, 3, "{keep} bytes: {}", out.stderr);
    }
}

/// `inspect` tells what krypto made without a key, and never shows a hash
/// value; random bytes are only a length.
#[test]
fn inspect_tells_what_krypto_made() {
    let report = |input: &[u8]| {
        let out = run(&["inspect"], input);
        (out.code, text(&out))
    };
    let m = master(3);
    let key = m.derive(b"c", b"s").unwrap();
    let id = hex::encode(&m.key_id().unwrap()).unwrap();
    let secret = SecretBuf::from_vec(b"x".to_vec()).unwrap();
    let blob = krypto::seal(&key, &m.key_id().unwrap(), &secret, krypto::Alg::Aes256Gcm).unwrap();

    // A blob, as it is, in hex and in base64; a changed header is exit 3.
    for input in [
        blob.clone(),
        hex::encode(&blob).unwrap().into_bytes(),
        krypto::base64::encode(&blob).unwrap().into_bytes(),
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

/// `inspect` reports a blob that starts with `FAFN` but is cut short of its
/// 54-byte header as cut short, with exit 3, as for `open` (0.9.0).
#[test]
fn inspect_of_a_blob_cut_short_in_its_header_is_exit_3() {
    let m = master(3);
    let secret = SecretBuf::from_vec(b"x".to_vec()).unwrap();
    let blob = krypto::seal(
        &m.derive(b"c", b"s").unwrap(),
        &m.key_id().unwrap(),
        &secret,
        krypto::Alg::Aegis256,
    )
    .unwrap();
    for keep in [10, 53] {
        let out = run(&["inspect"], &blob[..keep]);
        let r = text(&out);
        assert_eq!(out.code, 3, "{keep} bytes: {r}");
        assert!(
            r.starts_with("krypto blob") && r.contains("header      cut short"),
            "{keep} bytes: {r}"
        );
    }
}

/// One entry of a store file, in the encoding v1 and v2 share: the name and a
/// FAFN blob sealed as the store seals it (the entry context is frozen at v1).
fn store_entry(
    m: &MasterKey,
    salt: &[u8; 16],
    key_id: &[u8; 16],
    name: &str,
    value: &[u8],
) -> Vec<u8> {
    let mut info = b"krypto/store/v1|".to_vec();
    info.extend_from_slice(name.as_bytes());
    let dek = m.derive(&info, salt).unwrap();
    let secret = SecretBuf::from_vec(value.to_vec()).unwrap();
    let blob = krypto::seal(&dek, key_id, &secret, krypto::Alg::Aegis256).unwrap();
    let mut entry = (name.len() as u16).to_le_bytes().to_vec();
    entry.extend_from_slice(name.as_bytes());
    entry.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    entry.extend_from_slice(&blob);
    entry
}

/// A store file built byte for byte as spec/SPEC-secretstore.md writes it:
/// version 1 (37-byte header) or 2 (109-byte header with key check, `counter`
/// and container MAC), holding one entry per name.
fn store_file(m: &MasterKey, ver: u8, counter: u64, names: &[&str]) -> Vec<u8> {
    let salt = [7u8; 16];
    let key_id = m.key_id().unwrap();
    let mut entries = Vec::new();
    for (i, name) in names.iter().enumerate() {
        entries.extend_from_slice(&store_entry(m, &salt, &key_id, name, &[i as u8]));
    }
    let mut head = b"FST1".to_vec();
    head.push(ver);
    head.extend_from_slice(&salt);
    head.extend_from_slice(&key_id);
    if ver == 2 {
        let k_check = m.derive(b"krypto/store/v2|key-check", &salt).unwrap();
        let k_mac = m.derive(b"krypto/store/v2|container-mac", &salt).unwrap();
        let mut key_check_in = b"FST1".to_vec();
        key_check_in.push(ver);
        key_check_in.extend_from_slice(&salt);
        head.extend_from_slice(&krypto::hmac_sha256(&k_check, &key_check_in).unwrap());
        head.extend_from_slice(&counter.to_le_bytes());
        let mut mac_in = head.clone();
        mac_in.extend_from_slice(&entries);
        head.extend_from_slice(&krypto::hmac_sha256(&k_mac, &mac_in).unwrap());
    }
    head.extend_from_slice(&entries);
    head
}

/// `inspect` reads a store file of either format version: v1 as before, and
/// v2's 109-byte header with its counter and the entries after it, the MACs
/// labeled present but not verified, since `inspect` runs without a key
/// (spec/SPEC-secretstore.md).
#[test]
fn inspect_reads_store_files_of_both_versions() {
    let report = |input: &[u8]| {
        let out = run(&["inspect"], input);
        (out.code, text(&out))
    };
    let m = master(3);
    let id = hex::encode(&m.key_id().unwrap()).unwrap();
    // The line of a report that starts with `name`, or the empty string.
    let line = |r: &str, name: &str| {
        r.lines()
            .find(|l| l.trim_start().starts_with(name))
            .unwrap_or("")
            .to_string()
    };

    // v1: the 37-byte header, unchanged.
    let v1 = store_file(&m, 1, 0, &["db/password"]);
    let (code, r) = report(&v1);
    assert_eq!(code, 0, "{r}");
    assert!(r.starts_with("krypto store file"), "{r}");
    assert!(line(&r, "format").ends_with("1"), "{r}");
    assert!(
        r.contains(&id) && r.contains("db/password") && line(&r, "entries").ends_with("1"),
        "{r}"
    );
    assert!(!r.contains("counter") && !r.contains("mac"), "{r}");

    // v2: format 2, key id, counter, the MAC labeled, and the entries.
    let v2 = store_file(&m, 2, 7, &["api-key", "db/password"]);
    let (code, r) = report(&v2);
    assert_eq!(code, 0, "{r}");
    assert!(r.starts_with("krypto store file"), "{r}");
    assert!(line(&r, "format").ends_with("2"), "{r}");
    assert!(r.contains(&id), "{r}");
    assert!(line(&r, "counter").ends_with("7"), "{r}");
    assert!(line(&r, "mac").contains("present, not verified"), "{r}");
    assert!(line(&r, "entries").ends_with("2"), "{r}");
    assert!(r.contains("api-key, db/password"), "{r}");
    assert!(line(&r, "algorithm").contains("AEGIS-256"), "{r}");

    // More names than shown: the first 20, then how many more there are.
    let many: Vec<String> = (0..25).map(|i| format!("k{i:02}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    let (_, r) = report(&store_file(&m, 2, 0, &refs));
    assert!(
        line(&r, "entries").ends_with("25") && r.contains("and 5 more"),
        "{r}"
    );

    // Cut short: a header that is not whole is "cut short", in both versions.
    // A v2 header cut short is a changed file, exit 3, as `SecretStore::open`
    // gives `Auth` for it; a v1 header cut short is `Format` there, exit 0.
    for (cut, want) in [(&v2[..100], 3), (&v1[..30], 0)] {
        let (code, r) = report(cut);
        assert_eq!(code, want, "{r}");
        assert!(r.contains("cut short"), "{r}");
    }

    // A version this krypto does not know is said so, and nothing past the
    // version byte is read.
    let mut unknown = v1.clone();
    unknown[4] = 3;
    let (code, r) = report(&unknown);
    assert_eq!(code, 0, "{r}");
    assert!(
        line(&r, "format").ends_with("3") && r.contains("unsupported store version 3"),
        "{r}"
    );
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

/// `inspect` shows the parameters of an Argon2i or Argon2d password hash both
/// with a `v=` field and without one, as older strings have, and not its salt.
#[test]
fn inspect_shows_argon2i_and_argon2d_parameters_with_or_without_a_version() {
    // base64 of "saltsaltsaltsalt" and of "an example hash, not a real one.",
    // without padding.
    const SALT: &str = "c2FsdHNhbHRzYWx0c2FsdA";
    const HASH: &str = "YW4gZXhhbXBsZSBoYXNoLCBub3QgYSByZWFsIG9uZS4";
    for (prefix, variant) in [("$argon2i$", "Argon2i"), ("$argon2d$", "Argon2d")] {
        for version in ["", "v=19$"] {
            let input = format!("{prefix}{version}m=65536,t=3,p=2${SALT}${HASH}");
            let out = run(&["inspect"], input.as_bytes());
            let report = text(&out);
            assert_eq!(out.code, 0, "{input}: {}", out.stderr);
            let what = format!("password hash (PHC string, {variant})");
            assert_eq!(report.lines().next(), Some(what.as_str()), "{report}");
            assert!(report.contains("parameters  m=65536,t=3,p=2"), "{report}");
            assert!(!report.contains(SALT), "the salt is shown: {report}");
        }
    }
}

/// `inspect` shows only printable ASCII (0.8.2): control characters a file
/// puts in a PGP armor label, a PHC version, an OpenSSH key's cipher and KDF,
/// the key type in an SSH key blob or an SSH signature's hash are left out and
/// counted, and cannot add a line to the report.
#[test]
fn inspect_shows_no_control_characters() {
    let string = |b: &[u8]| [&(b.len() as u32).to_be_bytes()[..], b].concat();
    let pem = |label: &str, body: Vec<u8>| {
        let body = krypto::base64::encode(&body).unwrap();
        format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n").into_bytes()
    };
    let key = [string(b"ssh-ed25519"), string(&[7; 32])].concat();
    let hostile_key = [string(b"ssh-ed25519\x1b]0;owned\x07"), string(&[7; 32])].concat();
    // Each input, the marker its report must carry, and the start of a line
    // the input tries to add.
    let inputs: [(Vec<u8>, &str, Option<&str>); 6] = [
        (
            b"-----BEGIN PGP X\x1b[2J\r  cipher      none (not encrypted)-----\n\n\
              dGVzdA==\n-----END PGP X-----\n"
                .to_vec(),
            "[2 characters not shown]",
            Some("cipher"),
        ),
        (
            b"$argon2id$v=19\x1b[31m\n  injected    true$m=65536,t=3,p=2$c2FsdA$aGFzaA".to_vec(),
            "[2 characters not shown]",
            Some("injected"),
        ),
        (
            format!(
                "ssh-ed25519 {} comment",
                krypto::base64::encode(&hostile_key).unwrap()
            )
            .into_bytes(),
            "[2 characters not shown]",
            None,
        ),
        (
            pem(
                "OPENSSH PRIVATE KEY",
                [
                    &b"openssh-key-v1\0"[..],
                    &string(b"aes\x1b[2J"),
                    &string(b"bcrypt\r\n  keys        99"),
                    &string(b""),
                    &1u32.to_be_bytes(),
                    &string(&key),
                ]
                .concat(),
            ),
            "[3 characters not shown]",
            Some("keys        99"),
        ),
        (
            pem(
                "SSH SIGNATURE",
                [
                    &b"SSHSIG"[..],
                    &1u32.to_be_bytes(),
                    &string(&key),
                    &string(b"file"),
                    &string(b""),
                    &string(b"sha512\x1b]52;c;ZXhhbXBsZQ==\x07"),
                ]
                .concat(),
            ),
            "[2 characters not shown]",
            None,
        ),
        (
            b"$argon2id$v=19\x07$m=65536,t=3,p=2$c2FsdA$aGFzaA".to_vec(),
            "[1 character not shown]",
            None,
        ),
    ];
    for (input, marker, forged) in inputs {
        let out = run(&["inspect"], &input);
        let shown = String::from_utf8_lossy(&out.stdout)
            .escape_debug()
            .to_string();
        assert_eq!(out.code, 0, "{shown}: {}", out.stderr);
        assert!(
            out.stdout
                .iter()
                .all(|&b| (b >= 0x20 || b == b'\n') && b != 0x7f),
            "a control character reaches stdout: {shown}"
        );
        let report = text(&out);
        assert!(report.contains(marker), "no {marker}: {shown}");
        if let Some(forged) = forged {
            assert!(
                !report.lines().any(|l| l.trim_start().starts_with(forged)),
                "the input added a line: {shown}"
            );
        }
    }
}

/// `inspect` reads a crafted file right or says what in it is invalid, never
/// with a panic or a made-up value (0.8.2): an OID part with a leading 0x80,
/// an OID whose last part is not closed and an empty OID are `invalid OID`, a
/// part too long for 64 bits is `OID too long to show`, PEM inside PEM is
/// unwrapped at most two levels deep as hex is, and the report notes where
/// that limit stops it, an S2K count is read from its own byte when a session
/// key follows, and a WinZip AES strength from the AES extra field.
#[test]
fn inspect_reads_crafted_files_right_or_says_invalid() {
    let der = |h: &str| hex::decode(h).unwrap();
    let pem = |body: &[u8]| {
        let body = krypto::base64::encode(body).unwrap();
        format!("-----BEGIN X-----\n{body}\n-----END X-----\n").into_bytes()
    };
    let ed25519 = der("300a300506032b6570030100");
    let hex3 = hex::encode(
        hex::encode(hex::encode(&ed25519).unwrap().as_bytes())
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    const TOO_DEEP: &str = "note        stopped at the limit of two levels of unwrapping";
    // A local zip header, encrypted with method 99, whose first extra field
    // holds the bytes 01 99 before the AES extra field with strength 3.
    let zip = [
        &b"PK\x03\x04\x14\x00\x01\x00\x63\x00"[..],
        &[0; 16],
        &[1, 0, 20, 0],
        b"a",
        &der("555405000301990000"),
        &der("0199070002004145030800"),
    ]
    .concat();
    // Each input, the first line of its report, and what the report must hold.
    let inputs: [(Vec<u8>, &str, &str); 12] = [
        (
            der("300a30040602800004020000"),
            "encrypted private key (PKCS#8)",
            "scheme      invalid OID",
        ),
        (
            der("3009300406028010030100"),
            "public key (SubjectPublicKeyInfo)",
            "algorithm   invalid OID",
        ),
        (
            der("300b300606042b806570030100"),
            "public key (SubjectPublicKeyInfo)",
            "algorithm   invalid OID",
        ),
        (
            der("300b300606042b657081030100"),
            "public key (SubjectPublicKeyInfo)",
            "algorithm   invalid OID",
        ),
        (
            der("300730020600030100"),
            "public key (SubjectPublicKeyInfo)",
            "algorithm   invalid OID",
        ),
        (
            der("3011300c060a82808080808080808000030100"),
            "public key (SubjectPublicKeyInfo)",
            "algorithm   OID too long to show",
        ),
        (
            der("3012300d060b2b82808080808080808000030100"),
            "public key (SubjectPublicKeyInfo)",
            "algorithm   OID too long to show",
        ),
        (
            pem(&pem(&ed25519)),
            "public key (SubjectPublicKeyInfo)",
            "algorithm   Ed25519",
        ),
        (pem(&pem(&pem(&ed25519))), "PEM block: X", TOO_DEEP),
        (hex3.into_bytes(), "not recognized", TOO_DEEP),
        (
            der("c31e04090308010203040506070860a1a2a3a4a5a6a7a8a9aaabacadaeafb0ff"),
            "OpenPGP encrypted message",
            "iterated and salted SHA-256, 65536 bytes",
        ),
        (zip, "zip archive", "encrypted   AES-256 (WinZip AE)"),
    ];
    for (input, what, holds) in inputs {
        let out = run(&["inspect"], &input);
        let report = text(&out);
        assert_eq!(out.code, 0, "{what}: {}", out.stderr);
        assert_eq!(report.lines().next(), Some(what), "{report}");
        assert!(report.contains(holds), "no {holds}: {report}");
        assert_eq!(report.contains(TOO_DEEP), holds == TOO_DEEP, "{report}");
    }
}

/// `inspect` reads at most 4096 elements in one structure (0.9.0): at the
/// limit the report is as before; one DER element or OpenPGP packet more is
/// exit 1, one message on stderr and no report, also for a structure inside
/// another and under hex; an OID of one arc more is `OID too long to show`,
/// and the report goes on with exit 0.
#[test]
fn inspect_reads_at_most_4096_elements_in_one_structure() {
    // A DER element with a four-byte length, which `inspect` reads.
    let tlv = |tag: u8, body: &[u8]| {
        [&[tag, 0x84][..], &(body.len() as u32).to_be_bytes(), body].concat()
    };
    // An Ed25519 PKCS#8 key of `n` elements: version, algorithm, key, NULLs.
    let pkcs8 = |n: usize| {
        let head =
            hex::decode(&format!("020100300506032b657004220420{}", "00".repeat(32))).unwrap();
        tlv(0x30, &[head, b"\x05\x00".repeat(n - 3)].concat())
    };
    // `n` OpenPGP packets: an Ed25519 signature over SHA-256, then empty ones.
    let pgp = |n: usize| {
        [
            hex::decode("c20404001b08").unwrap(),
            b"\xc2\x00".repeat(n - 1),
        ]
        .concat()
    };
    // A public key whose algorithm is an OID of `n` arcs: 0.1, then 1s.
    let spki = |n: usize| {
        let alg = tlv(0x30, &tlv(0x06, &vec![1; n - 1]));
        tlv(0x30, &[alg, vec![3, 1, 0]].concat())
    };
    // A public key whose algorithm holds the Ed25519 OID and 4096 NULLs.
    let alg = tlv(
        0x30,
        &[tlv(0x06, &[0x2b, 0x65, 0x70]), b"\x05\x00".repeat(4096)].concat(),
    );
    let nested = hex::encode(&tlv(0x30, &[alg, vec![3, 1, 0]].concat())).unwrap();

    let shown = |what: &str| format!("algorithm   {what}");
    let inputs = [
        (pkcs8(4096), "private key (PKCS#8)", shown("Ed25519")),
        (pgp(4096), "OpenPGP signature", shown("Ed25519")),
        (
            spki(4096),
            "public key (SubjectPublicKeyInfo)",
            shown(&format!("0{}", ".1".repeat(4095))),
        ),
        (
            spki(4097),
            "public key (SubjectPublicKeyInfo)",
            shown("OID too long to show"),
        ),
    ];
    for (input, what, holds) in inputs {
        let out = run(&["inspect"], &input);
        let report = text(&out);
        assert_eq!(out.code, 0, "{what}: {}", out.stderr);
        assert_eq!(report.lines().next(), Some(what), "{report}");
        assert!(
            report.lines().any(|l| l.trim_start() == holds),
            "no {holds}: {report}"
        );
    }

    let der = "inspect reads at most 4096 elements in one DER structure; the input has more";
    let packets = "inspect reads at most 4096 OpenPGP packets; the input has more";
    for (input, message) in [
        (pkcs8(4097), der),
        (nested.into_bytes(), der),
        (pgp(4097), packets),
    ] {
        let out = run(&["inspect"], &input);
        assert_eq!(out.code, 1, "{}", out.stderr);
        assert!(out.stdout.is_empty(), "a report: {}", text(&out));
        assert_eq!(out.stderr.matches(message).count(), 1, "{}", out.stderr);
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

/// `verify` takes `--public` of at most 130 characters and `--signature` of
/// at most 144, the hex of a 65-byte P-256 point and a 72-byte P-256
/// signature (0.9.0): at the limits a signature verifies, and one character
/// more is a wrong call whose message names the flag and the limit. The help
/// of `verify` gives both limits.
#[test]
fn verify_bounds_public_and_signature() {
    let (private, public) = krypto::sign::ecdsa_p256_keypair().unwrap();
    // About one signature in four has the longest DER form.
    let (message, sig) = (0u32..256)
        .map(|i| format!("message {i}").into_bytes())
        .map(|m| {
            let sig = krypto::sign::ecdsa_p256_sign(&private, &m).unwrap();
            (m, sig)
        })
        .find(|(_, sig)| sig.len() == 72)
        .expect("no signature of the longest form in 256 messages");
    let public = hex::encode(&public).unwrap();
    let sig = hex::encode(&sig).unwrap();
    assert_eq!((public.len(), sig.len()), (130, 144));
    let verify = |public: &str, sig: &str| {
        let args = [
            "verify",
            "--alg",
            "p256",
            "--public",
            public,
            "--signature",
            sig,
        ];
        run(&args, &message)
    };

    let out = verify(&public, &sig);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let out = verify(&format!("{public}0"), &sig);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(
        out.stderr.contains("--public takes at most 130 characters"),
        "{}",
        out.stderr
    );
    let out = verify(&public, &format!("{sig}0"));
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(
        out.stderr
            .contains("--signature takes at most 144 characters"),
        "{}",
        out.stderr
    );

    let help = text(&run(&["verify", "--help"], b""));
    assert!(
        help.contains("at most 130") && help.contains("at most 144"),
        "{help}"
    );
}
