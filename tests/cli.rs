// SPDX-License-Identifier: MIT OR Apache-2.0
//! `krypto-cli`, the helper (0.8.0): each command does what it says and gives
//! what the crate gives, the exit codes tell the kinds of failure apart, and a
//! failure is a message, never a panic or a hang.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use krypto::{hex, sign, MasterKey, SecretBuf};

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

#[test]
fn seal_and_open_for_every_algorithm_as_the_crate_does() {
    let key = key_file("roundtrip", 3);
    let k = key.to_str().unwrap();
    let derived = master(3).derive(b"example/audit/v1", b"audit").unwrap();
    for alg in ["aegis256", "xchacha20", "aes256gcm"] {
        let sealed = run(
            &[
                "seal",
                "--key-file",
                k,
                "--context",
                "example/audit/v1",
                "--salt",
                "audit",
                "--alg",
                alg,
            ],
            b"sensitive-audit-json",
        );
        assert_eq!(sealed.code, 0, "seal {alg}: {}", sealed.stderr);
        krypto::open(&derived, &sealed.stdout)
            .unwrap()
            .expose(|b| assert_eq!(b, b"sensitive-audit-json", "the crate opens {alg}"));
        let opened = run(
            &[
                "open",
                "--key-file",
                k,
                "--context",
                "example/audit/v1",
                "--salt",
                "audit",
            ],
            &sealed.stdout,
        );
        assert_eq!(opened.code, 0, "open {alg}: {}", opened.stderr);
        assert_eq!(opened.stdout, b"sensitive-audit-json");
    }
    // A plaintext bigger than the chunks seal reads in, so its buffer grows.
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let flags = ["--key-file", k, "--context", "c", "--salt", "s"];
    let sealed = run(&[&["seal"][..], &flags].concat(), &big);
    assert_eq!(sealed.code, 0, "{}", sealed.stderr);
    assert_eq!(
        run(&[&["open"][..], &flags].concat(), &sealed.stdout).stdout,
        big
    );
}

#[test]
fn tampering_gives_exit_3() {
    let key = key_file("tamper", 3);
    let k = key.to_str().unwrap();
    let flags = ["--key-file", k, "--context", "c", "--salt", "s"];
    let sealed = run(&[&["seal"][..], &flags].concat(), b"x");
    assert_eq!(sealed.code, 0, "{}", sealed.stderr);
    let mut blob = sealed.stdout;
    let last = blob.len() - 1;
    blob[last] ^= 1;
    let opened = run(&[&["open"][..], &flags].concat(), &blob);
    assert_eq!(
        opened.code, 3,
        "tampering must be exit 3: {}",
        opened.stderr
    );
}

#[test]
fn another_key_generation_gives_exit_4() {
    let (old, new) = (key_file("gen-old", 3), key_file("gen-new", 4));
    let sealed = run(
        &[
            "seal",
            "--key-file",
            old.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        b"x",
    );
    assert_eq!(sealed.code, 0, "{}", sealed.stderr);
    let opened = run(
        &[
            "open",
            "--key-file",
            new.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        &sealed.stdout,
    );
    assert_eq!(
        opened.code, 4,
        "another generation must be exit 4: {}",
        opened.stderr
    );
}

#[test]
fn inspect_reads_the_header_without_a_key() {
    let key = key_file("inspect", 3);
    let sealed = run(
        &[
            "seal",
            "--key-file",
            key.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
            "--alg",
            "xchacha20",
        ],
        b"x",
    );
    assert_eq!(sealed.code, 0, "{}", sealed.stderr);
    let id = hex::encode(&master(3).key_id().unwrap());
    let inspected = run(&["inspect"], &sealed.stdout);
    assert_eq!(inspected.code, 0, "{}", inspected.stderr);
    assert_eq!(
        text(&inspected),
        format!(
            "format 1\nalgorithm xchacha20\nkey-id {id}\nbytes {}",
            sealed.stdout.len()
        )
    );
    assert_eq!(
        run(&["inspect"], b"not a blob").code,
        1,
        "not a blob is exit 1"
    );
}

#[test]
fn keyid_mac_and_sha256_give_what_the_crate_gives() {
    let key = key_file("values", 3);
    let k = key.to_str().unwrap();
    let keyid = run(&["keyid", "--key-file", k], b"");
    assert_eq!(text(&keyid), hex::encode(&master(3).key_id().unwrap()));
    let mac = run(
        &["mac", "--key-file", k, "--context", "c", "--salt", "s"],
        b"data",
    );
    let expected = krypto::hmac_sha256(&master(3).derive(b"c", b"s").unwrap(), b"data").unwrap();
    assert_eq!(text(&mac), hex::encode(&expected));
    let sha = run(&["sha256"], b"abc");
    assert_eq!(
        text(&sha),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn verify_says_whether_a_signature_holds() {
    let (seed, public) = sign::ed25519_keypair().unwrap();
    let ed = sign::ed25519_sign(&seed, b"message").unwrap();
    let (pkcs8, p256_public) = sign::ecdsa_p256_keypair().unwrap();
    let p256 = sign::ecdsa_p256_sign(&pkcs8, b"message").unwrap();
    for (alg, public, sig) in [
        ("ed25519", hex::encode(&public), hex::encode(&ed)),
        ("p256", hex::encode(&p256_public), hex::encode(&p256)),
    ] {
        let args = [
            "verify",
            "--alg",
            alg,
            "--public",
            &public,
            "--signature",
            &sig,
        ];
        let holds = run(&args, b"message");
        assert_eq!(holds.code, 0, "{alg}: {}", holds.stderr);
        assert_eq!(text(&holds), "the signature holds");
        assert_eq!(
            run(&args, b"messagE").code,
            3,
            "{alg}: a changed message is exit 3"
        );
    }
}

/// A wrong call is exit 2, reported before stdin is read: stdin is left open
/// here, so a command that waited for it would hang until the deadline. A
/// token in the wrong place is never repeated back.
#[test]
fn a_wrong_call_is_exit_2_at_once_and_repeats_nothing() {
    let key = key_file("wrong-call", 3);
    let k = key.to_str().unwrap();
    let calls: [&[&str]; 7] = [
        &["sael"],
        &["sha256", "hunter2-secret"],
        &["sha256", "--key-file", k],
        &["seal", "--key-file", k, "--context", "", "--salt", "s"],
        &[
            "seal",
            "--key-file",
            k,
            "--context",
            "c",
            "--salt",
            "s",
            "--alg",
            "rot13",
        ],
        &[
            "verify",
            "--alg",
            "x25519",
            "--public",
            "00",
            "--signature",
            "00",
        ],
        &["mac", "--key-file"],
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
}

/// A reader that goes away, as `head` does, is exit 1 with a message, never a
/// panic (exit 101).
#[test]
fn a_closed_stdout_is_exit_1_not_a_panic() {
    let mut child = cli()
        .arg("sha256")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take());
    child.stdin.take().unwrap().write_all(b"abc").unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("writing to stdout failed"), "{stderr}");
}

#[test]
fn bench_times_each_preset_and_seal_and_open() {
    let bench = run(&["bench"], b"");
    assert_eq!(bench.code, 0, "{}", bench.stderr);
    let report = text(&bench);
    for row in [
        "argon2id interactive",
        "argon2id balanced",
        "argon2id high",
        "seal aegis256",
        "open aegis256",
    ] {
        assert!(report.contains(row), "{row} is missing from:\n{report}");
    }
}

#[test]
fn version_and_help() {
    let version = run(&["version"], b"");
    assert_eq!(
        (version.code, text(&version)),
        (0, krypto::VERSION.to_string())
    );
    let help = run(&["--help"], b"");
    assert_eq!(help.code, 0);
    let help = text(&help);
    for command in [
        "version", "inspect", "keyid", "seal", "open", "mac", "sha256", "verify", "bench",
    ] {
        assert!(help.contains(command), "--help does not name {command}");
    }
    assert!(
        help.contains("<command> --help") && help.contains("exit codes"),
        "{help}"
    );
    // Each command's own help, also after other flags, and before any is checked.
    let seal = run(&["seal", "--key-file", "x", "--help"], b"");
    assert_eq!(seal.code, 0);
    for flag in ["--key-file", "--context", "--salt", "--alg", "aes256gcm"] {
        assert!(
            text(&seal).contains(flag),
            "seal --help does not name {flag}"
        );
    }
    assert!(text(&run(&["verify", "-h"], b"")).contains("ed25519, or p256"));
}
