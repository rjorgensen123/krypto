//! Integration tests for `krypto-cli` — the contract a non-Rust caller builds
//! on. Spawns the built binary and verifies the stdin/stdout
//! pipe, roundtrips and exit codes.

use std::io::Write;
use std::process::{Command, Stdio};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_krypto-cli"))
}

fn master_key(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "krypto-cli-master-{}-{tag}.key",
        std::process::id()
    ));
    std::fs::write(&p, [3u8; 32]).unwrap();
    p
}

/// Run the cli with the given args + stdin, return (exit code, stdout).
fn run(args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>) {
    let mut child = cli()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap_or(-1), out.stdout)
}

#[test]
fn seal_open_roundtrip() {
    let key = master_key("rt");
    let plaintext = b"sensitive-audit-json";
    let (code, blob) = run(
        &[
            "seal",
            "--key-file",
            key.to_str().unwrap(),
            "--context",
            "example/audit/v1",
            "--salt",
            "audit",
        ],
        plaintext,
    );
    assert_eq!(code, 0, "seal should succeed");
    assert_eq!(&blob[..4], b"FAFN", "the blob should carry the FAFN magic");

    // open must return exactly the plaintext.
    let mut child = cli()
        .args([
            "open",
            "--key-file",
            key.to_str().unwrap(),
            "--context",
            "example/audit/v1",
            "--salt",
            "audit",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&blob).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, plaintext);
    let _ = std::fs::remove_file(&key);
}

#[test]
fn tampering_gives_exit_3() {
    // A blob with a flipped byte must give exit code 3 (auth/tampering), so
    // the bridge can tell tampering from usage errors.
    let key = master_key("tamper");
    let (_c, mut blob) = run(
        &[
            "seal",
            "--key-file",
            key.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        b"data",
    );
    let last = blob.len() - 1;
    blob[last] ^= 0x01;
    let (code, _) = run(
        &[
            "open",
            "--key-file",
            key.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        &blob,
    );
    assert_eq!(code, 3, "tampering should give exit 3");
    let _ = std::fs::remove_file(&key);
}

/// A blob sealed under a DIFFERENT master key is exit 4 (wrong key generation),
/// not exit 3 (tampering alarm) — new in 0.5.0.
#[test]
fn different_key_generation_gives_exit_4() {
    let key_a = master_key("gen-a");
    let key_b = std::env::temp_dir().join(format!(
        "krypto-cli-master-{}-gen-b.key",
        std::process::id()
    ));
    std::fs::write(&key_b, [4u8; 32]).unwrap(); // a different master key

    let (code, blob) = run(
        &[
            "seal",
            "--key-file",
            key_a.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        b"data",
    );
    assert_eq!(code, 0);

    let (code, _) = run(
        &[
            "open",
            "--key-file",
            key_b.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        &blob,
    );
    assert_eq!(
        code, 4,
        "an old/other key generation should give exit 4, not a tampering alarm"
    );
    let _ = std::fs::remove_file(&key_a);
    let _ = std::fs::remove_file(&key_b);
}

#[test]
fn unknown_command_gives_exit_2_without_hanging() {
    // A typo in the command name must fail FAST with exit 2, not hang on stdin.
    // (We send a closed stdin; a hang bug would time out on read_to_end anyway.)
    let key = master_key("badcmd");
    let (code, _) = run(&["sael", "--key-file", key.to_str().unwrap()], b"");
    assert_eq!(code, 2, "an unknown command should give usage-error code 2");
    let _ = std::fs::remove_file(&key);
}

#[test]
fn keyid_is_deterministic() {
    let key = master_key("kid");
    let (c1, id1) = run(&["keyid", "--key-file", key.to_str().unwrap()], b"");
    let (c2, id2) = run(&["keyid", "--key-file", key.to_str().unwrap()], b"");
    assert_eq!(c1, 0);
    assert_eq!(c2, 0);
    assert_eq!(
        id1, id2,
        "the key id should be deterministic for the same master"
    );
    assert_eq!(id1.len(), 33, "16 bytes hex + newline"); // 32 hex chars + \n
    let _ = std::fs::remove_file(&key);
}

// --------------------------------------------------------------------------- //
// The 0.5.0 bridge extension: signatures, key agreement, passwords, hash.
// --------------------------------------------------------------------------- //

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("krypto-cli-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

/// keygen → public → sign → verify roundtrip, plus tampering → exit 3.
fn keygen_sign_verify(alg: &str) {
    let key = tmp(&format!("kg-{alg}"));
    let (code, out) = run(
        &["keygen", "--alg", alg, "--out", key.to_str().unwrap()],
        b"",
    );
    assert_eq!(code, 0, "keygen {alg} should succeed");
    let public = String::from_utf8(out).unwrap().trim().to_string();
    assert!(!public.is_empty() && public.chars().all(|c| c.is_ascii_hexdigit()));

    // `public` must agree with what keygen printed.
    let (code, out2) = run(
        &["public", "--alg", alg, "--key-file", key.to_str().unwrap()],
        b"",
    );
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8(out2).unwrap().trim(), public);

    let (code, sig) = run(
        &["sign", "--alg", alg, "--key-file", key.to_str().unwrap()],
        b"the message",
    );
    assert_eq!(code, 0, "sign {alg} should succeed");
    let sig = String::from_utf8(sig).unwrap().trim().to_string();

    let (code, _) = run(
        &[
            "verify",
            "--alg",
            alg,
            "--public",
            &public,
            "--signature",
            &sig,
        ],
        b"the message",
    );
    assert_eq!(code, 0, "verify {alg} should succeed");

    let (code, _) = run(
        &[
            "verify",
            "--alg",
            alg,
            "--public",
            &public,
            "--signature",
            &sig,
        ],
        b"the messagE",
    );
    assert_eq!(code, 3, "a tampered message should give exit 3");
    let _ = std::fs::remove_file(&key);
}

#[test]
fn cli_ed25519_roundtrip() {
    keygen_sign_verify("ed25519");
}

#[test]
fn cli_p256_roundtrip() {
    keygen_sign_verify("p256");
}

#[test]
fn cli_keygen_refuses_overwrite() {
    let key = tmp("no-overwrite");
    let (code, _) = run(
        &["keygen", "--alg", "ed25519", "--out", key.to_str().unwrap()],
        b"",
    );
    assert_eq!(code, 0);
    let (code, _) = run(
        &["keygen", "--alg", "ed25519", "--out", key.to_str().unwrap()],
        b"",
    );
    assert_eq!(code, 1, "an existing key file must never be overwritten");
    let _ = std::fs::remove_file(&key);
}

/// Both sides derive the same shared key file, and it works as --key-file
/// for seal/open (the composition the bridge is designed around).
#[test]
fn cli_x25519_shared_composes_with_seal() {
    let a = tmp("x-a");
    let b = tmp("x-b");
    let (c1, a_pub) = run(
        &["keygen", "--alg", "x25519", "--out", a.to_str().unwrap()],
        b"",
    );
    let (c2, b_pub) = run(
        &["keygen", "--alg", "x25519", "--out", b.to_str().unwrap()],
        b"",
    );
    assert_eq!((c1, c2), (0, 0));
    let a_pub = String::from_utf8(a_pub).unwrap().trim().to_string();
    let b_pub = String::from_utf8(b_pub).unwrap().trim().to_string();

    let sa = tmp("x-shared-a");
    let sb = tmp("x-shared-b");
    let (c, _) = run(
        &[
            "shared",
            "--key-file",
            a.to_str().unwrap(),
            "--peer",
            &b_pub,
            "--out",
            sa.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(c, 0);
    let (c, _) = run(
        &[
            "shared",
            "--key-file",
            b.to_str().unwrap(),
            "--peer",
            &a_pub,
            "--out",
            sb.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(c, 0);
    assert_eq!(
        std::fs::read(&sa).unwrap(),
        std::fs::read(&sb).unwrap(),
        "both sides must derive the same shared key"
    );

    // The shared file is a usable master key: A seals, B opens.
    let (c, blob) = run(
        &[
            "seal",
            "--key-file",
            sa.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        b"envelope payload",
    );
    assert_eq!(c, 0);
    let mut child = cli()
        .args([
            "open",
            "--key-file",
            sb.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&blob).unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, b"envelope payload");
    for p in [&a, &b, &sa, &sb] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn cli_derive_key_is_deterministic_and_usable() {
    let k1 = tmp("dk-1");
    let k2 = tmp("dk-2");
    let salt = "00112233445566778899aabbccddeeff"; // 16 bytes, canonical hex
    for out in [&k1, &k2] {
        let (code, _) = run(
            &[
                "derive-key",
                "--salt",
                salt,
                "--preset",
                "interactive",
                "--out",
                out.to_str().unwrap(),
            ],
            b"correct horse\n", // the trailing newline is stripped
        );
        assert_eq!(code, 0);
    }
    let bytes = std::fs::read(&k1).unwrap();
    assert_eq!(bytes.len(), 32);
    assert_eq!(
        bytes,
        std::fs::read(&k2).unwrap(),
        "same password+salt+preset → same key"
    );
    let _ = std::fs::remove_file(&k1);
    let _ = std::fs::remove_file(&k2);
}

#[test]
fn cli_password_hash_and_verify() {
    let (code, phc) = run(&["password-hash", "--preset", "interactive"], b"hunter2\n");
    assert_eq!(code, 0);
    let phc = String::from_utf8(phc).unwrap().trim().to_string();
    assert!(phc.starts_with("$argon2id$"), "PHC: {phc}");

    let (code, _) = run(&["password-verify", "--phc", &phc], b"hunter2\n");
    assert_eq!(code, 0, "the right password should verify");
    let (code, _) = run(&["password-verify", "--phc", &phc], b"hunter3\n");
    assert_eq!(code, 3, "a wrong password should give exit 3");
}

#[test]
fn cli_sha256_known_answer() {
    let (code, out) = run(&["sha256"], b"abc");
    assert_eq!(code, 0);
    assert_eq!(
        String::from_utf8(out).unwrap().trim(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn cli_verify_rejects_uppercase_hex_as_usage_error() {
    // Canonical hex is lowercase; uppercase argv is a usage error (2), not auth.
    let (code, _) = run(
        &[
            "verify",
            "--alg",
            "ed25519",
            "--public",
            "AB",
            "--signature",
            "cd",
        ],
        b"m",
    );
    assert_eq!(code, 2);
}

#[test]
fn cli_blob_key_id_reads_generation_without_key() {
    let key = master_key("bki");
    let (code, blob) = run(
        &[
            "seal",
            "--key-file",
            key.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        b"data",
    );
    assert_eq!(code, 0);
    let (c1, kid) = run(&["keyid", "--key-file", key.to_str().unwrap()], b"");
    // No --key-file needed: the id sits in the public header.
    let (c2, bid) = run(&["blob-key-id"], &blob);
    assert_eq!((c1, c2), (0, 0));
    assert_eq!(
        kid, bid,
        "the blob must carry the master key's generation id"
    );
    let _ = std::fs::remove_file(&key);
}

#[test]
fn cli_version_prints_crate_version() {
    let (code, out) = run(&["version"], b"");
    assert_eq!(code, 0);
    assert_eq!(
        String::from_utf8(out).unwrap().trim(),
        env!("CARGO_PKG_VERSION")
    );
}

#[test]
fn cli_rand_prints_n_hex_bytes() {
    let (code, out) = run(&["rand", "--n", "16"], b"");
    assert_eq!(code, 0);
    let s = String::from_utf8(out).unwrap();
    let t = s.trim();
    assert_eq!(t.len(), 32, "16 bytes = 32 hex chars");
    assert!(t
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    // Two draws must differ — a CSPRNG that repeats is broken (or seeded).
    let (_, out2) = run(&["rand", "--n", "16"], b"");
    assert_ne!(s, String::from_utf8(out2).unwrap());
}

#[test]
fn cli_rand_rejects_zero_and_missing_n() {
    let (code, _) = run(&["rand", "--n", "0"], b"");
    assert_eq!(code, 2, "zero bytes is a usage error");
    let (code, _) = run(&["rand"], b"");
    assert_eq!(code, 2, "missing --n is a usage error");
}

#[test]
fn cli_reseal_rotates_a_blob_between_key_generations() {
    // Two distinct master keys.
    let old_key = master_key("rsl-old");
    let new_path = std::env::temp_dir().join(format!(
        "krypto-cli-master-{}-rsl-new.key",
        std::process::id()
    ));
    std::fs::write(&new_path, [5u8; 32]).unwrap();

    let seal_args = |key: &str| -> Vec<String> {
        vec![
            "seal".into(),
            "--key-file".into(),
            key.into(),
            "--context".into(),
            "c".into(),
            "--salt".into(),
            "s".into(),
        ]
    };
    let (code, blob) = run(
        &seal_args(old_key.to_str().unwrap())
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        b"rotate me",
    );
    assert_eq!(code, 0);

    // Rotate old → new.
    let (code, rotated) = run(
        &[
            "reseal",
            "--key-file",
            old_key.to_str().unwrap(),
            "--new-key-file",
            new_path.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        &blob,
    );
    assert_eq!(code, 0);

    // Opens under the new key; the old key now says exit 4 (wrong generation).
    let (code, pt) = run(
        &[
            "open",
            "--key-file",
            new_path.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        &rotated,
    );
    assert_eq!((code, pt.as_slice()), (0, b"rotate me".as_slice()));
    let (code, _) = run(
        &[
            "open",
            "--key-file",
            old_key.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        &rotated,
    );
    assert_eq!(code, 4, "old generation is routing (4), not tampering (3)");

    // Resealing with the WRONG old key is also exit 4 — point --key-file at
    // the generation the blob was actually sealed under.
    let (code, _) = run(
        &[
            "reseal",
            "--key-file",
            new_path.to_str().unwrap(),
            "--new-key-file",
            old_key.to_str().unwrap(),
            "--context",
            "c",
            "--salt",
            "s",
        ],
        &blob,
    );
    assert_eq!(code, 4);

    let _ = std::fs::remove_file(&old_key);
    let _ = std::fs::remove_file(&new_path);
}
