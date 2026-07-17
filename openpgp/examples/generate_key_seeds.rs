//! Generates structured seed corpora for the OpenPGP fuzz targets.
//!
//! This example is a developer utility for creating small, valid, semantically
//! interesting seed inputs for `cargo fuzz`.  Rather than committing many binary
//! corpus files to the repository, we commit this generator and (re)produce the
//! seeds on demand — locally or in CI, before a `cargo fuzz run ... -runs=0`
//! regression replay.
//!
//! Run this from the repository root with:
//!
//! `cargo run -p sequoia-openpgp --example generate_key_seeds`
//!
//! Use this when adding a new fuzz target, refreshing a seed corpus, or
//! regenerating corpus files after changing how the inputs are constructed.
//!
//! The seeds are intentionally small and structured: they give each fuzz target
//! a valid OpenPGP object to start mutating from.  They are *not* a substitute
//! for committed regression reproducers (minimized inputs from real fixed bugs),
//! which live alongside them in `fuzz/corpus/<target>/` and are preserved here
//! because this generator only ever writes its own distinctly-named files.
//!
//! Note: seeds do not need to cryptographically verify.  Every stream-based
//! fuzz target keeps its input regardless of whether verification/decryption
//! succeeds — the property under test is "must not panic" — so we sign and
//! encrypt with a freshly generated key whose secret we hold.
//!
//! Target coverage:
//!
//! - `cert_from_bytes`               cert (public, secret/TSK, armored)
//! - `key_packet_from_bytes`         primary/subkey packets (public + secret)
//! - `rawcert_from_bytes`            binary cert, binary keyring
//! - `cert_parser_from_bytes`        armored cert, binary cert, binary keyring
//! - `cert_parser_binary_from_bytes` binary cert, binary keyring
//! - `message_from_bytes`            literal, inline-signed, encrypted messages
//! - `packet_pile_from_bytes`        secret cert + inline-signed + encrypted
//! - `inline_verify_from_bytes`      inline-signed message
//! - `csf_verify_from_bytes`         cleartext-signed message (CSF)
//! - `decrypt_from_bytes`            encrypted message

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use sequoia_openpgp as openpgp;

use openpgp::cert::prelude::*;
use openpgp::packet::Packet;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::Serialize;
use openpgp::serialize::stream::*;

const P: &StandardPolicy = &StandardPolicy::new();
const MESSAGE: &[u8] = b"sequoia fuzz seed corpus message";

/// Base corpus directory.  Defaults to the in-tree `openpgp/fuzz/corpus`, but
/// `./fuzz-all.sh` sets `FUZZ_CORPUS_OUT` to an out-of-tree directory so that
/// running the fuzzers never modifies the source tree.
fn corpus(target: &str) -> PathBuf {
    let base = std::env::var_os("FUZZ_CORPUS_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("openpgp/fuzz/corpus"));
    base.join(target)
}

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static SEED_FILES: AtomicUsize = AtomicUsize::new(0);
static SEED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Per-file detail is printed only when FUZZ_VERBOSITY is a positive integer;
/// otherwise the generator prints just the one-line summary from main().
fn verbose() -> bool {
    std::env::var("FUZZ_VERBOSITY").ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map_or(false, |n| n > 0)
}

fn write_seed(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join(name), bytes)?;
    SEED_FILES.fetch_add(1, Ordering::Relaxed);
    SEED_BYTES.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    if verbose() {
        eprintln!("  {:>7}  {}/{}", bytes.len(), dir.display(), name);
    }
    Ok(())
}

/// An inline-signed message: one-pass-sig + literal + signature.
fn sign_inline(tsk: &openpgp::Cert) -> Result<Vec<u8>> {
    let kp = tsk
        .keys().unencrypted_secret().with_policy(P, None)
        .supported().alive().revoked(false).for_signing()
        .next().ok_or_else(|| anyhow::anyhow!("no signing-capable key"))?
        .key().clone().into_keypair()?;

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let signer = Signer::new(message, kp)?.build()?;
    let mut lw = LiteralWriter::new(signer).build()?;
    lw.write_all(MESSAGE)?;
    lw.finalize()?;
    Ok(sink)
}

/// A cleartext-signed message (Cleartext Signature Framework).
///
/// The output begins with `-----BEGIN PGP SIGNED MESSAGE-----`, which the
/// `csf_verify_from_bytes` target requires before it will exercise the input.
fn sign_cleartext(tsk: &openpgp::Cert) -> Result<Vec<u8>> {
    let kp = tsk
        .keys().unencrypted_secret().with_policy(P, None)
        .supported().alive().revoked(false).for_signing()
        .next().ok_or_else(|| anyhow::anyhow!("no signing-capable key"))?
        .key().clone().into_keypair()?;

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let mut signer = Signer::new(message, kp)?.cleartext().build()?;
    signer.write_all(MESSAGE)?;
    signer.finalize()?;
    Ok(sink)
}

/// A message encrypted to `cert`'s transport-encryption subkey.
fn encrypt(cert: &openpgp::Cert) -> Result<Vec<u8>> {
    let recipients = cert
        .keys().with_policy(P, None)
        .supported().alive().revoked(false).for_transport_encryption();

    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let message = Encryptor::for_recipients(message, recipients).build()?;
    let mut lw = LiteralWriter::new(message).build()?;
    lw.write_all(MESSAGE)?;
    lw.finalize()?;
    Ok(sink)
}

/// A bare literal-data message.
fn literal() -> Result<Vec<u8>> {
    let mut sink = Vec::new();
    let message = Message::new(&mut sink);
    let mut lw = LiteralWriter::new(message).build()?;
    lw.write_all(MESSAGE)?;
    lw.finalize()?;
    Ok(sink)
}

fn main() -> Result<()> {
    if ! Path::new("openpgp").exists() {
        return Err(anyhow::anyhow!(
            "Run from the root of the sequoia repository"));
    }

    // A general-purpose cert with signing + encryption subkeys and secret key
    // material, used to produce every message-shaped seed.
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("Fuzz Seed <fuzz@example.org>")
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .generate()?;

    // A second cert so we can build a multi-cert keyring seed.
    let (cert2, _revocation) = CertBuilder::new()
        .add_userid("Fuzz Seed Two <fuzz2@example.org>")
        .generate()?;

    // --- Reusable serialized blobs ---------------------------------------

    let mut cert_public = Vec::new();
    cert.serialize(&mut cert_public)?;               // binary, public parts

    let mut cert_secret = Vec::new();
    cert.as_tsk().serialize(&mut cert_secret)?;      // binary, with secrets

    let mut cert_armored = Vec::new();
    cert.armored().serialize(&mut cert_armored)?;    // ASCII-armored, public

    let mut keyring = Vec::new();                    // binary keyring: two certs
    cert.serialize(&mut keyring)?;
    cert2.serialize(&mut keyring)?;

    let literal = literal()?;
    let signed = sign_inline(&cert)?;
    let cleartext = sign_cleartext(&cert)?;
    let encrypted = encrypt(&cert)?;

    // --- Distribute seeds to each target's corpus ------------------------

    if verbose() { eprintln!("cert seeds:"); }
    write_seed(&corpus("cert_from_bytes"), "cert-public.pgp", &cert_public)?;
    write_seed(&corpus("cert_from_bytes"), "cert-secret.tsk", &cert_secret)?;
    write_seed(&corpus("cert_from_bytes"), "cert-armored.asc", &cert_armored)?;

    write_seed(&corpus("rawcert_from_bytes"), "cert-public.pgp", &cert_public)?;
    write_seed(&corpus("rawcert_from_bytes"), "keyring.pgp", &keyring)?;

    write_seed(&corpus("cert_parser_from_bytes"), "cert-armored.asc", &cert_armored)?;
    write_seed(&corpus("cert_parser_from_bytes"), "cert-public.pgp", &cert_public)?;
    write_seed(&corpus("cert_parser_from_bytes"), "keyring.pgp", &keyring)?;

    write_seed(&corpus("cert_parser_binary_from_bytes"), "cert-public.pgp", &cert_public)?;
    write_seed(&corpus("cert_parser_binary_from_bytes"), "keyring.pgp", &keyring)?;

    // Key packets: primary and any subkeys, in both public and secret-bearing
    // form.  `.key()` is public-typed, so `parts_into_secret()` is what pulls in
    // the secret MPIs / S2K structure that make the secret packets worth
    // fuzzing; we emit those only when the secret is actually present.
    if verbose() { eprintln!("key-packet seeds:"); }
    let kp_dir = corpus("key_packet_from_bytes");

    let primary = cert.primary_key().key().clone();
    let mut primary_public = Vec::new();
    Packet::from(primary.clone()).serialize(&mut primary_public)?;
    write_seed(&kp_dir, "primary-public-key.packet", &primary_public)?;
    if let Ok(secret) = primary.clone().parts_into_secret() {
        let mut buf = Vec::new();
        Packet::from(secret).serialize(&mut buf)?;
        write_seed(&kp_dir, "primary-secret-key.packet", &buf)?;
    }

    for (idx, ka) in cert.keys().subkeys().enumerate() {
        let key = ka.key().clone();
        let mut public = Vec::new();
        Packet::from(key.clone()).serialize(&mut public)?;
        write_seed(&kp_dir, &format!("subkey-{idx:02}-public.packet"), &public)?;
        if let Ok(secret) = key.clone().parts_into_secret() {
            let mut buf = Vec::new();
            Packet::from(secret).serialize(&mut buf)?;
            write_seed(&kp_dir, &format!("subkey-{idx:02}-secret.packet"), &buf)?;
        }
    }

    // Message-shaped seeds.
    if verbose() { eprintln!("message seeds:"); }
    write_seed(&corpus("message_from_bytes"), "literal.pgp", &literal)?;
    write_seed(&corpus("message_from_bytes"), "signed-inline.pgp", &signed)?;
    write_seed(&corpus("message_from_bytes"), "encrypted.pgp", &encrypted)?;

    write_seed(&corpus("packet_pile_from_bytes"), "cert-secret.tsk", &cert_secret)?;
    write_seed(&corpus("packet_pile_from_bytes"), "signed-inline.pgp", &signed)?;
    write_seed(&corpus("packet_pile_from_bytes"), "encrypted.pgp", &encrypted)?;

    write_seed(&corpus("inline_verify_from_bytes"), "signed-inline.pgp", &signed)?;
    write_seed(&corpus("csf_verify_from_bytes"), "signed-cleartext.asc", &cleartext)?;
    write_seed(&corpus("decrypt_from_bytes"), "encrypted.pgp", &encrypted)?;

    eprintln!(
        "generate_key_seeds: wrote {} seed files ({} bytes)",
        SEED_FILES.load(Ordering::Relaxed),
        SEED_BYTES.load(Ordering::Relaxed),
    );
    Ok(())
}
