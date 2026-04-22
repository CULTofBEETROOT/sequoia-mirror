//! Generates structured seed corpora for OpenPGP fuzz targets.
//!
//! This example is a developer utility for creating small, valid, semantically
//! interesting seed inputs for `cargo fuzz`.  It currently writes:
//!
//! - certificate inputs for `fuzz/corpus/cert_from_bytes/`
//! - key-packet inputs for `fuzz/corpus/key_packet_from_bytes/`
//!
//! Run this from the repository root with:
//!
//! `cargo run -p sequoia-openpgp --example generate_key_seeds`
//!
//! Use this when adding a new fuzz target, refreshing a seed corpus, or
//! regenerating corpus files after changing how the inputs are constructed.
//!
//! The generated corpora are intentionally small and structured: they are meant
//! to help fuzz targets start from valid OpenPGP objects and then mutate from
//! there.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use sequoia_openpgp as openpgp;

use openpgp::cert::CertBuilder;
use openpgp::packet::Packet;
use openpgp::serialize::Serialize;

fn write_seed(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join(name), bytes)?;
    Ok(())
}

fn main() -> Result<()> {
    if ! fs::exists("openpgp").expect("checking existence of openpgp directory") {
        return Err(anyhow::anyhow!(
            "Run from the root of the sequoia-openpgp repository"));
    }

    let cert_out = PathBuf::from("openpgp/fuzz/corpus/cert_from_bytes");
    let key_packet_out = PathBuf::from("openpgp/fuzz/corpus/key_packet_from_bytes");

    let (cert, _revocation) = CertBuilder::new().generate()?;

    // Whole cert, for cert-oriented fuzz targets.
    let mut cert_bytes = Vec::new();
    cert.serialize(&mut cert_bytes)?;
    write_seed(&cert_out, "cert-secret.pgp", &cert_bytes)?;

    // Primary key as a secret-bearing packet.
    let primary = cert.primary_key().key().clone();

    let mut primary_secret = Vec::new();
    Packet::from(primary.clone()).serialize(&mut primary_secret)?;
    write_seed(
        &key_packet_out,
        "primary-secret-key.packet",
        &primary_secret,
    )?;

    // The same primary key serialized as public.
    let primary_public = primary.parts_as_public();
    let mut primary_public_bytes = Vec::new();
    Packet::from(primary_public.clone()).serialize(&mut primary_public_bytes)?;
    write_seed(
        &key_packet_out,
        "primary-public-key.packet",
        &primary_public_bytes,
    )?;

    // Optional: include subkeys too, if present.
    for (idx, ka) in cert.keys().subkeys().enumerate() {
        let key = ka.key().clone();

        let mut secret = Vec::new();
        Packet::from(key.clone()).serialize(&mut secret)?;
        write_seed(
            &key_packet_out,
            &format!("subkey-{idx:02}-secret.packet"),
            &secret,
        )?;

        let public = key.parts_as_public();
        let mut public_bytes = Vec::new();
        Packet::from(public.clone()).serialize(&mut public_bytes)?;
        write_seed(
            &key_packet_out,
            &format!("subkey-{idx:02}-public.packet"),
            &public_bytes,
        )?;
    }

    eprintln!("Wrote cert seeds to {}", cert_out.display());
    eprintln!("Wrote key-packet seeds to {}", key_packet_out.display());
    Ok(())
}
