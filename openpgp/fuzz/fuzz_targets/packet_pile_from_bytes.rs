//! Fuzz `PacketPile::from_bytes` using arbitrary packet data.
//!
//! This target exercises low-level OpenPGP packet framing, nesting,
//! partial body handling, and malformed packet recovery. It's
//! intentionally simple and does not require semantic validity.
//!
//! The seed corpus should include a mix of public/secret certs,
//! literal messages, compressed messages, signed messages, encrypted
//! messages, partial-body messages, and malformed signature fixtures.

#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::Corpus;

use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;
use openpgp::PacketPile;

fuzz_target!(|data: &[u8]| -> Corpus {
    let _ = PacketPile::from_bytes(data);
    Corpus::Keep
});
