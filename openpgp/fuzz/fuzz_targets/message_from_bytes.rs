//! Fuzz `Message::from_bytes` using arbitrary message-shaped input.
//!
//! The corpus should focus on OpenPGP messages rather than standalone
//! certs: literal data, compressed data, signed messages,
//! partial-body messages, encrypted messages, and password-encrypted
//! messages.

#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::Corpus;

use sequoia_openpgp as openpgp;
use openpgp::Message;
use openpgp::parse::Parse;

fuzz_target!(|data: &[u8]| -> Corpus {
    let _ = Message::from_bytes(data);
    Corpus::Keep
});
