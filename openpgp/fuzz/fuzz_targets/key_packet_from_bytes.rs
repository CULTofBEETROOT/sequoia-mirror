//! Fuzzes `Packet::from_bytes` using packet-level inputs, with an emphasis on
//! key packets.
//!
//! The corresponding seed corpus lives under:
//!
//! `fuzz/corpus/key_packet_from_bytes/`
//!
//! Run from `openpgp/` using:
//!
//! ```bash
//! cargo fuzz run key_packet_from_bytes fuzz/corpus/key_packet_from_bytes
//! ```
//!
//! This target is intentionally narrow: it starts by exercising packet parsing
//! on arbitrary bytes, seeded with valid key-packet encodings.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sequoia_openpgp as openpgp;
use openpgp::packet::Packet;
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = Packet::from_bytes(data) {
        match packet {
            Packet::PublicKey(_)
            | Packet::SecretKey(_)
            | Packet::PublicSubkey(_)
            | Packet::SecretSubkey(_) => {
                if let Ok(buf) = packet.to_vec() {
                    let _ = Packet::from_bytes(&buf);
                }
            }
            _ => {}
        }
    }
});
