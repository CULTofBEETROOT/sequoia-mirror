//! Exercise `RawCertParser` and `CertParser` on binary packet input.
//!
//! `RawCertParser` only handles binary OpenPGP data.
//! `CertParser::from_bytes` may auto-detect ASCII armor, so this
//! target builds a `PacketParser` with dearmoring disabled and then
//! constructs a `CertParser` from that.  This keeps both parser paths
//! focused on binary input.
//!
//! This target is non-asserting: it is intended to exercise both
//! parser stacks and detect panics or sanitizer findings.  Agreement
//! checks should be added separately if they can compare parser
//! outcomes precisely.

#![no_main]

use libfuzzer_sys::Corpus;
use libfuzzer_sys::fuzz_target;

use sequoia_openpgp as openpgp;
use openpgp::cert::CertParser;
use openpgp::cert::raw::RawCertParser;
use openpgp::parse::Dearmor;
use openpgp::parse::PacketParserBuilder;
use openpgp::parse::Parse;

fuzz_target!(|data: &[u8]| -> Corpus {
    if let Ok(parser) = RawCertParser::from_bytes(data) {
        for item in parser {
            let _ = item;
        }
    }

    if let Ok(builder) = PacketParserBuilder::from_bytes(data) {
        if let Ok(pp) = builder
            .dearmor(Dearmor::Disabled)
            .build()
        {
            let parser = CertParser::from(pp);
            for item in parser {
                let _ = item;
            }
        }
    }

    Corpus::Keep
});
