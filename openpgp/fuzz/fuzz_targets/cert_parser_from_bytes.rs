//! Fuzz the high-level `CertParser::from_bytes` entry point.
//!
//! Unlike binary-only parser targets, this exercises `CertParser`'s
//! default input handling, including ASCII armor detection and binary
//! input handling.  The target fully iterates the parser so
//! multi-cert/keyring-shaped inputs, iterator state, and EOF paths
//! are exercised.

#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::Corpus;

use sequoia_openpgp as openpgp;
use openpgp::cert::CertParser;
use openpgp::parse::Parse;

fuzz_target!(|data: &[u8]| -> Corpus {
    if let Ok(parser) = CertParser::from_bytes(data) {
        for item in parser {
            let _ = item;
        }
    }

    Corpus::Keep
});
