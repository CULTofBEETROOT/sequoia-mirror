//! Fuzz target for `RawCertParser`.
//!
//! ## Purpose
//!
//! This target exercises the low-level raw certificate parser using arbitrary
//! byte input. It focuses on robustness properties rather than semantic
//! correctness:
//!
//! - The parser must not panic.
//! - Malformed input should result in `Err` values, not crashes.
//!
//! ## Why this target exists
//!
//! A previous bug allowed `RawCertParser` to panic on malformed input due to an
//! internal assumption:
//!
//!     expect("just read it")
//!
//! This assumption was violated when the parser's internal accounting diverged
//! from the underlying reader, leading to an `UnexpectedEof` panic.
//!
//! This fuzz target ensures that:
//!
//! > If `RawCertParser::from_bytes(input)` succeeds, fully iterating the parser
//! > must not panic, regardless of input validity.
//!
//! ## Strategy
//!
//! - Feed arbitrary input to `RawCertParser::from_bytes`.
//! - If initialization succeeds, fully iterate the parser.
//! - Ignore all results (both `Ok` and `Err` are acceptable outcomes).
//!
//! This ensures we exercise:
//!
//! - iterator state transitions
//! - error propagation paths
//! - EOF and truncation handling
//! - internal length/accounting consistency
//!
//! ## Corpus
//!
//! The corpus includes:
//!
//! - valid OpenPGP certificates (for structure-aware mutation)
//! - a minimized regression input triggering the historical EOF panic
//! - these guide libFuzzer toward realistic inputs.
//!
//! ## Notes
//!
//! This target intentionally avoids artificial mutation strategies (e.g.
//! truncation bias). Instead, the patterns are encoded in the corpus so that
//! libFuzzer can evolve them.

#![no_main]

use sequoia_openpgp as openpgp;
use openpgp::cert::raw::RawCertParser;
use openpgp::parse::Parse;

use libfuzzer_sys::{fuzz_target, Corpus};

fuzz_target!(|data: &[u8]| -> Corpus {
    if let Ok(parser) = RawCertParser::from_bytes(data) {
        for item in parser {
            let _ = item;
        }
    }

    Corpus::Keep
});
