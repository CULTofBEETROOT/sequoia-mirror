#![no_main]

use libfuzzer_sys::{Corpus, fuzz_target};

use sequoia_ipc as ipc;
use ipc::keybox;

fuzz_target!(|data: &[u8]| -> Corpus {
    match keybox::Keybox::from_bytes(data) {
        Ok(keybox) => {
            // iterate over content
            let mut parse_ok = true;
            let mut record_counter = 0;

            for record in keybox {
                record_counter += 1;

                // Break the loop to avoid getting caught in circular structures.
                // We only assume that two successive records do not start at
                // the same byte, so that N bytes can only contain N records.
                // The parser should detect circular (or non progressing)
                // structures and abort with an error.
                if record_counter > data.len() {
                    panic!("too many records {} in data of size {}", record_counter, data.len());
                }

                match record {
                    Ok(r) => {
                        // A trivial check of the content.
                        if r.version() != 1 {
                            parse_ok = false;
                        }
                    },
                    Err(e) => {
                        if ! matches!(e.downcast_ref(), Some(keybox::Error::LargeRecord(_))) {
                            parse_ok = false;
                            break;
                        }
                    },
                }
            }
            if parse_ok {
                Corpus::Keep
            } else {
                Corpus::Reject
            }
        },
        Err(_) => Corpus::Reject,
    }
});
