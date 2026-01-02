These are test vectors from draft-ietf-openpgp-nist-bp-comp-03.

Run

SEQ_DEBUG_PQC=1 cargo test -p sequoia-openpgp --locked --no-default-features --features crypto-openssl --test pqc-nist-bp-ietf -- --nocapture

