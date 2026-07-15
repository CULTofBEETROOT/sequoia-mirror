#!/bin/sh
# Seed hook for the openpgp fuzz targets, invoked by fuzz-all.sh in replay mode.
# Regenerates the structured seed corpora under openpgp/fuzz/corpus/.
#
# Run from the repository root (fuzz-all.sh does this for you):
#   openpgp/fuzz/generate-seeds.sh
set -eu

# Fresh, self-consistent OpenPGP objects (certs, key packets, signed/encrypted
# messages) generated from a throwaway key.
cargo run -p sequoia-openpgp --example generate_key_seeds

# Real-world fixtures copied from openpgp/tests/data, for the parser/message
# targets.  Complements the generated seeds above.
bash openpgp/fuzz/scripts/populate-parser-corpora.sh
