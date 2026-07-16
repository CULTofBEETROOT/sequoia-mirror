#!/bin/sh
# openpgp's seed hook.  This is NOT a generic script: it is the openpgp crate's
# implementation of a per-crate convention.  The repo-level ./fuzz-all.sh runner
# looks for <crate>/fuzz/generate-seeds.sh before a replay and runs it if
# present, so every crate that fuzzes keeps its own copy under its own fuzz/
# directory (ipc would add ipc/fuzz/generate-seeds.sh, and so on).  The filename
# is shared by convention; the OpenPGP-specific steps below are not.
#
# Populates the structured seed corpora under openpgp/fuzz/corpus/.  Run from the
# repository root (./fuzz-all.sh does this for you):
#   openpgp/fuzz/generate-seeds.sh
set -eu

# Fresh, self-consistent OpenPGP objects (certs, key packets, signed/encrypted
# messages) generated from a throwaway key.
cargo run -p sequoia-openpgp --example generate_key_seeds

# Real-world fixtures copied from openpgp/tests/data, for the parser/message
# targets.  Complements the generated seeds above.
bash openpgp/fuzz/scripts/populate-parser-corpora.sh
