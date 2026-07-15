# Fuzzing `sequoia-openpgp`

This directory contains `cargo-fuzz` targets for `sequoia-openpgp`.

The targets are intentionally small and focused. Each target expects inputs
appropriate to its corresponding corpus directory, and corpus directories
should contain homogeneous inputs for the target they serve.

## Prerequisites

Install `cargo-fuzz` if needed:

```bash
cargo install cargo-fuzz
```

## Running fuzz targets

Run fuzz targets from the `openpgp/` directory (not from
`openpgp/fuzz/`). Note: you need to run these with the nightly
option. On macOS with homebrew installed, you may need to set the path
prefix as follows:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

By default, `cargo-fuzz` uses `fuzz/corpus/<target-name>` as the corpus
directory for a target.  Additional corpus directories can be supplied after
the target name when needed.

Examples that reply on this default include:

```bash
cargo fuzz run cert_from_bytes
cargo fuzz run key_packet_from_bytes
```

Optionally the corpus directory can be specified, here is an example
with two corpus folders.

```bash
cargo fuzz run key_packet_from_bytes \
  fuzz/corpus/key_packet_from_bytes \
  fuzz/corpus/cert_from_bytes \
  -- -max_total_time=30
```

To limit execution time during local experimentation, pass libFuzzer options
after `--`:

```bash
cargo fuzz run key_packet_from_bytes -- -max_total_time=30
```

(`-max_total_time` specifies time to run in seconds before giving up.)

## Running all targets (regression + smoke)

`fuzz-all.sh` runs every target across every crate that has a `fuzz/` project
(it auto-discovers them, so `ipc` and others are picked up automatically).  It
has two modes, selected with `FUZZ_MODE`:

```bash
# Deterministic regression replay: (re)generate seeds, then run each corpus
# file once (-runs=0).  Fast; a crash here is a reintroduced bug.
FUZZ_MODE=replay openpgp/fuzz/fuzz-all.sh

# Short mutation run (nondeterministic; may find new crashes).
FUZZ_MODE=timed FUZZ_TIME_PER_TARGET=30 openpgp/fuzz/fuzz-all.sh
```

Useful knobs: `CARGO_BUILD_JOBS` (peak-RAM lever for the AddressSanitizer
(ASan) build — cargo-fuzz instruments targets with ASan by default, which makes
compilation memory-hungry),
`FUZZ_RSS_LIMIT_MB`, and `FUZZ_SKIP="target_a target_b"` to exclude a target
with a known-open bug from a gating run.  These modes back the `fuzz-replay`
and `fuzz-timed` CI jobs.

## Seed corpora

Rather than committing large binary corpora, we commit the seed *generators* and
(re)produce seeds on demand — locally or in CI before a replay run.  The seed
hook `openpgp/fuzz/generate-seeds.sh` (run automatically by `fuzz-all.sh` in
replay mode) populates every target's corpus from two complementary sources:

```bash
# 1. Fresh, self-consistent objects (certs, key packets, signed/encrypted/
#    cleartext messages) built from a throwaway key, covering all targets:
cargo run -p sequoia-openpgp --example generate_key_seeds

# 2. Real-world fixtures copied from openpgp/tests/data:
bash openpgp/fuzz/scripts/populate-parser-corpora.sh
```

Both are safe to run repeatedly.  The generated inputs are valid OpenPGP objects
that give fuzz targets meaningful starting points to mutate from.

What to commit to git: the generators above, plus any minimized **regression
reproducers** for real fixed bugs (these can't be regenerated).  Do not commit
bulk accumulated corpora.

## Adding new fuzz targets

When adding a new fuzz target:

- Keep the target narrowly focused.
- Create or update a matching corpus directory under `fuzz/corpus/`.
- Prefer structured seed inputs over large random corpora.
- Ensure the target runs from `openpgp/` using `cargo fuzz run`.

Notes:

- Corpus directories should match the expectations of the `fuzz` target.
- Keep seed corpora small and meaningful.
- Fuzz targets are intended to exercise parsing and related logic
  without panicking on arbitrary inputs.
