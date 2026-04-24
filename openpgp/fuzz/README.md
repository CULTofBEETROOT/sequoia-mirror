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

Run fuzz targets from the `openpgp/` directory (not from `openpgp/fuzz/`).

Examples:

```bash
cargo fuzz run cert_from_bytes fuzz/corpus/cert_from_bytes
cargo fuzz run key_packet_from_bytes fuzz/corpus/key_packet_from_bytes
```

To limit execution time during local experimentation, pass libFuzzer options
after `--`:

```bash
cargo fuzz run key_packet_from_bytes fuzz/corpus/key_packet_from_bytes -- -max_total_time=30
```

(`-max_total_time` specifies time to run in seconds before giving up.)

## Seed corpora

Structured seed corpora can be generated or refreshed using:

```bash
cargo run -p sequoia-openpgp --example generate_key_seeds
```

This currently creates:

```
fuzz/corpus/cert_from_bytes/
fuzz/corpus/key_packet_from_bytes/
```

The generated inputs are valid OpenPGP objects (certificates and key packets).
They provide useful starting points for fuzzing so that mutations explore
meaningful parser and serialization paths.

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
